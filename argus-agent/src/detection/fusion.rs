//! Confidence-weighted fusion of capability samples into a health-score
//! contribution.
//!
//! Today this is intentionally conservative: it computes an additive
//! contribution to the raw score that **never reduces** the rule-derived
//! verdict. As more capabilities come online with real backends (eBPF
//! retransmits, ECN/CNP rates, completion-latency histograms) the fusion
//! layer is expected to take over from the severity-floor approach used
//! today and become the authoritative scorer.
//!
//! Math sketch (current implementation):
//!   - Each capability has a *weight* in `[0.0, 1.0]` (see `cap_weight`).
//!   - For every sample, we compute `sample.value_normalized * weight *
//!     sample.effective_weight()` and sum.
//!   - The total is squashed via `tanh(x / 2.0) * 0.5` so it is bounded
//!     in `[0, 0.5]` and non-linear: small contributions barely move
//!     the score, large ones approach but never reach 0.5.
//!
//! The 0.5 cap is intentional: the rule layer can still drive the score
//! all the way to `critical_enter` (0.55 by default) on its own, so the
//! capability contribution alone is never enough to push state into
//! Critical without rule corroboration.

use argus_common::{Capability, Sample};

/// Per-capability weight in the fusion sum. Higher = the capability has
/// more influence on the raw score.
fn cap_weight(cap: Capability) -> f64 {
    match cap {
        Capability::LinkErrors => 1.0,
        Capability::RetransmitSignal => 0.8,
        Capability::CompletionLatency => 0.6,
        Capability::PfcPause => 0.5,
        Capability::EcnMarks => 0.4,
        Capability::CnpRate => 0.4,
        Capability::CreditStall => 0.5,
        Capability::NakRate => 0.7,
        Capability::OutOfOrder => 0.4,
        Capability::Throughput => 0.0,
        Capability::QpAttribution => 0.0,
        Capability::ProcessAttribution => 0.0,
        Capability::PeerLiveness => 0.6,
    }
}

/// Normalize a sample value to roughly `[0, 1]` for fusion purposes.
/// Different capabilities have wildly different units; this keeps each
/// signal comparable.
fn normalize(sample: &Sample) -> f64 {
    let v = sample.value;
    if v <= 0.0 || !v.is_finite() {
        return 0.0;
    }
    match sample.capability {
        // LinkErrors: weighted error count, roughly 0..50 in healthy windows;
        // squash via /50.
        Capability::LinkErrors => (v / 50.0).clamp(0.0, 1.0),
        // RetransmitSignal: ratio-style 0..1 already (inferred), or absolute
        // count for sysfs path; squash via /100.
        Capability::RetransmitSignal => {
            if v <= 1.0 {
                v
            } else {
                (v / 100.0).clamp(0.0, 1.0)
            }
        }
        // CompletionLatency: ns; >100us is concerning, >1ms is critical.
        Capability::CompletionLatency => ((v - 100_000.0) / 900_000.0).clamp(0.0, 1.0),
        // PFC pause / NAK / CNP: rate-style; >10/s is concerning.
        Capability::PfcPause | Capability::NakRate | Capability::CnpRate => {
            (v / 100.0).clamp(0.0, 1.0)
        }
        Capability::EcnMarks => (v / 1000.0).clamp(0.0, 1.0),
        Capability::CreditStall => (v / 100.0).clamp(0.0, 1.0),
        Capability::OutOfOrder => (v / 50.0).clamp(0.0, 1.0),
        // PeerLiveness: typical RTT in us; 1ms+ is concerning.
        Capability::PeerLiveness => ((v - 100.0) / 1000.0).clamp(0.0, 1.0),
        // Pure metadata caps don't contribute.
        Capability::Throughput
        | Capability::QpAttribution
        | Capability::ProcessAttribution => 0.0,
    }
}

/// Compute the fusion contribution for a window. Bounded in `[0, 0.5]`.
#[must_use]
pub fn sample_score_contribution(samples: &[Sample]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut sum = 0.0;
    for s in samples {
        if !s.is_actionable() {
            continue;
        }
        let w = cap_weight(s.capability);
        if w <= 0.0 {
            continue;
        }
        sum += normalize(s) * w * s.effective_weight();
    }
    // Bound + non-linear squash. tanh(0)=0, tanh(2)≈0.96, tanh(∞)=1.
    let squashed = (sum / 2.0).tanh();
    (squashed * 0.5).clamp(0.0, 0.5)
}

/// Per-rule audit trail: which capabilities the rule consulted and their
/// observed quality. Surfaced via the alert struct (future) and the
/// `/coverage` endpoint.
#[derive(Clone, Debug, Default)]
pub struct RuleEvidence {
    pub consulted: Vec<Capability>,
    pub min_quality_weight: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::{BackendId, Quality};

    fn s(cap: Capability, value: f64, q: Quality) -> Sample {
        Sample {
            capability: cap,
            value,
            confidence: 1.0,
            quality: q,
            origin: BackendId::Synthetic,
            timestamp_ns: 0,
            qp_num: None,
            port: None,
            priority: None,
            device: None,
        }
    }

    #[test]
    fn empty_samples_zero_contribution() {
        assert_eq!(sample_score_contribution(&[]), 0.0);
    }

    #[test]
    fn absent_quality_ignored() {
        let samples = vec![s(Capability::LinkErrors, 100.0, Quality::Absent)];
        assert_eq!(sample_score_contribution(&samples), 0.0);
    }

    #[test]
    fn high_link_errors_contribute() {
        let samples = vec![s(Capability::LinkErrors, 50.0, Quality::High)];
        let c = sample_score_contribution(&samples);
        assert!(c > 0.0 && c <= 0.5, "expected (0, 0.5], got {c}");
    }

    #[test]
    fn low_quality_contributes_less_than_high() {
        let high = vec![s(Capability::LinkErrors, 50.0, Quality::High)];
        let low = vec![s(Capability::LinkErrors, 50.0, Quality::Low)];
        assert!(sample_score_contribution(&high) > sample_score_contribution(&low));
    }

    #[test]
    fn metadata_caps_dont_contribute() {
        let samples = vec![s(Capability::Throughput, 10_000.0, Quality::High)];
        assert_eq!(sample_score_contribution(&samples), 0.0);
    }

    #[test]
    fn contribution_is_bounded() {
        // Many strong signals — should still be ≤ 0.5.
        let mut samples = Vec::new();
        for _ in 0..20 {
            samples.push(s(Capability::LinkErrors, 1000.0, Quality::High));
            samples.push(s(Capability::RetransmitSignal, 1000.0, Quality::High));
        }
        let c = sample_score_contribution(&samples);
        assert!(c <= 0.5 + 1e-9);
    }
}

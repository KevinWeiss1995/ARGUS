//! Capability-driven signal collection layer.
//!
//! See `argus_common::capability` for the public type vocabulary
//! (`Capability`, `Quality`, `Sample`, etc.). This module defines the
//! `CapabilityProvider` trait that each backend implements, plus the
//! `CapabilityRegistry` that owns provider selection at runtime.
//!
//! Architecture
//! ============
//!
//! At startup, every provider is asked `probe(&FabricEnv)` to declare
//! whether it can run on the current host. The registry picks, **per
//! capability**, the available provider with the highest declared quality.
//! Unselected providers are kept on a fallback chain for `/coverage`.
//!
//! Each window, the engine calls `collect(ctx)` on every active provider.
//! Samples are tagged with their `Capability`, `Quality`, and per-sample
//! `confidence`, and are routed into the detection layer's fusion pass.

#![allow(clippy::module_name_repetitions)]

pub mod fabric;
pub mod providers;
pub mod sketches;

pub use fabric::{FabricEnv, FabricKind, KallsymsCache};

use argus_common::{
    AggregatedMetrics, BackendId, BackendOutcome, BackendProbeResult, Capability,
    CapabilityCoverage, CoverageGrade, CoverageReport, Quality, Sample,
};
use std::collections::HashMap;

/// Runtime context passed to every provider on each `collect()` call.
///
/// Providers should treat this as read-only. The aggregator is included so
/// existing collectors (sysfs/ebpf-aggregator) can adapt their snapshots
/// into `Sample`s without holding their own state.
pub struct DetectionContext<'a> {
    pub metrics: &'a AggregatedMetrics,
    pub window_seq: u64,
    pub timestamp_ns: u64,
    pub fabric: &'a FabricEnv,
    /// Per-window CQ completion-latency sketch. May be empty when the
    /// pipeline isn't seeing CQ events (mock/replay without CQ traffic,
    /// live mode without ebpf cq probes).
    pub cq_latency_sketch: Option<&'a sketches::DdSketch>,
}

/// Result of probing a provider against the running host.
#[derive(Clone, Debug)]
pub enum ProbeOutcome {
    /// Provider can run; declared `Quality` reflects backend type.
    Available { quality: Quality },
    /// Provider cannot run on this host. `reason` is logged + surfaced via /coverage.
    Unavailable { reason: String },
}

/// Trait every signal backend implements.
///
/// Providers are stateless w.r.t. the `Capability` they serve — they own
/// their own internal state (eBPF maps, sysfs handles, baselines).
pub trait CapabilityProvider: Send + Sync {
    /// Stable identifier — appears in Prometheus labels and /coverage.
    fn id(&self) -> BackendId;

    /// Capability this provider serves.
    fn capability(&self) -> Capability;

    /// Maximum quality this backend can ever produce, used as the tie-break
    /// during selection. Actual sample quality may be lower if a counter
    /// is present but stale or zero.
    fn declared_quality(&self) -> Quality;

    /// Probe whether this provider can run. Called once at startup.
    /// Default implementation says yes at declared quality (good for tests).
    fn probe(&mut self, _env: &FabricEnv) -> ProbeOutcome {
        ProbeOutcome::Available {
            quality: self.declared_quality(),
        }
    }

    /// Per-window collection. Empty `Vec` is valid (no observations).
    fn collect(&mut self, ctx: &DetectionContext<'_>) -> Vec<Sample>;
}

/// Owns all providers; selects the best available per capability.
pub struct CapabilityRegistry {
    /// Active provider per capability — what the engine actually polls each window.
    active: HashMap<Capability, Box<dyn CapabilityProvider>>,
    /// All probe outcomes for /coverage reporting.
    probe_log: HashMap<Capability, Vec<BackendProbeResult>>,
    /// Cached coverage report, recomputed when `register_all()` finishes.
    coverage: CoverageReport,
}

impl CapabilityRegistry {
    /// Create a registry from a set of candidate providers.
    /// Probes all of them; selects the highest-quality available per capability.
    /// Unavailable ones are recorded for the coverage report.
    #[must_use]
    pub fn new(env: &FabricEnv, candidates: Vec<Box<dyn CapabilityProvider>>) -> Self {
        let mut active: HashMap<Capability, Box<dyn CapabilityProvider>> = HashMap::new();
        let mut probe_log: HashMap<Capability, Vec<BackendProbeResult>> = HashMap::new();

        // First pass: probe everything, collect outcomes.
        struct Probed {
            provider: Box<dyn CapabilityProvider>,
            outcome: ProbeOutcome,
        }
        let mut probed: Vec<Probed> = candidates
            .into_iter()
            .map(|mut p| {
                let outcome = p.probe(env);
                Probed {
                    provider: p,
                    outcome,
                }
            })
            .collect();

        // Build probe log entries first (clone outcomes, no provider movement yet).
        for p in &probed {
            let cap = p.provider.capability();
            let probe_result = BackendProbeResult {
                backend: p.provider.id(),
                declared_quality: p.provider.declared_quality(),
                outcome: match &p.outcome {
                    ProbeOutcome::Available { quality } => BackendOutcome::Available {
                        observed_quality: *quality,
                    },
                    ProbeOutcome::Unavailable { reason } => BackendOutcome::Unavailable {
                        reason: reason.clone(),
                    },
                },
            };
            probe_log.entry(cap).or_default().push(probe_result);
        }

        // Second pass: pick best available per capability.
        // We sort within each capability bucket by observed quality DESC,
        // then move only the winner into `active`.
        let mut by_cap: HashMap<Capability, Vec<Probed>> = HashMap::new();
        while let Some(p) = probed.pop() {
            by_cap.entry(p.provider.capability()).or_default().push(p);
        }
        for (cap, mut bucket) in by_cap {
            bucket.sort_by_key(|p| match &p.outcome {
                ProbeOutcome::Available { quality } => std::cmp::Reverse((*quality).as_i64()),
                ProbeOutcome::Unavailable { .. } => std::cmp::Reverse(-1),
            });
            if let Some(best) = bucket.into_iter().next() {
                if matches!(best.outcome, ProbeOutcome::Available { .. }) {
                    active.insert(cap, best.provider);
                }
            }
        }

        let coverage = build_coverage_report(env, &active, &probe_log);

        Self {
            active,
            probe_log,
            coverage,
        }
    }

    /// Empty registry, useful for tests and minimal configurations.
    #[must_use]
    pub fn empty(env: &FabricEnv) -> Self {
        Self::new(env, Vec::new())
    }

    /// Iterate active providers in capability order for deterministic output.
    #[must_use]
    pub fn active_providers(&self) -> Vec<(Capability, BackendId, Quality)> {
        let mut v: Vec<_> = self
            .active
            .iter()
            .map(|(cap, p)| (*cap, p.id(), p.declared_quality()))
            .collect();
        v.sort_by_key(|(cap, _, _)| cap.name());
        v
    }

    /// Snapshot the current coverage report.
    #[must_use]
    pub fn coverage(&self) -> &CoverageReport {
        &self.coverage
    }

    /// Run one collection pass across every active provider.
    /// Errors from individual providers are isolated: a panic-free provider
    /// that returns `vec![]` is normal, and a misbehaving provider should
    /// not bring down the agent. (We use `catch_unwind` only around the
    /// async boundary in the live agent; here we trust providers.)
    pub fn collect_all(&mut self, ctx: &DetectionContext<'_>) -> Vec<Sample> {
        let mut all = Vec::new();
        // Iterate in deterministic order so trace logs and proptests are stable.
        let mut caps: Vec<Capability> = self.active.keys().copied().collect();
        caps.sort_by_key(|c| c.name());
        for cap in caps {
            if let Some(provider) = self.active.get_mut(&cap) {
                let samples = provider.collect(ctx);
                all.extend(samples);
            }
        }
        all
    }

    /// Probe-time records — used by /coverage and Prometheus capability metric.
    #[must_use]
    pub fn probe_log(&self) -> &HashMap<Capability, Vec<BackendProbeResult>> {
        &self.probe_log
    }
}

fn build_coverage_report(
    env: &FabricEnv,
    active: &HashMap<Capability, Box<dyn CapabilityProvider>>,
    probe_log: &HashMap<Capability, Vec<BackendProbeResult>>,
) -> CoverageReport {
    let mut caps_out: Vec<CapabilityCoverage> = Capability::all()
        .iter()
        .map(|cap| {
            let active_provider = active.get(cap);
            let (active_backend, quality) = match active_provider {
                Some(p) => (Some(p.id()), p.declared_quality()),
                None => (None, Quality::Absent),
            };
            let chain = probe_log.get(cap).cloned().unwrap_or_default();
            CapabilityCoverage {
                capability: *cap,
                active_backend,
                quality,
                fallback_chain: chain,
            }
        })
        .collect();
    caps_out.sort_by_key(|c| c.capability.name());

    let critical_caps = [
        Capability::LinkErrors,
        Capability::Throughput,
        Capability::CompletionLatency,
        Capability::RetransmitSignal,
    ];
    let critical_qualities: Vec<Quality> = critical_caps
        .iter()
        .map(|c| {
            caps_out
                .iter()
                .find(|cc| cc.capability == *c)
                .map_or(Quality::Absent, |cc| cc.quality)
        })
        .collect();

    let grade = if critical_qualities.iter().all(|q| *q == Quality::High) {
        CoverageGrade::A
    } else if critical_qualities
        .iter()
        .all(|q| *q >= Quality::Medium)
    {
        CoverageGrade::B
    } else if critical_qualities.iter().any(|q| *q != Quality::Absent) {
        CoverageGrade::C
    } else {
        CoverageGrade::F
    };

    CoverageReport {
        grade,
        fabric: env.fabric.map(|f| f.name().to_string()),
        capabilities: caps_out,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::AggregatedMetrics;

    /// Fake provider: declares quality, optionally probes Available, emits one synthetic sample.
    struct FakeProvider {
        cap: Capability,
        id: BackendId,
        quality: Quality,
        available: bool,
    }

    impl CapabilityProvider for FakeProvider {
        fn id(&self) -> BackendId {
            self.id
        }
        fn capability(&self) -> Capability {
            self.cap
        }
        fn declared_quality(&self) -> Quality {
            self.quality
        }
        fn probe(&mut self, _env: &FabricEnv) -> ProbeOutcome {
            if self.available {
                ProbeOutcome::Available {
                    quality: self.quality,
                }
            } else {
                ProbeOutcome::Unavailable {
                    reason: "synthetic_unavailable".into(),
                }
            }
        }
        fn collect(&mut self, _ctx: &DetectionContext<'_>) -> Vec<Sample> {
            vec![Sample {
                capability: self.cap,
                value: 1.0,
                confidence: 1.0,
                quality: self.quality,
                origin: self.id,
                timestamp_ns: 0,
                qp_num: None,
                port: None,
                priority: None,
                device: None,
            }]
        }
    }

    #[test]
    fn registry_picks_highest_quality_available() {
        let env = FabricEnv::synthetic();
        let providers: Vec<Box<dyn CapabilityProvider>> = vec![
            Box::new(FakeProvider {
                cap: Capability::Throughput,
                id: BackendId::Synthetic,
                quality: Quality::Low,
                available: true,
            }),
            Box::new(FakeProvider {
                cap: Capability::Throughput,
                id: BackendId::SysfsPortCounters,
                quality: Quality::High,
                available: true,
            }),
            Box::new(FakeProvider {
                cap: Capability::Throughput,
                id: BackendId::EbpfRetx,
                quality: Quality::Medium,
                available: true,
            }),
        ];
        let registry = CapabilityRegistry::new(&env, providers);
        let active = registry.active_providers();
        let (_cap, id, q) = active.iter().find(|(c, _, _)| *c == Capability::Throughput).unwrap();
        assert_eq!(*q, Quality::High);
        assert_eq!(*id, BackendId::SysfsPortCounters);
    }

    #[test]
    fn registry_skips_unavailable() {
        let env = FabricEnv::synthetic();
        let providers: Vec<Box<dyn CapabilityProvider>> = vec![
            Box::new(FakeProvider {
                cap: Capability::PfcPause,
                id: BackendId::EthtoolPfc,
                quality: Quality::High,
                available: false,
            }),
            Box::new(FakeProvider {
                cap: Capability::PfcPause,
                id: BackendId::PfcInference,
                quality: Quality::Low,
                available: true,
            }),
        ];
        let registry = CapabilityRegistry::new(&env, providers);
        let active = registry.active_providers();
        let (_, id, q) = active
            .iter()
            .find(|(c, _, _)| *c == Capability::PfcPause)
            .expect("inferred PFC should still be active");
        assert_eq!(*id, BackendId::PfcInference);
        assert_eq!(*q, Quality::Low);
    }

    #[test]
    fn coverage_grade_drops_when_critical_absent() {
        let env = FabricEnv::synthetic();
        // Only LinkErrors at High; the other 3 critical caps are absent.
        let providers: Vec<Box<dyn CapabilityProvider>> = vec![Box::new(FakeProvider {
            cap: Capability::LinkErrors,
            id: BackendId::SysfsPortCounters,
            quality: Quality::High,
            available: true,
        })];
        let registry = CapabilityRegistry::new(&env, providers);
        let report = registry.coverage();
        assert_eq!(report.grade, CoverageGrade::C);
    }

    #[test]
    fn collect_all_runs_active_providers() {
        let env = FabricEnv::synthetic();
        let providers: Vec<Box<dyn CapabilityProvider>> = vec![Box::new(FakeProvider {
            cap: Capability::LinkErrors,
            id: BackendId::SysfsPortCounters,
            quality: Quality::High,
            available: true,
        })];
        let mut registry = CapabilityRegistry::new(&env, providers);
        let metrics = AggregatedMetrics::default();
        let ctx = DetectionContext {
            metrics: &metrics,
            window_seq: 1,
            timestamp_ns: 0,
            fabric: &env,
            cq_latency_sketch: None,
        };
        let samples = registry.collect_all(&ctx);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].capability, Capability::LinkErrors);
        assert_eq!(samples[0].quality, Quality::High);
    }

    #[test]
    fn probe_log_records_unavailable_backends() {
        let env = FabricEnv::synthetic();
        let providers: Vec<Box<dyn CapabilityProvider>> = vec![Box::new(FakeProvider {
            cap: Capability::EcnMarks,
            id: BackendId::EthtoolEcn,
            quality: Quality::High,
            available: false,
        })];
        let registry = CapabilityRegistry::new(&env, providers);
        let log = registry.probe_log().get(&Capability::EcnMarks).unwrap();
        assert_eq!(log.len(), 1);
        match &log[0].outcome {
            BackendOutcome::Unavailable { reason } => {
                assert!(reason.contains("synthetic"));
            }
            _ => panic!("expected Unavailable outcome"),
        }
    }
}

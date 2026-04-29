//! LinkErrors capability — universal: every fabric exposes some form of
//! port_rcv_errors / port_xmit_discards / link_downed via sysfs.
//!
//! Backends:
//!   - `SysfsLinkErrorsProvider`: high-quality, derived from current
//!     `IbCounterDeltas` already aggregated by the pipeline.
//!   - `InferredLinkErrorsProvider`: low-quality fallback, only ever
//!     emits a sample if the sysfs path didn't fire (kept Available so we
//!     have *something* even on weird hosts).

use crate::capabilities::{
    CapabilityProvider, DetectionContext, FabricEnv, ProbeOutcome,
};
use argus_common::{BackendId, Capability, Quality, Sample};

/// Reads `IbCounterDeltas` already aggregated from sysfs into a single
/// `LinkErrors` sample per window. Quality is `High` because we are reading
/// kernel counters directly.
pub struct SysfsLinkErrorsProvider;

impl SysfsLinkErrorsProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for SysfsLinkErrorsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for SysfsLinkErrorsProvider {
    fn id(&self) -> BackendId {
        BackendId::SysfsPortCounters
    }
    fn capability(&self) -> Capability {
        Capability::LinkErrors
    }
    fn declared_quality(&self) -> Quality {
        Quality::High
    }
    fn probe(&mut self, env: &FabricEnv) -> ProbeOutcome {
        // Available iff *any* discovered RDMA device or we're in synthetic mode.
        if env.synthetic || !env.devices.is_empty() {
            ProbeOutcome::Available {
                quality: Quality::High,
            }
        } else {
            ProbeOutcome::Unavailable {
                reason: "no RDMA devices found in /sys/class/infiniband".into(),
            }
        }
    }
    fn collect(&mut self, ctx: &DetectionContext<'_>) -> Vec<Sample> {
        let d = &ctx.metrics.ib_counter_deltas;
        // Confidence ramps with traffic — zero traffic means we can't really
        // distinguish "perfect run" from "link down with no flow". Hold low
        // confidence on quiet windows so fusion doesn't lock in a spurious 0.
        let traffic = d.has_traffic();
        let confidence = if traffic { 1.0 } else { 0.2 };

        // Aggregate hard error deltas into a single rate-style value.
        let hard = d.total_hard_error_delta() as f64;
        let recovery = d.link_error_recovery_delta as f64;
        let downed = d.link_downed_delta as f64;
        let value = hard + 5.0 * recovery + 50.0 * downed;

        vec![Sample {
            capability: Capability::LinkErrors,
            value,
            confidence,
            quality: Quality::High,
            origin: BackendId::SysfsPortCounters,
            timestamp_ns: ctx.timestamp_ns,
            qp_num: None,
            port: None,
            priority: None,
            device: None,
        }]
    }
}

/// Always-on fallback. Emits zero, low-quality samples — its purpose is
/// to keep the LinkErrors capability *registered* even on hosts where the
/// sysfs provider can't probe (e.g., unit tests, unusual mountpoints).
pub struct InferredLinkErrorsProvider;

impl InferredLinkErrorsProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for InferredLinkErrorsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for InferredLinkErrorsProvider {
    fn id(&self) -> BackendId {
        BackendId::CqErrorInference
    }
    fn capability(&self) -> Capability {
        Capability::LinkErrors
    }
    fn declared_quality(&self) -> Quality {
        Quality::Low
    }
    fn probe(&mut self, _env: &FabricEnv) -> ProbeOutcome {
        ProbeOutcome::Available {
            quality: Quality::Low,
        }
    }
    fn collect(&mut self, ctx: &DetectionContext<'_>) -> Vec<Sample> {
        // Inference: completion-queue stalls hint at link issues even when
        // counters are unavailable.
        let stalls = ctx.metrics.cq_jitter.stall_count as f64;
        vec![Sample {
            capability: Capability::LinkErrors,
            value: stalls,
            confidence: if stalls > 0.0 { 0.3 } else { 0.05 },
            quality: Quality::Low,
            origin: BackendId::CqErrorInference,
            timestamp_ns: ctx.timestamp_ns,
            qp_num: None,
            port: None,
            priority: None,
            device: None,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::{AggregatedMetrics, IbCounterDeltas};

    #[test]
    fn sysfs_link_errors_high_quality() {
        let env = FabricEnv::synthetic();
        let mut p = SysfsLinkErrorsProvider::new();
        match p.probe(&env) {
            ProbeOutcome::Available { quality } => assert_eq!(quality, Quality::High),
            _ => panic!("synthetic env should make sysfs LinkErrors available"),
        }

        let metrics = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                link_error_recovery_delta: 1,
                hw_rcv_pkts_delta: 100,
                hw_xmit_pkts_delta: 100,
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx = DetectionContext {
            metrics: &metrics,
            window_seq: 1,
            timestamp_ns: 0,
            fabric: &env,
            cq_latency_sketch: None,
        };
        let samples = p.collect(&ctx);
        assert_eq!(samples.len(), 1);
        assert!(samples[0].value > 0.0);
        assert_eq!(samples[0].confidence, 1.0);
    }

    #[test]
    fn sysfs_link_errors_low_confidence_when_quiet() {
        let env = FabricEnv::synthetic();
        let mut p = SysfsLinkErrorsProvider::new();
        let metrics = AggregatedMetrics::default();
        let ctx = DetectionContext {
            metrics: &metrics,
            window_seq: 1,
            timestamp_ns: 0,
            fabric: &env,
            cq_latency_sketch: None,
        };
        let samples = p.collect(&ctx);
        assert!(samples[0].confidence < 0.5);
    }
}

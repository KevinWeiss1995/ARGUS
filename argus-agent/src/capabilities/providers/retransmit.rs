//! RetransmitSignal capability — the most fabric-divergent signal.
//!
//! Tier order (per the architecture plan):
//!   1. **eBPF kprobe** on driver retry counters — ideal but requires
//!      stable kernel symbols (`mlx5_ib_retransmit`, `rxe_requester` retry
//!      paths, etc.). Scaffolded; off by default.
//!   2. **ethtool driver-private stats** — many ethernet RDMA drivers
//!      expose `tx_pkts_phy`, `rx_oos`, `retry_*` keys. Quality = Medium.
//!      Stubbed: probe `Unavailable` until ethtool integration lands.
//!   3. **MAD/perfquery on real IB**: `port_xmit_pkts` vs `port_rcv_pkts`
//!      ratio anomaly. Quality = Medium.
//!   4. **WR ratio inference**: when `hw_xmit_pkts > hw_rcv_pkts` by more
//!      than expected, infer retransmissions. This is the Soft-RoCE path.
//!      Quality = Low.
//!
//! The pipeline today already aggregates `rxe_*` deltas; the inference
//! provider re-uses them.

use crate::capabilities::{
    CapabilityProvider, DetectionContext, FabricEnv, ProbeOutcome,
};
use argus_common::{BackendId, Capability, Quality, Sample};

pub struct EbpfRetransmitProvider {
    attached: bool,
}

impl EbpfRetransmitProvider {
    #[must_use]
    pub fn new() -> Self {
        Self { attached: false }
    }
}

impl Default for EbpfRetransmitProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for EbpfRetransmitProvider {
    fn id(&self) -> BackendId {
        BackendId::EbpfRetx
    }
    fn capability(&self) -> Capability {
        Capability::RetransmitSignal
    }
    fn declared_quality(&self) -> Quality {
        Quality::High
    }
    fn probe(&mut self, env: &FabricEnv) -> ProbeOutcome {
        if env.synthetic || !env.privileges.can_run_ebpf() || !self.attached {
            return ProbeOutcome::Unavailable {
                reason: "ebpf retx probe not attached (scaffold)".into(),
            };
        }
        ProbeOutcome::Available {
            quality: Quality::High,
        }
    }
    fn collect(&mut self, _ctx: &DetectionContext<'_>) -> Vec<Sample> {
        vec![]
    }
}

/// MAD/perfquery proxy: real IB fabrics expose `port_xmit_pkts` vs
/// `port_rcv_pkts` plus `port_rcv_remote_physical_errors` via the standard
/// counter set. We treat *deltas of these* over a window as a Medium-quality
/// retransmit signal — true retransmits aren't directly exposed, but the
/// asymmetry plus remote-physical errors is the canonical proxy.
pub struct MadRetransmitProvider;

impl MadRetransmitProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for MadRetransmitProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for MadRetransmitProvider {
    fn id(&self) -> BackendId {
        BackendId::MadRetxProxy
    }
    fn capability(&self) -> Capability {
        Capability::RetransmitSignal
    }
    fn declared_quality(&self) -> Quality {
        Quality::Medium
    }
    fn probe(&mut self, env: &FabricEnv) -> ProbeOutcome {
        // Real IB only — RoCE/softroce expose the same counters but the
        // retransmit semantics differ.
        let any_ib = env.devices.iter().any(|d| {
            matches!(
                d.fabric,
                crate::capabilities::FabricKind::InfiniBand
            )
        });
        if !any_ib {
            return ProbeOutcome::Unavailable {
                reason: "no InfiniBand fabric detected".into(),
            };
        }
        if env.any_device_has_std_counter("port_rcv_remote_physical_errors") {
            ProbeOutcome::Available {
                quality: Quality::Medium,
            }
        } else {
            ProbeOutcome::Unavailable {
                reason: "port_rcv_remote_physical_errors counter not exposed".into(),
            }
        }
    }
    fn collect(&mut self, ctx: &DetectionContext<'_>) -> Vec<Sample> {
        let d = &ctx.metrics.ib_counter_deltas;
        let phys = d.port_rcv_remote_physical_errors_delta as f64;
        let asymm = (d.hw_xmit_pkts_delta as f64 - d.hw_rcv_pkts_delta as f64).max(0.0);
        let value = phys + 0.05 * asymm;
        vec![Sample {
            capability: Capability::RetransmitSignal,
            value,
            confidence: if d.has_traffic() { 0.7 } else { 0.2 },
            quality: Quality::Medium,
            origin: BackendId::MadRetxProxy,
            timestamp_ns: ctx.timestamp_ns,
            qp_num: None,
            port: None,
            priority: None,
            device: None,
        }]
    }
}

pub struct SysfsRetransmitProvider;

impl SysfsRetransmitProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for SysfsRetransmitProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for SysfsRetransmitProvider {
    fn id(&self) -> BackendId {
        BackendId::EthtoolRetx
    }
    fn capability(&self) -> Capability {
        Capability::RetransmitSignal
    }
    fn declared_quality(&self) -> Quality {
        Quality::Medium
    }
    fn probe(&mut self, env: &FabricEnv) -> ProbeOutcome {
        // ethtool integration lands separately. Until then, only enable
        // when sysfs hw_counters expose retry-style names — a reasonable
        // proxy for "this driver tracks retransmits."
        if env.any_device_has_hw_counter("retry") {
            ProbeOutcome::Available {
                quality: Quality::Medium,
            }
        } else {
            ProbeOutcome::Unavailable {
                reason: "no retry/* counters in sysfs hw_counters".into(),
            }
        }
    }
    fn collect(&mut self, ctx: &DetectionContext<'_>) -> Vec<Sample> {
        let d = &ctx.metrics.ib_counter_deltas;
        // RXE retry_exceeded is a Medium-quality signal: we know retry path
        // was hit but not how often per-QP. Pair with seq_error / dup_request
        // to get a useful rate.
        let retry = d.rxe_retry_exceeded_delta as f64;
        let seq = d.rxe_seq_error_delta as f64;
        let dup = d.rxe_duplicate_request_delta as f64;
        let value = retry + 0.5 * seq + 0.3 * dup;
        let traffic = d.has_traffic();
        let confidence = if traffic { 0.8 } else { 0.2 };
        vec![Sample {
            capability: Capability::RetransmitSignal,
            value,
            confidence,
            quality: Quality::Medium,
            origin: BackendId::EthtoolRetx,
            timestamp_ns: ctx.timestamp_ns,
            qp_num: None,
            port: None,
            priority: None,
            device: None,
        }]
    }
}

/// Inference fallback: derive a retransmit-rate-like signal from packet asymmetry.
/// `xmit > rcv * 1.05` over the same window suggests redundant traffic on the
/// wire. Quality = Low.
pub struct InferredRetransmitProvider;

impl InferredRetransmitProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for InferredRetransmitProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for InferredRetransmitProvider {
    fn id(&self) -> BackendId {
        BackendId::WrRatioInference
    }
    fn capability(&self) -> Capability {
        Capability::RetransmitSignal
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
        let d = &ctx.metrics.ib_counter_deltas;
        let xmit = d.hw_xmit_pkts_delta as f64;
        let rcv = d.hw_rcv_pkts_delta as f64;
        if xmit < 1.0 || rcv < 1.0 {
            return vec![];
        }
        // Proxy: "extra" packets per direction beyond the 1:1 baseline.
        let extra = (xmit - rcv).max(0.0);
        let ratio = extra / xmit.max(1.0);
        // Confidence is low and only rises if we observe sustained asymmetry.
        let conf = (ratio * 4.0).clamp(0.0, 0.4);
        vec![Sample {
            capability: Capability::RetransmitSignal,
            value: ratio,
            confidence: conf,
            quality: Quality::Low,
            origin: BackendId::WrRatioInference,
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

    fn ctx_with<'a>(env: &'a FabricEnv, metrics: &'a AggregatedMetrics) -> DetectionContext<'a> {
        DetectionContext {
            metrics,
            window_seq: 1,
            timestamp_ns: 0,
            fabric: env,
            cq_latency_sketch: None,
        }
    }

    #[test]
    fn inferred_retransmit_zero_when_no_asymmetry() {
        let env = FabricEnv::synthetic();
        let mut p = InferredRetransmitProvider::new();
        let metrics = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                hw_rcv_pkts_delta: 100,
                hw_xmit_pkts_delta: 100,
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx = ctx_with(&env, &metrics);
        let samples = p.collect(&ctx);
        assert!(samples.is_empty() || samples[0].value == 0.0);
    }

    #[test]
    fn inferred_retransmit_detects_asymmetry() {
        let env = FabricEnv::synthetic();
        let mut p = InferredRetransmitProvider::new();
        let metrics = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                hw_rcv_pkts_delta: 100,
                hw_xmit_pkts_delta: 200,
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx = ctx_with(&env, &metrics);
        let samples = p.collect(&ctx);
        assert_eq!(samples.len(), 1);
        assert!(samples[0].value > 0.0);
        assert_eq!(samples[0].quality, Quality::Low);
    }

    #[test]
    fn mad_retransmit_unavailable_on_softroce() {
        let env = FabricEnv::synthetic(); // softroce
        let mut p = MadRetransmitProvider::new();
        match p.probe(&env) {
            ProbeOutcome::Unavailable { .. } => (),
            ProbeOutcome::Available { .. } => panic!("should be unavailable on softroce"),
        }
    }
}

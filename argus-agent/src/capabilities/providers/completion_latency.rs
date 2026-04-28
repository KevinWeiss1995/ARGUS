//! CompletionLatency capability.
//!
//! Three tiers, from highest to lowest fidelity:
//!   1. **eBPF kprobe on CQ post/poll**: provides true per-completion latency.
//!      Available when CAP_BPF is held *and* a relevant tracepoint/kprobe
//!      exists on the kernel (mlx5_ib_poll_one, ib_poll_cq, rxe_completer, etc.).
//!   2. **`libibverbs` poll-time sampling**: requires linking rdma-core; we
//!      stub it and mark Unavailable for now (path documented for future).
//!   3. **Throughput-proxy inference**: derive a *jitter* signal from
//!      already-aggregated `cq_jitter` metrics. Quality = Low.
//!
//! All tiers feed a `DdSketch` for percentile output (p50/p95/p99/p999).

use crate::capabilities::{
    sketches::DdSketch, CapabilityProvider, DetectionContext, FabricEnv, ProbeOutcome,
};
use argus_common::{BackendId, Capability, Quality, Sample};

/// The eBPF tier. On platforms without the privilege/kernel support, probes
/// `Unavailable` and the provider chain falls through to the inference tier.
///
/// **Status**: scaffold only. The backing eBPF program is intentionally not
/// added in this commit — adding it requires CO-RE bindings for several CQ
/// poll functions across kernels. The provider is wired so it can be
/// switched on by replacing `attached: false` with real attach logic without
/// touching the registry.
pub struct EbpfCqLatencyProvider {
    sketch: DdSketch,
    attached: bool,
}

impl EbpfCqLatencyProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sketch: DdSketch::new(0.02, 1024),
            attached: false,
        }
    }
}

impl Default for EbpfCqLatencyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for EbpfCqLatencyProvider {
    fn id(&self) -> BackendId {
        BackendId::EbpfCqLatency
    }
    fn capability(&self) -> Capability {
        Capability::CompletionLatency
    }
    fn declared_quality(&self) -> Quality {
        Quality::High
    }
    fn probe(&mut self, env: &FabricEnv) -> ProbeOutcome {
        // We require root/CAP_BPF *and* a real (non-synthetic) host. Until
        // the eBPF program lands, always report Unavailable so the registry
        // falls back to the inference tier deterministically.
        if env.synthetic {
            return ProbeOutcome::Unavailable {
                reason: "synthetic env".into(),
            };
        }
        if !env.privileges.can_run_ebpf() {
            return ProbeOutcome::Unavailable {
                reason: "missing CAP_BPF / not root".into(),
            };
        }
        if !self.attached {
            return ProbeOutcome::Unavailable {
                reason: "ebpf cq-latency program not attached (scaffold)".into(),
            };
        }
        ProbeOutcome::Available {
            quality: Quality::High,
        }
    }
    fn collect(&mut self, ctx: &DetectionContext<'_>) -> Vec<Sample> {
        // When attached, drain per-completion samples from the BPF map into
        // the sketch and emit percentile samples. Until then this returns
        // an empty Vec — the provider is dormant.
        if !self.attached {
            return vec![];
        }
        // Future: drain BPF ringbuf into self.sketch.insert(latency_ns)
        let _ = ctx;
        let p50 = self.sketch.quantile(0.50);
        let p99 = self.sketch.quantile(0.99);
        let p999 = self.sketch.quantile(0.999);
        let count = self.sketch.count();
        self.sketch.reset();
        let confidence = if count >= 100 { 1.0 } else { (count as f64 / 100.0).max(0.05) };
        vec![
            ebpf_quantile_sample("p50", p50, confidence, ctx.timestamp_ns),
            ebpf_quantile_sample("p99", p99, confidence, ctx.timestamp_ns),
            ebpf_quantile_sample("p999", p999, confidence, ctx.timestamp_ns),
        ]
    }
}

fn ebpf_quantile_sample(label: &'static str, value: f64, confidence: f64, ts: u64) -> Sample {
    Sample {
        capability: Capability::CompletionLatency,
        value,
        confidence,
        quality: Quality::High,
        origin: BackendId::EbpfCqLatency,
        timestamp_ns: ts,
        qp_num: None,
        port: None,
        priority: None,
        device: Some(label.to_string()),
    }
}

/// Inferred / proxy tier: prefer the per-window DDSketch from the
/// aggregator (medium quality if any completions arrived this window),
/// fall back to coarse `cq_jitter` aggregates (low quality).
pub struct ThroughputProxyLatencyProvider;

impl ThroughputProxyLatencyProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for ThroughputProxyLatencyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for ThroughputProxyLatencyProvider {
    fn id(&self) -> BackendId {
        BackendId::ThroughputProxyLatency
    }
    fn capability(&self) -> Capability {
        Capability::CompletionLatency
    }
    fn declared_quality(&self) -> Quality {
        // High when CQ events feed the DDSketch — that path produces
        // bin-quantile estimates within `alpha=0.02` (2%) of true
        // percentiles. The fallback aggregate path emits Low quality
        // per-sample so the fusion layer down-weights it appropriately.
        Quality::High
    }
    fn probe(&mut self, _env: &FabricEnv) -> ProbeOutcome {
        ProbeOutcome::Available {
            quality: Quality::High,
        }
    }
    fn collect(&mut self, ctx: &DetectionContext<'_>) -> Vec<Sample> {
        // Preferred path: real DDSketch from this window's CQ completions.
        if let Some(sk) = ctx.cq_latency_sketch {
            if sk.count() > 0 {
                let count = sk.count();
                let conf = (count as f64 / 200.0).clamp(0.1, 0.95);
                return vec![
                    quantile_sample("p50", sk.quantile(0.50), conf, ctx.timestamp_ns, Quality::Medium),
                    quantile_sample("p95", sk.quantile(0.95), conf, ctx.timestamp_ns, Quality::Medium),
                    quantile_sample("p99", sk.quantile(0.99), conf, ctx.timestamp_ns, Quality::Medium),
                    quantile_sample("p999", sk.quantile(0.999), conf, ctx.timestamp_ns, Quality::Medium),
                ];
            }
        }

        // Fallback: aggregate cq_jitter — Low quality.
        let cq = &ctx.metrics.cq_jitter;
        if cq.completion_count == 0 {
            return vec![];
        }
        let avg = cq.avg_latency_ns() as f64;
        let p99 = cq.estimated_p99_ns() as f64;
        let max = cq.max_latency_ns as f64;
        let conf = (cq.completion_count as f64 / 100.0).clamp(0.05, 0.7);
        vec![
            quantile_sample("avg", avg, conf, ctx.timestamp_ns, Quality::Low),
            quantile_sample("p99", p99, conf, ctx.timestamp_ns, Quality::Low),
            quantile_sample("max", max, conf, ctx.timestamp_ns, Quality::Low),
        ]
    }
}

fn quantile_sample(
    label: &'static str,
    value: f64,
    confidence: f64,
    ts: u64,
    quality: Quality,
) -> Sample {
    Sample {
        capability: Capability::CompletionLatency,
        value,
        confidence,
        quality,
        origin: BackendId::ThroughputProxyLatency,
        timestamp_ns: ts,
        qp_num: None,
        port: None,
        priority: None,
        device: Some(label.to_string()),
    }
}

//! Throughput capability — bytes and packets per window from sysfs port counters.

use crate::capabilities::{
    CapabilityProvider, DetectionContext, FabricEnv, ProbeOutcome,
};
use argus_common::{BackendId, Capability, Quality, Sample};

pub struct SysfsThroughputProvider;

impl SysfsThroughputProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for SysfsThroughputProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for SysfsThroughputProvider {
    fn id(&self) -> BackendId {
        BackendId::SysfsPortCounters
    }
    fn capability(&self) -> Capability {
        Capability::Throughput
    }
    fn declared_quality(&self) -> Quality {
        Quality::High
    }
    fn probe(&mut self, env: &FabricEnv) -> ProbeOutcome {
        if env.synthetic || !env.devices.is_empty() {
            ProbeOutcome::Available {
                quality: Quality::High,
            }
        } else {
            ProbeOutcome::Unavailable {
                reason: "no RDMA devices".into(),
            }
        }
    }
    fn collect(&mut self, ctx: &DetectionContext<'_>) -> Vec<Sample> {
        let d = &ctx.metrics.ib_counter_deltas;
        let pkts = d.throughput_pkts() as f64;
        let bytes = d.throughput_bytes() as f64;

        // Two samples: one for packet rate, one for byte rate. Detection
        // rules pick the one they care about.
        vec![
            Sample {
                capability: Capability::Throughput,
                value: pkts,
                confidence: 1.0,
                quality: Quality::High,
                origin: BackendId::SysfsPortCounters,
                timestamp_ns: ctx.timestamp_ns,
                qp_num: None,
                port: None,
                priority: None,
                device: Some("pkts".into()),
            },
            Sample {
                capability: Capability::Throughput,
                value: bytes,
                confidence: 1.0,
                quality: Quality::High,
                origin: BackendId::SysfsPortCounters,
                timestamp_ns: ctx.timestamp_ns,
                qp_num: None,
                port: None,
                priority: None,
                device: Some("bytes".into()),
            },
        ]
    }
}

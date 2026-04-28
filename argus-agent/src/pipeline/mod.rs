pub mod aggregator;

use argus_common::{AggregatedMetrics, Alert, ArgusEvent, CoverageReport, Sample};

use crate::capabilities::{
    providers::default_candidates, CapabilityRegistry, DetectionContext, FabricEnv,
};
use crate::detection::DetectionEngine;
use aggregator::Aggregator;

/// Central processing pipeline: ingest events, aggregate metrics, run detection.
///
/// Owns the capability registry and fabric environment so providers can be
/// polled once per window in lock-step with detection. The registry's
/// coverage report is surfaced via `/coverage` and the
/// `argus_capability_coverage` Prometheus gauge.
pub struct Pipeline {
    aggregator: Aggregator,
    detection: DetectionEngine,
    capabilities: CapabilityRegistry,
    fabric: FabricEnv,
    window_seq: u64,
    last_samples: Vec<Sample>,
}

impl Pipeline {
    #[must_use]
    pub fn new(num_cpus: u32) -> Self {
        let fabric = FabricEnv::detect();
        Self::with_fabric(num_cpus, fabric, &crate::config::DetectionConfig::default())
    }

    #[must_use]
    pub fn with_config(num_cpus: u32, config: &crate::config::DetectionConfig) -> Self {
        let fabric = FabricEnv::detect();
        Self::with_fabric(num_cpus, fabric, config)
    }

    /// Test/agent constructor with explicit `FabricEnv`. Useful when the
    /// caller wants to inject a synthetic environment or pre-detected
    /// fabric (e.g., from `--simulate` mode).
    #[must_use]
    pub fn with_fabric(
        num_cpus: u32,
        fabric: FabricEnv,
        config: &crate::config::DetectionConfig,
    ) -> Self {
        let candidates = default_candidates(&fabric);
        let capabilities = CapabilityRegistry::new(&fabric, candidates);
        Self {
            aggregator: Aggregator::new(num_cpus),
            detection: DetectionEngine::with_config(config),
            capabilities,
            fabric,
            window_seq: 0,
            last_samples: Vec::new(),
        }
    }

    /// Ingest a single event into the aggregator without running detection.
    pub fn ingest(&mut self, event: &ArgusEvent) {
        self.aggregator.ingest(event);
    }

    /// Ingest a BPF map snapshot (live mode only).
    #[cfg(target_os = "linux")]
    pub fn ingest_bpf_snapshot(&mut self, snap: &crate::sources::ebpf::BpfMapSnapshot) {
        self.aggregator.ingest_bpf_snapshot(snap);
    }

    /// Run detection rules against current aggregated metrics.
    /// Call once per window tick, not per event. Capability providers run
    /// **before** detection so rules see fresh `Sample`s in the same window.
    /// The detection engine computes the composite health score internally.
    pub fn evaluate(&mut self) -> Vec<Alert> {
        self.window_seq += 1;
        let timestamp_ns = self
            .aggregator
            .current_metrics()
            .window_end_ns;

        // Phase 1: collect samples from every active capability provider.
        let metrics_snapshot = self.aggregator.current_metrics();
        let cq_sketch = self.aggregator.cq_latency_sketch();
        let ctx = DetectionContext {
            metrics: metrics_snapshot,
            window_seq: self.window_seq,
            timestamp_ns,
            fabric: &self.fabric,
            cq_latency_sketch: Some(cq_sketch),
        };
        let samples = self.capabilities.collect_all(&ctx);
        self.last_samples = samples.clone();

        // Phase 2: feed metrics + samples to the detection engine.
        let coverage = self.capabilities.coverage().clone();
        let alerts = self.detection.evaluate_with_coverage(
            self.aggregator.current_metrics(),
            &samples,
            Some(&coverage),
        );
        let score = self.detection.smoothed_score().effective();
        self.aggregator.set_health_score(score);
        alerts
    }

    #[must_use]
    pub fn current_metrics(&self) -> &AggregatedMetrics {
        self.aggregator.current_metrics()
    }

    pub fn reset_window(&mut self) {
        self.aggregator.reset();
        // Detection engine state (hysteresis, rolling stats) intentionally
        // persists across windows. Only the aggregator resets.
    }

    #[must_use]
    pub fn detection_engine(&self) -> &DetectionEngine {
        &self.detection
    }

    #[must_use]
    pub fn fabric(&self) -> &FabricEnv {
        &self.fabric
    }

    #[must_use]
    pub fn coverage(&self) -> &CoverageReport {
        self.capabilities.coverage()
    }

    /// Most recent sample batch — used by status/coverage endpoints.
    #[must_use]
    pub fn last_samples(&self) -> &[Sample] {
        &self.last_samples
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::{IrqEntryEvent, SlabAllocEvent};

    fn synthetic_pipeline(num_cpus: u32) -> Pipeline {
        Pipeline::with_fabric(
            num_cpus,
            FabricEnv::synthetic(),
            &crate::config::DetectionConfig::default(),
        )
    }

    #[test]
    fn pipeline_ingests_events() {
        let mut pipeline = synthetic_pipeline(4);

        let event = ArgusEvent::SlabAlloc(SlabAllocEvent {
            timestamp_ns: 1_000_000,
            cpu: 0,
            bytes_req: 64,
            bytes_alloc: 64,
            latency_ns: 500,
            numa_node: 0,
        });

        pipeline.ingest(&event);
        let metrics = pipeline.current_metrics();
        assert_eq!(metrics.slab_metrics.alloc_count, 1);
        assert_eq!(metrics.slab_metrics.total_latency_ns, 500);
    }

    #[test]
    fn pipeline_evaluate_runs_detection() {
        use argus_common::HardwareCounterEvent;

        let mut pipeline = synthetic_pipeline(4);

        let mut base_pkts = 0u64;
        let mut base_dup = 0u64;

        let mut ingest_bad = |pipeline: &mut Pipeline| {
            for i in 0u32..100 {
                let cpu: u32 = if i < 75 { 0 } else { (i % 3) + 1 };
                pipeline.ingest(&ArgusEvent::IrqEntry(IrqEntryEvent {
                    timestamp_ns: u64::from(i) * 1_000_000,
                    cpu,
                    irq: 33,
                    handler_name_hash: 0xaabb,
                }));
            }
            base_pkts += 100;
            base_dup += 30;
            pipeline.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
                timestamp_ns: 200_000_000,
                port_num: 1,
                counter: argus_common::HardwareCounter::HwRcvPkts(base_pkts),
            }));
            pipeline.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
                timestamp_ns: 200_000_000,
                port_num: 1,
                counter: argus_common::HardwareCounter::RxeDuplicateRequest(base_dup),
            }));
        };

        ingest_bad(&mut pipeline);
        let _ = pipeline.evaluate();
        pipeline.reset_window();

        ingest_bad(&mut pipeline);
        let _ = pipeline.evaluate();
        pipeline.reset_window();

        for _ in 0..4 {
            ingest_bad(&mut pipeline);
            let _ = pipeline.evaluate();
            pipeline.reset_window();
        }

        let state = pipeline.detection_engine().current_state();
        assert!(
            state != argus_common::HealthState::Healthy,
            "sustained bad metrics should trigger at least Degraded, got {state:?}"
        );
    }

    #[test]
    fn pipeline_reset_clears_metrics() {
        let mut pipeline = synthetic_pipeline(4);

        let event = ArgusEvent::SlabAlloc(SlabAllocEvent {
            timestamp_ns: 1_000_000,
            cpu: 0,
            bytes_req: 64,
            bytes_alloc: 64,
            latency_ns: 500,
            numa_node: 0,
        });
        pipeline.ingest(&event);
        pipeline.reset_window();

        let metrics = pipeline.current_metrics();
        assert_eq!(metrics.slab_metrics.alloc_count, 0);
    }

    #[test]
    fn pipeline_exposes_coverage_report() {
        let pipeline = synthetic_pipeline(4);
        let cov = pipeline.coverage();
        // Synthetic env: at minimum we expect LinkErrors + Throughput active.
        let active: Vec<_> = cov.capabilities.iter().filter(|c| c.active_backend.is_some()).collect();
        assert!(!active.is_empty(), "synthetic env should have at least one active provider");
    }

    #[test]
    fn pipeline_evaluate_collects_samples() {
        let mut pipeline = synthetic_pipeline(4);
        pipeline.ingest(&ArgusEvent::IrqEntry(IrqEntryEvent {
            timestamp_ns: 1_000_000,
            cpu: 0,
            irq: 33,
            handler_name_hash: 0,
        }));
        let _ = pipeline.evaluate();
        // last_samples should contain at least one sample (LinkErrors + Throughput).
        assert!(!pipeline.last_samples().is_empty());
    }
}

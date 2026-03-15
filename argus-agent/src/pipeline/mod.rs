pub mod aggregator;

use argus_common::{AggregatedMetrics, Alert, ArgusEvent};

use crate::detection::DetectionEngine;
use aggregator::Aggregator;

/// Central processing pipeline: ingest events, aggregate metrics, run detection.
pub struct Pipeline {
    aggregator: Aggregator,
    detection: DetectionEngine,
}

impl Pipeline {
    #[must_use]
    pub fn new(num_cpus: u32) -> Self {
        Self {
            aggregator: Aggregator::new(num_cpus),
            detection: DetectionEngine::new(),
        }
    }

    #[must_use]
    pub fn with_config(num_cpus: u32, config: &crate::config::DetectionConfig) -> Self {
        Self {
            aggregator: Aggregator::new(num_cpus),
            detection: DetectionEngine::with_config(config),
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
    /// Call once per window tick, not per event.
    pub fn evaluate(&mut self) -> Vec<Alert> {
        self.detection.evaluate(self.aggregator.current_metrics())
    }

    #[must_use]
    pub fn current_metrics(&self) -> &AggregatedMetrics {
        self.aggregator.current_metrics()
    }

    pub fn reset_window(&mut self) {
        self.aggregator.reset();
        // NOTE: detection engine state (hysteresis counters, rolling stats)
        // persists across windows intentionally. Only the aggregator resets.
    }

    #[must_use]
    pub fn detection_engine(&self) -> &DetectionEngine {
        &self.detection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::{IrqEntryEvent, SlabAllocEvent};

    #[test]
    fn pipeline_ingests_events() {
        let mut pipeline = Pipeline::new(4);

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
        let mut pipeline = Pipeline::new(4);

        let ingest_skewed = |pipeline: &mut Pipeline| {
            for i in 0u32..100 {
                let cpu: u32 = if i < 75 { 0 } else { (i % 3) + 1 };
                pipeline.ingest(&ArgusEvent::IrqEntry(IrqEntryEvent {
                    timestamp_ns: u64::from(i) * 1_000_000,
                    cpu,
                    irq: 33,
                    handler_name_hash: 0xaabb,
                }));
            }
        };

        // Window 1: skewed, evaluate, reset
        ingest_skewed(&mut pipeline);
        let _ = pipeline.evaluate();
        pipeline.reset_window();

        // Window 2: skewed again, evaluate — hysteresis should now trigger
        ingest_skewed(&mut pipeline);
        let _ = pipeline.evaluate();

        let metrics = pipeline.current_metrics();
        assert_eq!(metrics.interrupt_distribution.total_count, 100);
        assert!(metrics.interrupt_distribution.dominant_cpu_pct() >= 70.0);
        assert_eq!(
            pipeline.detection_engine().current_state(),
            argus_common::HealthState::Degraded,
            "skewed IRQs should trigger degraded after hysteresis"
        );
    }

    #[test]
    fn pipeline_reset_clears_metrics() {
        let mut pipeline = Pipeline::new(4);

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
}

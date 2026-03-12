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

    /// Process a single event, returning any alerts triggered.
    pub fn process_event(&mut self, event: &ArgusEvent) -> Vec<Alert> {
        self.aggregator.ingest(event);
        self.detection.evaluate(&self.aggregator.current_metrics())
    }

    #[must_use]
    pub fn current_metrics(&self) -> &AggregatedMetrics {
        self.aggregator.current_metrics()
    }

    pub fn reset_window(&mut self) {
        self.aggregator.reset();
        self.detection.reset();
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
    fn pipeline_processes_events() {
        let mut pipeline = Pipeline::new(4);

        let event = ArgusEvent::SlabAlloc(SlabAllocEvent {
            timestamp_ns: 1_000_000,
            cpu: 0,
            bytes_req: 64,
            bytes_alloc: 64,
            latency_ns: 500,
            numa_node: 0,
        });

        let _alerts = pipeline.process_event(&event);
        let metrics = pipeline.current_metrics();
        assert_eq!(metrics.slab_metrics.alloc_count, 1);
        assert_eq!(metrics.slab_metrics.total_latency_ns, 500);
    }

    #[test]
    fn pipeline_tracks_interrupt_distribution() {
        let mut pipeline = Pipeline::new(4);

        for i in 0u32..100 {
            let cpu: u32 = if i < 75 { 0 } else { (i % 3) + 1 };
            let event = ArgusEvent::IrqEntry(IrqEntryEvent {
                timestamp_ns: u64::from(i) * 1_000_000,
                cpu,
                irq: 33,
                handler_name_hash: 0xaabb,
            });
            pipeline.process_event(&event);
        }

        let metrics = pipeline.current_metrics();
        assert_eq!(metrics.interrupt_distribution.total_count, 100);
        assert!(metrics.interrupt_distribution.dominant_cpu_pct() >= 70.0);
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
        pipeline.process_event(&event);
        pipeline.reset_window();

        let metrics = pipeline.current_metrics();
        assert_eq!(metrics.slab_metrics.alloc_count, 0);
    }
}

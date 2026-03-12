use argus_common::{AggregatedMetrics, ArgusEvent};

/// Maintains rolling metric aggregations from raw events.
pub struct Aggregator {
    metrics: AggregatedMetrics,
    num_cpus: u32,
}

impl Aggregator {
    #[must_use]
    pub fn new(num_cpus: u32) -> Self {
        let mut metrics = AggregatedMetrics::default();
        metrics.interrupt_distribution.per_cpu_counts = vec![0; num_cpus as usize];
        Self { metrics, num_cpus }
    }

    pub fn ingest(&mut self, event: &ArgusEvent) {
        let ts = event.timestamp_ns();
        if self.metrics.window_start_ns == 0 {
            self.metrics.window_start_ns = ts;
        }
        self.metrics.window_end_ns = ts;

        match event {
            ArgusEvent::SlabAlloc(e) => {
                self.metrics.slab_metrics.alloc_count += 1;
                self.metrics.slab_metrics.total_latency_ns += e.latency_ns;
                self.metrics.slab_metrics.total_bytes_req += u64::from(e.bytes_req);
                self.metrics.slab_metrics.total_bytes_alloc += u64::from(e.bytes_alloc);
                if e.latency_ns > self.metrics.slab_metrics.max_latency_ns {
                    self.metrics.slab_metrics.max_latency_ns = e.latency_ns;
                }
            }
            ArgusEvent::SlabFree(e) => {
                self.metrics.slab_metrics.free_count += 1;
                let _ = e;
            }
            ArgusEvent::IrqEntry(e) => {
                let cpu_idx = e.cpu as usize;
                if cpu_idx < self.metrics.interrupt_distribution.per_cpu_counts.len() {
                    self.metrics.interrupt_distribution.per_cpu_counts[cpu_idx] += 1;
                }
                self.metrics.interrupt_distribution.total_count += 1;
            }
            ArgusEvent::NapiPoll(e) => {
                self.metrics.network_metrics.napi_polls += 1;
                self.metrics.network_metrics.napi_total_work += u64::from(e.work_done);
                self.metrics.network_metrics.napi_total_budget += u64::from(e.budget);
            }
            ArgusEvent::NetifReceive(e) => {
                self.metrics.network_metrics.packets_received += 1;
                self.metrics.network_metrics.bytes_received += u64::from(e.len);
            }
            ArgusEvent::CqCompletion(e) => {
                self.metrics.rdma_metrics.completion_count += 1;
                self.metrics.rdma_metrics.total_latency_ns += e.latency_ns;
                if e.latency_ns > self.metrics.rdma_metrics.max_latency_ns {
                    self.metrics.rdma_metrics.max_latency_ns = e.latency_ns;
                }
                if e.is_error {
                    self.metrics.rdma_metrics.error_count += 1;
                }
            }
            ArgusEvent::HardwareCounter(_) => {
                // Hardware counters are absolute values, not aggregated incrementally.
                // They are handled separately by the telemetry layer.
            }
        }
    }

    #[must_use]
    pub fn current_metrics(&self) -> &AggregatedMetrics {
        &self.metrics
    }

    pub fn reset(&mut self) {
        self.metrics = AggregatedMetrics::default();
        self.metrics.interrupt_distribution.per_cpu_counts = vec![0; self.num_cpus as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::*;

    #[test]
    fn aggregates_slab_allocs() {
        let mut agg = Aggregator::new(4);

        for i in 0..10 {
            agg.ingest(&ArgusEvent::SlabAlloc(SlabAllocEvent {
                timestamp_ns: i * 1_000_000,
                cpu: 0,
                bytes_req: 64,
                bytes_alloc: 128,
                latency_ns: 100 + i * 10,
                numa_node: 0,
            }));
        }

        let m = &agg.current_metrics().slab_metrics;
        assert_eq!(m.alloc_count, 10);
        assert_eq!(m.total_bytes_req, 640);
        assert_eq!(m.total_bytes_alloc, 1280);
        assert_eq!(m.max_latency_ns, 190);
    }

    #[test]
    fn aggregates_interrupt_distribution() {
        let mut agg = Aggregator::new(4);

        for cpu in [0, 0, 0, 0, 1, 2, 3, 0, 0, 0] {
            agg.ingest(&ArgusEvent::IrqEntry(IrqEntryEvent {
                timestamp_ns: 1_000_000,
                cpu,
                irq: 33,
                handler_name_hash: 0,
            }));
        }

        let dist = &agg.current_metrics().interrupt_distribution;
        assert_eq!(dist.per_cpu_counts, vec![7, 1, 1, 1]);
        assert_eq!(dist.total_count, 10);
        assert_eq!(dist.dominant_cpu_pct(), 70.0);
    }

    #[test]
    fn aggregates_cq_completions() {
        let mut agg = Aggregator::new(4);

        agg.ingest(&ArgusEvent::CqCompletion(CqCompletionEvent {
            timestamp_ns: 1_000_000,
            cpu: 0,
            latency_ns: 2000,
            queue_pair_num: 1,
            is_error: false,
            opcode: 0,
        }));
        agg.ingest(&ArgusEvent::CqCompletion(CqCompletionEvent {
            timestamp_ns: 2_000_000,
            cpu: 1,
            latency_ns: 8000,
            queue_pair_num: 2,
            is_error: true,
            opcode: 0,
        }));

        let m = &agg.current_metrics().rdma_metrics;
        assert_eq!(m.completion_count, 2);
        assert_eq!(m.error_count, 1);
        assert_eq!(m.max_latency_ns, 8000);
        assert_eq!(m.avg_latency_ns(), 5000);
    }

    #[test]
    fn reset_clears_everything() {
        let mut agg = Aggregator::new(4);

        agg.ingest(&ArgusEvent::SlabAlloc(SlabAllocEvent {
            timestamp_ns: 1_000_000,
            cpu: 0,
            bytes_req: 64,
            bytes_alloc: 64,
            latency_ns: 100,
            numa_node: 0,
        }));

        agg.reset();
        let m = agg.current_metrics();
        assert_eq!(m.slab_metrics.alloc_count, 0);
        assert_eq!(m.interrupt_distribution.per_cpu_counts.len(), 4);
        assert_eq!(m.window_start_ns, 0);
    }

    #[test]
    fn window_timestamps_tracked() {
        let mut agg = Aggregator::new(2);

        agg.ingest(&ArgusEvent::IrqEntry(IrqEntryEvent {
            timestamp_ns: 5_000_000,
            cpu: 0,
            irq: 1,
            handler_name_hash: 0,
        }));
        agg.ingest(&ArgusEvent::IrqEntry(IrqEntryEvent {
            timestamp_ns: 15_000_000,
            cpu: 1,
            irq: 1,
            handler_name_hash: 0,
        }));

        let m = agg.current_metrics();
        assert_eq!(m.window_start_ns, 5_000_000);
        assert_eq!(m.window_end_ns, 15_000_000);
    }
}

use std::collections::HashMap;

use argus_common::{AggregatedMetrics, ArgusEvent, HardwareCounter};

/// Maintains rolling metric aggregations from raw events.
pub struct Aggregator {
    metrics: AggregatedMetrics,
    num_cpus: u32,
    /// Previous absolute counter values keyed by (port, counter_discriminant).
    /// Used to compute deltas between windows.
    prev_counters: HashMap<(u32, u8), u64>,
}

fn counter_discriminant(c: &HardwareCounter) -> u8 {
    match c {
        HardwareCounter::SymbolErrors(_) => 0,
        HardwareCounter::LinkDowned(_) => 1,
        HardwareCounter::PortRcvErrors(_) => 2,
        HardwareCounter::PortXmitDiscards(_) => 3,
        HardwareCounter::PortRcvData(_) => 4,
        HardwareCounter::PortXmitData(_) => 5,
        HardwareCounter::PortRcvRemotePhysicalErrors(_) => 6,
        HardwareCounter::LocalLinkIntegrityErrors(_) => 7,
        HardwareCounter::ExcessiveBufferOverrunErrors(_) => 8,
        HardwareCounter::LinkErrorRecovery(_) => 15,
        HardwareCounter::HwRcvPkts(_) => 9,
        HardwareCounter::HwXmitPkts(_) => 10,
        HardwareCounter::RxeDuplicateRequest(_) => 11,
        HardwareCounter::RxeSeqError(_) => 12,
        HardwareCounter::RxeRetryExceeded(_) => 13,
        HardwareCounter::RxeSendError(_) => 14,
        HardwareCounter::PortXmitWait(_) => 16,
    }
}

fn counter_value(c: &HardwareCounter) -> u64 {
    match c {
        HardwareCounter::SymbolErrors(v)
        | HardwareCounter::LinkDowned(v)
        | HardwareCounter::PortRcvErrors(v)
        | HardwareCounter::PortXmitDiscards(v)
        | HardwareCounter::PortRcvData(v)
        | HardwareCounter::PortXmitData(v)
        | HardwareCounter::PortRcvRemotePhysicalErrors(v)
        | HardwareCounter::LocalLinkIntegrityErrors(v)
        | HardwareCounter::ExcessiveBufferOverrunErrors(v)
        | HardwareCounter::LinkErrorRecovery(v)
        | HardwareCounter::HwRcvPkts(v)
        | HardwareCounter::HwXmitPkts(v)
        | HardwareCounter::RxeDuplicateRequest(v)
        | HardwareCounter::RxeSeqError(v)
        | HardwareCounter::RxeRetryExceeded(v)
        | HardwareCounter::RxeSendError(v)
        | HardwareCounter::PortXmitWait(v) => *v,
    }
}

impl Aggregator {
    #[must_use]
    pub fn new(num_cpus: u32) -> Self {
        let mut metrics = AggregatedMetrics::default();
        metrics.interrupt_distribution.per_cpu_counts = vec![0; num_cpus as usize];
        Self {
            metrics,
            num_cpus,
            prev_counters: HashMap::new(),
        }
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
            ArgusEvent::HardwareCounter(e) => {
                self.ingest_hw_counter(e.port_num, &e.counter);
            }
        }
    }

    fn ingest_hw_counter(&mut self, port: u32, counter: &HardwareCounter) {
        let disc = counter_discriminant(counter);
        let current = counter_value(counter);
        let key = (port, disc);

        let delta = if let Some(&prev) = self.prev_counters.get(&key) {
            current.saturating_sub(prev)
        } else {
            0
        };
        self.prev_counters.insert(key, current);

        let d = &mut self.metrics.ib_counter_deltas;
        match counter {
            HardwareCounter::SymbolErrors(_) => d.symbol_error_delta += delta,
            HardwareCounter::LinkDowned(_) => d.link_downed_delta += delta,
            HardwareCounter::PortRcvErrors(_) => d.port_rcv_errors_delta += delta,
            HardwareCounter::PortXmitDiscards(_) => d.port_xmit_discards_delta += delta,
            HardwareCounter::PortRcvData(_) => d.port_rcv_data_delta += delta,
            HardwareCounter::PortXmitData(_) => d.port_xmit_data_delta += delta,
            HardwareCounter::PortRcvRemotePhysicalErrors(_) => {
                d.port_rcv_remote_physical_errors_delta += delta;
            }
            HardwareCounter::LocalLinkIntegrityErrors(_) => {
                d.local_link_integrity_errors_delta += delta;
            }
            HardwareCounter::ExcessiveBufferOverrunErrors(_) => {
                d.excessive_buffer_overrun_errors_delta += delta;
            }
            HardwareCounter::LinkErrorRecovery(_) => {
                d.link_error_recovery_delta += delta;
            }
            HardwareCounter::HwRcvPkts(_) => d.hw_rcv_pkts_delta += delta,
            HardwareCounter::HwXmitPkts(_) => d.hw_xmit_pkts_delta += delta,
            HardwareCounter::RxeDuplicateRequest(_) => d.rxe_duplicate_request_delta += delta,
            HardwareCounter::RxeSeqError(_) => d.rxe_seq_error_delta += delta,
            HardwareCounter::RxeRetryExceeded(_) => d.rxe_retry_exceeded_delta += delta,
            HardwareCounter::RxeSendError(_) => d.rxe_send_error_delta += delta,
            HardwareCounter::PortXmitWait(_) => d.port_xmit_wait_delta += delta,
        }
    }

    /// Ingest a BPF map snapshot (per-window deltas from in-kernel counters).
    /// Sets metrics fields directly — called once per window from the map reader.
    #[cfg(target_os = "linux")]
    pub fn ingest_bpf_snapshot(&mut self, snap: &crate::sources::ebpf::BpfMapSnapshot) {
        let dist = &mut self.metrics.interrupt_distribution;
        for (i, &delta) in snap.per_cpu_irq_deltas.iter().enumerate() {
            if i < dist.per_cpu_counts.len() {
                dist.per_cpu_counts[i] = delta;
            }
        }
        dist.total_count = snap.total_irq_count;

        let slab = &mut self.metrics.slab_metrics;
        slab.alloc_count = snap.slab_alloc_count;
        slab.free_count = snap.slab_free_count;
        slab.total_bytes_req = snap.slab_total_bytes_req;
        slab.total_bytes_alloc = snap.slab_total_bytes_alloc;

        let net = &mut self.metrics.network_metrics;
        net.napi_polls = snap.napi_poll_count;
        net.napi_total_work = snap.napi_total_work;
        net.napi_total_budget = snap.napi_total_budget;

        let cq = &mut self.metrics.cq_jitter;
        cq.completion_count = snap.cq_completion_count;
        cq.total_latency_ns = snap.cq_total_latency_ns;
        cq.max_latency_ns = snap.cq_max_latency_ns;
        cq.stall_count = snap.cq_stall_count;
    }

    #[must_use]
    pub fn current_metrics(&self) -> &AggregatedMetrics {
        &self.metrics
    }

    /// Stamp the composite health score on the current window's metrics.
    /// Called by the pipeline after each detection pass.
    pub fn set_health_score(&mut self, score: f64) {
        self.metrics.composite_health_score = score;
    }

    /// Reset per-window metrics but keep absolute counter state for delta computation.
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

    #[test]
    fn hw_counter_deltas_computed() {
        let mut agg = Aggregator::new(4);

        // First reading establishes baseline (delta = 0)
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 1_000,
            port_num: 1,
            counter: HardwareCounter::SymbolErrors(100),
        }));
        assert_eq!(
            agg.current_metrics().ib_counter_deltas.symbol_error_delta,
            0
        );

        // Second reading: delta = 110 - 100 = 10
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 2_000,
            port_num: 1,
            counter: HardwareCounter::SymbolErrors(110),
        }));
        assert_eq!(
            agg.current_metrics().ib_counter_deltas.symbol_error_delta,
            10
        );

        // Reset clears deltas but retains absolute baseline
        agg.reset();
        assert_eq!(
            agg.current_metrics().ib_counter_deltas.symbol_error_delta,
            0
        );

        // Third reading: delta = 115 - 110 = 5
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 3_000,
            port_num: 1,
            counter: HardwareCounter::SymbolErrors(115),
        }));
        assert_eq!(
            agg.current_metrics().ib_counter_deltas.symbol_error_delta,
            5
        );
    }

    #[test]
    fn hw_counter_multi_port() {
        let mut agg = Aggregator::new(4);

        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 1_000,
            port_num: 1,
            counter: HardwareCounter::LinkDowned(0),
        }));
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 1_000,
            port_num: 2,
            counter: HardwareCounter::LinkDowned(0),
        }));

        // Port 1 link goes down
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 2_000,
            port_num: 1,
            counter: HardwareCounter::LinkDowned(1),
        }));
        assert_eq!(agg.current_metrics().ib_counter_deltas.link_downed_delta, 1);

        // Port 2 also goes down — deltas accumulate across ports
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 2_000,
            port_num: 2,
            counter: HardwareCounter::LinkDowned(2),
        }));
        assert_eq!(agg.current_metrics().ib_counter_deltas.link_downed_delta, 3);
    }
}

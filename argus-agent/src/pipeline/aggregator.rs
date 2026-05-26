use std::collections::{HashMap, HashSet};

use argus_common::{AggregatedMetrics, ArgusEvent, HardwareCounter, IbPortIdle};

use crate::capabilities::sketches::DdSketch;

/// Maintains rolling metric aggregations from raw events.
pub struct Aggregator {
    metrics: AggregatedMetrics,
    num_cpus: u32,
    /// Previous absolute counter values keyed by (port, counter_discriminant).
    /// Used to compute deltas between windows.
    prev_counters: HashMap<(u32, u8), u64>,
    /// Per-window completion latency sketch — fed by `CqCompletion` events.
    /// Provides p50/p95/p99/p999 to the CompletionLatency capability.
    cq_latency_sketch: DdSketch,
    /// Per-port idle counter (port_num → seconds idle). Persists across
    /// window resets — a port with no traffic for 600s reports 600s, not 0.
    /// Hardware error monitoring continues regardless; idle just means
    /// "no throughput observed this window."
    port_idle_seconds: HashMap<u32, u64>,
    /// Ports that observed any non-zero throughput counter delta this window.
    /// Cleared by `mark_window_complete`.
    port_had_traffic_this_window: HashSet<u32>,
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
        HardwareCounter::HwRcvPkts(_) => 9,
        HardwareCounter::HwXmitPkts(_) => 10,
        HardwareCounter::RxeDuplicateRequest(_) => 11,
        HardwareCounter::RxeSeqError(_) => 12,
        HardwareCounter::RxeRetryExceeded(_) => 13,
        HardwareCounter::RxeSendError(_) => 14,
        HardwareCounter::LinkErrorRecovery(_) => 15,
        HardwareCounter::PortXmitWait(_) => 16,
        // Mellanox mlx5 extended counters — disjoint discriminants
        // so they get their own slots in the prev_counters map.
        HardwareCounter::Mlx5LocalAckTimeoutErr(_) => 17,
        HardwareCounter::Mlx5PacketSeqErr(_) => 18,
        HardwareCounter::Mlx5ImpliedNakSeqErr(_) => 19,
        HardwareCounter::Mlx5OutOfBuffer(_) => 20,
        HardwareCounter::Mlx5OutOfSequence(_) => 21,
        HardwareCounter::Mlx5ReqCqeError(_) => 22,
        HardwareCounter::Mlx5RespCqeError(_) => 23,
        HardwareCounter::Mlx5RoceAdpRetrans(_) => 24,
        HardwareCounter::Mlx5RoceSlowRestart(_) => 25,
        HardwareCounter::Mlx5NpCnpSent(_) => 26,
        HardwareCounter::Mlx5RpCnpHandled(_) => 27,
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
        | HardwareCounter::PortXmitWait(v)
        | HardwareCounter::Mlx5LocalAckTimeoutErr(v)
        | HardwareCounter::Mlx5PacketSeqErr(v)
        | HardwareCounter::Mlx5ImpliedNakSeqErr(v)
        | HardwareCounter::Mlx5OutOfBuffer(v)
        | HardwareCounter::Mlx5OutOfSequence(v)
        | HardwareCounter::Mlx5ReqCqeError(v)
        | HardwareCounter::Mlx5RespCqeError(v)
        | HardwareCounter::Mlx5RoceAdpRetrans(v)
        | HardwareCounter::Mlx5RoceSlowRestart(v)
        | HardwareCounter::Mlx5NpCnpSent(v)
        | HardwareCounter::Mlx5RpCnpHandled(v) => *v,
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
            cq_latency_sketch: DdSketch::new(0.02, 1024),
            port_idle_seconds: HashMap::new(),
            port_had_traffic_this_window: HashSet::new(),
        }
    }

    /// Read-only access to the per-window CQ latency sketch. Reset on
    /// `reset()` so quantiles reflect a single window.
    #[must_use]
    pub fn cq_latency_sketch(&self) -> &DdSketch {
        &self.cq_latency_sketch
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
                // RdmaMetrics: the legacy per-event aggregate (kept for
                // backwards-compat with replay scenarios that key off it).
                self.metrics.rdma_metrics.completion_count += 1;
                self.metrics.rdma_metrics.total_latency_ns += e.latency_ns;
                if e.latency_ns > self.metrics.rdma_metrics.max_latency_ns {
                    self.metrics.rdma_metrics.max_latency_ns = e.latency_ns;
                }
                if e.is_error {
                    self.metrics.rdma_metrics.error_count += 1;
                }

                // CqJitter: the field the TUI panel + detection rules
                // actually read for CQ latency / micro-stall analysis.
                // In live mode this is populated from the eBPF
                // CQ_JITTER_STATS map via ingest_bpf_snapshot — but
                // mock and replay sources emit individual
                // CqCompletionEvent records that never reach that
                // path. Without this mirror, the CQ Latency p99 panel
                // is permanently blank in mock/replay regardless of
                // event content. Mirror the same fields here so the
                // panel works in every mode.
                let cq = &mut self.metrics.cq_jitter;
                cq.completion_count += 1;
                cq.total_latency_ns += e.latency_ns;
                if e.latency_ns > cq.max_latency_ns {
                    cq.max_latency_ns = e.latency_ns;
                }
                // A latency that exceeds the "stall" threshold counts
                // for the stall_count signal that CqJitterRule keys
                // off. 50µs matches the threshold the eBPF probe uses
                // internally for the same metric.
                if e.latency_ns >= 50_000 {
                    cq.stall_count += 1;
                }

                self.cq_latency_sketch.insert(e.latency_ns as f64);
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

        // Any hw counter reading for this port means the port is being polled.
        // Initialize its idle tracker if we haven't seen it before.
        self.port_idle_seconds.entry(port).or_insert(0);

        // Mark traffic if a throughput counter shows non-zero delta.
        let is_throughput = matches!(
            counter,
            HardwareCounter::PortRcvData(_)
                | HardwareCounter::PortXmitData(_)
                | HardwareCounter::HwRcvPkts(_)
                | HardwareCounter::HwXmitPkts(_)
        );
        if is_throughput && delta > 0 {
            self.port_had_traffic_this_window.insert(port);
        }

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
            HardwareCounter::Mlx5LocalAckTimeoutErr(_) => {
                d.mlx5_local_ack_timeout_err_delta += delta;
            }
            HardwareCounter::Mlx5PacketSeqErr(_) => d.mlx5_packet_seq_err_delta += delta,
            HardwareCounter::Mlx5ImpliedNakSeqErr(_) => {
                d.mlx5_implied_nak_seq_err_delta += delta;
            }
            HardwareCounter::Mlx5OutOfBuffer(_) => d.mlx5_out_of_buffer_delta += delta,
            HardwareCounter::Mlx5OutOfSequence(_) => d.mlx5_out_of_sequence_delta += delta,
            HardwareCounter::Mlx5ReqCqeError(_) => d.mlx5_req_cqe_error_delta += delta,
            HardwareCounter::Mlx5RespCqeError(_) => d.mlx5_resp_cqe_error_delta += delta,
            HardwareCounter::Mlx5RoceAdpRetrans(_) => d.mlx5_roce_adp_retrans_delta += delta,
            HardwareCounter::Mlx5RoceSlowRestart(_) => d.mlx5_roce_slow_restart_delta += delta,
            HardwareCounter::Mlx5NpCnpSent(_) => d.mlx5_np_cnp_sent_delta += delta,
            HardwareCounter::Mlx5RpCnpHandled(_) => d.mlx5_rp_cnp_handled_delta += delta,
        }
    }

    /// Roll idle counters at window close. Ports with traffic this window
    /// reset to 0; others accumulate `window_secs`. Call this once per
    /// window, after the snapshot is taken but before `reset()`.
    pub fn mark_window_complete(&mut self, window_secs: u64) {
        for (port, idle) in &mut self.port_idle_seconds {
            if self.port_had_traffic_this_window.contains(port) {
                *idle = 0;
            } else {
                *idle = idle.saturating_add(window_secs);
            }
        }
        self.port_had_traffic_this_window.clear();
    }

    /// Read-only access to the per-port idle map (port_num → idle seconds).
    #[must_use]
    pub fn port_idle_seconds(&self) -> &HashMap<u32, u64> {
        &self.port_idle_seconds
    }

    /// Stamp a fully-annotated per-port idle list onto the current metrics.
    /// Callers supply (device, port) pairs from `HwCounterReader::discovered_ports`
    /// so the device names land in the published `AggregatedMetrics`.
    /// Ports not in the supplied list still get an entry with device name "unknown"
    /// so cross-device port-number collisions remain visible.
    pub fn set_ib_port_idle(&mut self, discovered: &[(String, u32)]) {
        let mut idle_list: Vec<IbPortIdle> = Vec::with_capacity(self.port_idle_seconds.len());
        for (device, port) in discovered {
            if let Some(&idle_seconds) = self.port_idle_seconds.get(port) {
                idle_list.push(IbPortIdle {
                    device: device.clone(),
                    port: *port,
                    idle_seconds,
                });
            }
        }
        // Catch any ports we tracked but the caller didn't enumerate
        // (shouldn't happen in normal operation; preserves visibility).
        for (port, &idle_seconds) in &self.port_idle_seconds {
            if !discovered.iter().any(|(_, p)| p == port) {
                idle_list.push(IbPortIdle {
                    device: "unknown".to_string(),
                    port: *port,
                    idle_seconds,
                });
            }
        }
        self.metrics.ib_port_idle = idle_list;
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
        slab.total_latency_ns = snap.slab_total_latency_ns;
        slab.max_latency_ns = snap.slab_max_latency_ns;

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
        self.cq_latency_sketch.reset();
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
    fn ib_port_idle_zero_when_traffic_present() {
        let mut agg = Aggregator::new(4);

        // Baseline read for port 1 throughput
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 1_000,
            port_num: 1,
            counter: HardwareCounter::PortRcvData(0),
        }));
        // Second read shows non-zero delta — traffic observed
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 2_000,
            port_num: 1,
            counter: HardwareCounter::PortRcvData(4000),
        }));

        agg.mark_window_complete(3);
        agg.set_ib_port_idle(&[("mlx5_0".into(), 1)]);

        let idle = &agg.current_metrics().ib_port_idle;
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0].device, "mlx5_0");
        assert_eq!(idle[0].port, 1);
        assert_eq!(idle[0].idle_seconds, 0);
        assert!(!agg.current_metrics().ib_fabric_idle());
    }

    #[test]
    fn ib_port_idle_accumulates_without_traffic() {
        let mut agg = Aggregator::new(4);

        // Baseline read so the port is tracked
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 1_000,
            port_num: 1,
            counter: HardwareCounter::PortRcvData(0),
        }));
        agg.mark_window_complete(3);

        // Window 2: no throughput delta but error counters still polled
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 4_000,
            port_num: 1,
            counter: HardwareCounter::SymbolErrors(0),
        }));
        agg.mark_window_complete(3);

        // Window 3: still idle
        agg.mark_window_complete(3);

        agg.set_ib_port_idle(&[("mlx5_0".into(), 1)]);

        let idle = &agg.current_metrics().ib_port_idle;
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0].idle_seconds, 9, "3 windows × 3s = 9s idle");
        assert!(agg.current_metrics().ib_fabric_idle());
        assert_eq!(agg.current_metrics().ib_max_idle_seconds(), 9);
    }

    #[test]
    fn ib_port_idle_resets_when_traffic_returns() {
        let mut agg = Aggregator::new(4);

        // Establish port + accumulate some idle time
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 1_000,
            port_num: 1,
            counter: HardwareCounter::HwRcvPkts(0),
        }));
        agg.mark_window_complete(3);
        agg.mark_window_complete(3); // idle += 3
        agg.mark_window_complete(3); // idle += 3 (total 6)

        // Traffic returns
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 2_000,
            port_num: 1,
            counter: HardwareCounter::HwRcvPkts(500),
        }));
        agg.mark_window_complete(3);
        agg.set_ib_port_idle(&[("rxe0".into(), 1)]);

        let idle = &agg.current_metrics().ib_port_idle;
        assert_eq!(idle[0].idle_seconds, 0, "traffic resets idle counter");
    }

    #[test]
    fn ib_fabric_idle_false_when_no_ports_known() {
        let agg = Aggregator::new(4);
        // No ports tracked at all
        assert!(!agg.current_metrics().ib_fabric_idle());
        assert_eq!(agg.current_metrics().ib_max_idle_seconds(), 0);
    }

    #[test]
    fn ib_port_idle_zero_byte_delta_is_idle() {
        let mut agg = Aggregator::new(4);

        // Two readings at same value — zero delta means no traffic
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 1_000,
            port_num: 1,
            counter: HardwareCounter::PortRcvData(1000),
        }));
        agg.ingest(&ArgusEvent::HardwareCounter(HardwareCounterEvent {
            timestamp_ns: 2_000,
            port_num: 1,
            counter: HardwareCounter::PortRcvData(1000),
        }));
        agg.mark_window_complete(3);
        agg.set_ib_port_idle(&[("mlx5_0".into(), 1)]);

        assert_eq!(agg.current_metrics().ib_port_idle[0].idle_seconds, 3);
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

use argus_common::{AggregatedMetrics, HealthState};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};

/// Constant-time byte comparison to prevent timing side-channels on bearer tokens.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

pub struct PrometheusExporter {
    registry: Registry,
    metrics: ArgusPrometheusMetrics,
    prev_health: HealthState,
}

#[derive(Clone)]
struct ArgusPrometheusMetrics {
    health_state: Gauge,
    health_score: Gauge,
    event_count: Gauge,
    alert_count: Family<Vec<(String, String)>, Counter>,
    state_transitions: Family<Vec<(String, String)>, Counter>,
    irq_total: Family<Vec<(String, String)>, Counter>,
    irq_skew_pct: Gauge,
    irq_dominant_cpu: Gauge,
    irq_total_rate: Gauge,
    slab_alloc_count: Counter,
    slab_avg_latency_ns: Gauge,
    slab_max_latency_ns: Gauge,
    cq_completion_count: Counter,
    cq_avg_latency_ns: Gauge,
    cq_max_latency_ns: Gauge,
    cq_stall_count: Counter,
    cq_p99_latency_ns: Gauge,
    ib_error_delta_total: Gauge,
    ib_symbol_errors: Family<Vec<(String, String)>, Gauge>,
    ib_link_downed: Family<Vec<(String, String)>, Gauge>,
    ib_link_error_recovery: Family<Vec<(String, String)>, Gauge>,
    ib_port_rcv_errors: Family<Vec<(String, String)>, Gauge>,
    ib_port_xmit_discards: Family<Vec<(String, String)>, Gauge>,
    ib_port_xmit_wait: Family<Vec<(String, String)>, Gauge>,
    ib_throughput_rcv_bytes: Family<Vec<(String, String)>, Gauge>,
    ib_throughput_xmit_bytes: Family<Vec<(String, String)>, Gauge>,
    ib_throughput_rcv_pkts: Family<Vec<(String, String)>, Gauge>,
    ib_throughput_xmit_pkts: Family<Vec<(String, String)>, Gauge>,
    ib_rxe_duplicate_request: Family<Vec<(String, String)>, Gauge>,
    ib_rxe_seq_error: Family<Vec<(String, String)>, Gauge>,
    ib_rxe_retry_exceeded: Family<Vec<(String, String)>, Gauge>,
    ib_rxe_send_error: Family<Vec<(String, String)>, Gauge>,
    // Mellanox mlx5-specific extended counters — the slow-degradation
    // signal set documented by NVIDIA / OFED. Per-port labelled.
    ib_mlx5_local_ack_timeout_err: Family<Vec<(String, String)>, Gauge>,
    ib_mlx5_packet_seq_err: Family<Vec<(String, String)>, Gauge>,
    ib_mlx5_implied_nak_seq_err: Family<Vec<(String, String)>, Gauge>,
    ib_mlx5_out_of_buffer: Family<Vec<(String, String)>, Gauge>,
    ib_mlx5_out_of_sequence: Family<Vec<(String, String)>, Gauge>,
    ib_mlx5_req_cqe_error: Family<Vec<(String, String)>, Gauge>,
    ib_mlx5_resp_cqe_error: Family<Vec<(String, String)>, Gauge>,
    ib_mlx5_roce_adp_retrans: Family<Vec<(String, String)>, Gauge>,
    ib_mlx5_roce_slow_restart: Family<Vec<(String, String)>, Gauge>,
    ib_mlx5_np_cnp_sent: Family<Vec<(String, String)>, Gauge>,
    ib_mlx5_rp_cnp_handled: Family<Vec<(String, String)>, Gauge>,
    napi_utilization_pct: Gauge,
    // Smoothed health score components
    health_score_raw: Gauge,
    health_score_effective: Gauge,
    health_score_ewma: Gauge,
    health_score_peak_hold: Gauge,
    // Scheduler metrics
    scheduler_desired_state: Gauge,
    scheduler_observed_state: Gauge,
    scheduler_drain_total: Family<Vec<(String, String)>, Counter>,
    scheduler_resume_total: Family<Vec<(String, String)>, Counter>,
    scheduler_errors_total: Family<Vec<(String, String)>, Counter>,
    scheduler_last_action_ts: Gauge,
    scheduler_drain_duration_secs: Gauge,
    scheduler_drain_rejected: Counter,
    // Capability framework
    capability_coverage: Family<Vec<(String, String)>, Gauge>,
    capability_grade: Gauge,
    sample_contribution_millis: Gauge,
    cq_latency_p50_ns: Gauge,
    cq_latency_p95_ns: Gauge,
    cq_latency_p99_ns: Gauge,
    cq_latency_p999_ns: Gauge,
    timescale_state: Family<Vec<(String, String)>, Gauge>,
    timescale_score_millis: Family<Vec<(String, String)>, Gauge>,
    burst_classification: Family<Vec<(String, String)>, Gauge>,
    ebpf_lru_evictions: Family<Vec<(String, String)>, Counter>,
    // IB fabric idle visibility. Idle means "no throughput observed this
    // window" — hardware error counters keep firing regardless.
    ib_port_idle_seconds: Family<Vec<(String, String)>, Gauge>,
    ib_fabric_idle: Gauge,
    ib_max_idle_seconds: Gauge,
    // Polling heartbeat: proves to operators that the sysfs reader is
    // actually being invoked each window, even when every counter delta
    // is legitimately zero. This is what we point at when someone asks
    // "is monitoring actually running? I see all zeros."
    hw_counter_polls_total: Family<Vec<(String, String)>, Counter>,
    hw_counter_last_read_secs: Family<Vec<(String, String)>, Gauge>,
    // Absolute IB counter values (cumulative since boot). Unlike the
    // delta gauges, these are monotonically increasing and let external
    // Prometheus compute long-window slopes:
    //     rate(argus_ib_counter_total{counter="symbol_error_count"}[24h])
    // which is the literature-recommended (El-Sayed & Schroeder DSN
    // 2013; NVIDIA UFM Health Score) pattern for detecting slow IB
    // degradation that doesn't manifest in per-window deltas.
    ib_counter_total: Family<Vec<(String, String)>, Gauge>,
    // NIC host-side health: PCIe link state + thermal. Independent of
    // IB protocol — catches NIC/slot/thermal failures that don't move
    // any IB counter.
    nic_pcie_current_width: Family<Vec<(String, String)>, Gauge>,
    nic_pcie_max_width: Family<Vec<(String, String)>, Gauge>,
    nic_pcie_degraded: Family<Vec<(String, String)>, Gauge>,
    nic_temperature_celsius: Family<Vec<(String, String)>, Gauge>,
    // 0/1 gauges that surface which optional eBPF feature paths
    // actually attached. Operators investigating "why is the CQ
    // Latency panel always zero?" can confirm here whether the
    // probes are alive without grepping /proc/kallsyms by hand.
    ebpf_cq_kprobes_attached: Gauge,
    ebpf_slab_latency_attached: Gauge,
}

impl PrometheusExporter {
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let health_state = Gauge::default();
        registry.register(
            "argus_health_state",
            "Node health state (0=healthy, 1=degraded, 2=critical, 3=recovering)",
            health_state.clone(),
        );

        let health_score = Gauge::default();
        registry.register(
            "argus_health_score_millis",
            "Composite health score in milliunits (0=healthy, 1000=worst)",
            health_score.clone(),
        );

        let event_count = Gauge::default();
        registry.register(
            "argus_events",
            "Total events processed",
            event_count.clone(),
        );

        let alert_count = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_alerts",
            "Total alerts by kind and severity",
            alert_count.clone(),
        );

        let state_transitions = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_state_transitions",
            "Health state transitions",
            state_transitions.clone(),
        );

        let irq_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_irq",
            "Total interrupts by CPU",
            irq_total.clone(),
        );

        let irq_skew_pct = Gauge::default();
        registry.register(
            "argus_irq_imbalance_pct",
            "Normalized IRQ imbalance (0=balanced, 100=all on one CPU)",
            irq_skew_pct.clone(),
        );

        let irq_dominant_cpu = Gauge::default();
        registry.register(
            "argus_irq_dominant_cpu",
            "CPU ID handling the most IRQs in the current window",
            irq_dominant_cpu.clone(),
        );

        let irq_total_rate = Gauge::default();
        registry.register(
            "argus_irq_total_rate",
            "Total IRQ count across all CPUs in the current window",
            irq_total_rate.clone(),
        );

        let slab_alloc_count = Counter::default();
        registry.register(
            "argus_slab_alloc",
            "Total slab allocations",
            slab_alloc_count.clone(),
        );

        let slab_avg_latency_ns = Gauge::default();
        registry.register(
            "argus_slab_avg_latency_ns",
            "Average slab allocation latency in nanoseconds",
            slab_avg_latency_ns.clone(),
        );

        let slab_max_latency_ns = Gauge::default();
        registry.register(
            "argus_slab_max_latency_ns",
            "Maximum slab allocation latency in nanoseconds",
            slab_max_latency_ns.clone(),
        );

        let cq_completion_count = Counter::default();
        registry.register(
            "argus_cq_completions",
            "Total CQ completions",
            cq_completion_count.clone(),
        );

        let cq_avg_latency_ns = Gauge::default();
        registry.register(
            "argus_cq_avg_latency_ns",
            "Average CQ completion latency in nanoseconds",
            cq_avg_latency_ns.clone(),
        );

        let cq_max_latency_ns = Gauge::default();
        registry.register(
            "argus_cq_max_latency_ns",
            "Maximum CQ completion latency in nanoseconds",
            cq_max_latency_ns.clone(),
        );

        let cq_stall_count = Counter::default();
        registry.register(
            "argus_cq_stalls",
            "CQ completions exceeding stall threshold (>50us)",
            cq_stall_count.clone(),
        );

        let cq_p99_latency_ns = Gauge::default();
        registry.register(
            "argus_cq_p99_latency_ns",
            "Estimated p99 CQ completion latency in nanoseconds",
            cq_p99_latency_ns.clone(),
        );

        let ib_error_delta_total = Gauge::default();
        registry.register(
            "argus_ib_error_delta_total",
            "Total IB hardware counter error deltas in current window",
            ib_error_delta_total.clone(),
        );

        let ib_symbol_errors = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_symbol_errors_delta",
            "IB symbol error count delta per window",
            ib_symbol_errors.clone(),
        );

        let ib_link_downed = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_link_downed_delta",
            "IB link downed event delta per window",
            ib_link_downed.clone(),
        );

        let ib_link_error_recovery = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_link_error_recovery_delta",
            "IB link error recovery delta per window (early cable fault warning)",
            ib_link_error_recovery.clone(),
        );

        let ib_port_rcv_errors = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_port_rcv_errors_delta",
            "IB port receive errors delta per window",
            ib_port_rcv_errors.clone(),
        );

        let ib_port_xmit_discards = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_port_xmit_discards_delta",
            "IB port transmit discards delta per window",
            ib_port_xmit_discards.clone(),
        );

        let ib_port_xmit_wait = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_port_xmit_wait_delta",
            "IB port transmit wait delta per window (congestion indicator)",
            ib_port_xmit_wait.clone(),
        );

        let ib_throughput_rcv_bytes = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_throughput_rcv_bytes",
            "IB receive throughput in bytes per window",
            ib_throughput_rcv_bytes.clone(),
        );

        let ib_throughput_xmit_bytes = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_throughput_xmit_bytes",
            "IB transmit throughput in bytes per window",
            ib_throughput_xmit_bytes.clone(),
        );

        let ib_throughput_rcv_pkts = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_throughput_rcv_pkts",
            "IB receive throughput in packets per window",
            ib_throughput_rcv_pkts.clone(),
        );

        let ib_throughput_xmit_pkts = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_throughput_xmit_pkts",
            "IB transmit throughput in packets per window",
            ib_throughput_xmit_pkts.clone(),
        );

        let ib_rxe_duplicate_request = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_rxe_duplicate_request_delta",
            "RXE duplicate request errors per window",
            ib_rxe_duplicate_request.clone(),
        );

        let ib_rxe_seq_error = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_rxe_seq_error_delta",
            "RXE sequence errors per window (retransmissions from packet loss)",
            ib_rxe_seq_error.clone(),
        );

        let ib_rxe_retry_exceeded = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_rxe_retry_exceeded_delta",
            "RXE retry exceeded errors per window",
            ib_rxe_retry_exceeded.clone(),
        );

        let ib_rxe_send_error = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_rxe_send_error_delta",
            "RXE send errors per window",
            ib_rxe_send_error.clone(),
        );

        // ----------- Mellanox mlx5 extended counters --------------------
        // These are the slow-degradation indicators that NVIDIA, OFED, and
        // El-Sayed & Schroeder (DSN 2013) all flag as the primary signals
        // for marginal-link diagnosis on Mellanox hardware. Each is per-
        // port labelled and exposed as a per-window delta gauge. The
        // absolute (counter-typed) versions are added separately for
        // long-window slope analysis.

        let ib_mlx5_local_ack_timeout_err = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_mlx5_local_ack_timeout_err_delta",
            "Mellanox: RC-connection local ACK timeouts in the labelled port this window. Slow-creep indicator of intermittent peer/path connectivity.",
            ib_mlx5_local_ack_timeout_err.clone(),
        );

        let ib_mlx5_packet_seq_err = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_mlx5_packet_seq_err_delta",
            "Mellanox: PSN sequence errors in the labelled port this window. Primary marginal-network-path indicator per NVIDIA documentation.",
            ib_mlx5_packet_seq_err.clone(),
        );

        let ib_mlx5_implied_nak_seq_err = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_mlx5_implied_nak_seq_err_delta",
            "Mellanox: implied NAKs from PSN sequence errors. Companion to packet_seq_err.",
            ib_mlx5_implied_nak_seq_err.clone(),
        );

        let ib_mlx5_out_of_buffer = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_mlx5_out_of_buffer_delta",
            "Mellanox: receive-buffer exhaustion events in the labelled port this window.",
            ib_mlx5_out_of_buffer.clone(),
        );

        let ib_mlx5_out_of_sequence = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_mlx5_out_of_sequence_delta",
            "Mellanox: out-of-order packet arrivals. Climbs under adaptive-routing / path-flap conditions.",
            ib_mlx5_out_of_sequence.clone(),
        );

        let ib_mlx5_req_cqe_error = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_mlx5_req_cqe_error_delta",
            "Mellanox: completion-queue errors on RDMA REQUEST work-requests. Direct RDMA-stack-level error report.",
            ib_mlx5_req_cqe_error.clone(),
        );

        let ib_mlx5_resp_cqe_error = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_mlx5_resp_cqe_error_delta",
            "Mellanox: completion-queue errors on RDMA RESPONSE work-requests.",
            ib_mlx5_resp_cqe_error.clone(),
        );

        let ib_mlx5_roce_adp_retrans = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_mlx5_roce_adp_retrans_delta",
            "Mellanox: RoCE adaptive retransmissions. Indicates RoCE-layer packet recovery activity from silent wire drops.",
            ib_mlx5_roce_adp_retrans.clone(),
        );

        let ib_mlx5_roce_slow_restart = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_mlx5_roce_slow_restart_delta",
            "Mellanox: RoCE slow-restart activations. Strong fabric/NIC trouble indicator when sustained.",
            ib_mlx5_roce_slow_restart.clone(),
        );

        let ib_mlx5_np_cnp_sent = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_mlx5_np_cnp_sent_delta",
            "Mellanox: Congestion Notification Packets sent from this Notification Point (DCQCN congestion control).",
            ib_mlx5_np_cnp_sent.clone(),
        );

        let ib_mlx5_rp_cnp_handled = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_mlx5_rp_cnp_handled_delta",
            "Mellanox: Congestion Notification Packets handled at this Reaction Point. Climbs when upstream fabric ECN-marks our traffic.",
            ib_mlx5_rp_cnp_handled.clone(),
        );

        let napi_utilization_pct = Gauge::default();
        registry.register(
            "argus_napi_utilization_pct",
            "NAPI budget utilization percentage (0-100 integer)",
            napi_utilization_pct.clone(),
        );

        let health_score_raw = Gauge::default();
        registry.register(
            "argus_health_score_raw_millis",
            "Raw composite health score before smoothing (0-1000 millis)",
            health_score_raw.clone(),
        );

        let health_score_effective = Gauge::default();
        registry.register(
            "argus_health_score_effective_millis",
            "Effective smoothed health score fed to state machine (0-1000 millis)",
            health_score_effective.clone(),
        );

        let health_score_ewma = Gauge::default();
        registry.register(
            "argus_health_score_ewma_millis",
            "EWMA track of smoothed health score (0-1000 millis)",
            health_score_ewma.clone(),
        );

        let health_score_peak_hold = Gauge::default();
        registry.register(
            "argus_health_score_peak_hold_millis",
            "Peak-hold track of smoothed health score (0-1000 millis)",
            health_score_peak_hold.clone(),
        );

        let scheduler_desired_state = Gauge::default();
        registry.register(
            "argus_scheduler_desired_state",
            "Scheduler desired state (0=available, 1=draining, 2=held_by_operator)",
            scheduler_desired_state.clone(),
        );

        let scheduler_observed_state = Gauge::default();
        registry.register(
            "argus_scheduler_observed_state",
            "Scheduler observed state (0=available, 1=draining, 2=drained, 3=down, 4=unknown)",
            scheduler_observed_state.clone(),
        );

        let scheduler_drain_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_scheduler_drain",
            "Total drain operations attempted",
            scheduler_drain_total.clone(),
        );

        let scheduler_resume_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_scheduler_resume",
            "Total resume operations attempted",
            scheduler_resume_total.clone(),
        );

        let scheduler_errors_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_scheduler_errors",
            "Failed scheduler operations by op",
            scheduler_errors_total.clone(),
        );

        let scheduler_last_action_ts = Gauge::default();
        registry.register(
            "argus_scheduler_last_action_timestamp",
            "Unix timestamp of last successful scheduler action",
            scheduler_last_action_ts.clone(),
        );

        let scheduler_drain_duration_secs = Gauge::default();
        registry.register(
            "argus_scheduler_drain_duration_seconds",
            "Seconds since the node was drained (0 when available)",
            scheduler_drain_duration_secs.clone(),
        );

        let scheduler_drain_rejected = Counter::default();
        registry.register(
            "argus_scheduler_drain_rejected_total",
            "Drain operations rejected by rate limiter",
            scheduler_drain_rejected.clone(),
        );

        let capability_coverage = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_capability_coverage",
            "Capability provider quality tier (0=absent, 1=low, 2=medium, 3=high) by capability and active backend",
            capability_coverage.clone(),
        );

        let capability_grade = Gauge::default();
        registry.register(
            "argus_capability_grade",
            "Overall coverage grade (0=F, 1=C, 2=B, 3=A)",
            capability_grade.clone(),
        );

        let sample_contribution_millis = Gauge::default();
        registry.register(
            "argus_sample_contribution_millis",
            "Last fusion contribution from capability samples to raw health score (0-500 millis)",
            sample_contribution_millis.clone(),
        );

        let cq_latency_p50_ns = Gauge::default();
        registry.register(
            "argus_cq_latency_p50_ns",
            "CQ completion latency p50 (DDSketch)",
            cq_latency_p50_ns.clone(),
        );
        let cq_latency_p95_ns = Gauge::default();
        registry.register(
            "argus_cq_latency_p95_ns",
            "CQ completion latency p95 (DDSketch)",
            cq_latency_p95_ns.clone(),
        );
        let cq_latency_p99_ns = Gauge::default();
        registry.register(
            "argus_cq_latency_p99_ns",
            "CQ completion latency p99 (DDSketch)",
            cq_latency_p99_ns.clone(),
        );
        let cq_latency_p999_ns = Gauge::default();
        registry.register(
            "argus_cq_latency_p999_ns",
            "CQ completion latency p99.9 (DDSketch)",
            cq_latency_p999_ns.clone(),
        );

        let timescale_state = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_timescale_state",
            "Per-timescale health state (0=healthy, 1=degraded, 2=critical, 3=recovering)",
            timescale_state.clone(),
        );

        let timescale_score_millis = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_timescale_score_millis",
            "Per-timescale effective health score (0-1000 millis)",
            timescale_score_millis.clone(),
        );

        let burst_classification = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_burst_classification",
            "Burst classifier output (1 if active for the labeled class, 0 otherwise)",
            burst_classification.clone(),
        );

        let ebpf_lru_evictions = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_ebpf_lru_evictions",
            "eBPF LRU map miss count (correlations lost due to map pressure)",
            ebpf_lru_evictions.clone(),
        );

        let ib_port_idle_seconds = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_port_idle_seconds",
            "Seconds since the labelled IB port last observed any throughput. Hardware error monitoring continues regardless of idle state — passive monitoring of an idle link is still real monitoring.",
            ib_port_idle_seconds.clone(),
        );

        let ib_fabric_idle = Gauge::default();
        registry.register(
            "argus_ib_fabric_idle",
            "1 when every discovered IB port has been idle for at least one window; 0 when any port has traffic. Always 0 if no ports are discovered.",
            ib_fabric_idle.clone(),
        );

        let ib_max_idle_seconds = Gauge::default();
        registry.register(
            "argus_ib_max_idle_seconds",
            "Largest idle-seconds value across all discovered IB ports.",
            ib_max_idle_seconds.clone(),
        );

        let hw_counter_polls_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_hw_counter_polls_total",
            "Number of times the sysfs hardware-counter reader has been invoked for the labelled IB port since argusd started. Increases by 1 per window. If this stays flat, monitoring is NOT polling — the per-port counter deltas reading 0 are just an artifact of an idle link, not an indication of broken sensing.",
            hw_counter_polls_total.clone(),
        );

        let hw_counter_last_read_secs = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_hw_counter_last_read_unix_seconds",
            "Unix timestamp (seconds) of the most recent successful sysfs read for the labelled IB port. (now() - this value) tells you how stale the counter data is.",
            hw_counter_last_read_secs.clone(),
        );

        let ib_counter_total = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_counter_total",
            "Absolute (cumulative since boot) value of an IB hardware counter, as last read from /sys/class/infiniband/<device>/ports/<port>/{counters,hw_counters}/. Labels: device, port, counter. Use rate() over this for long-window slow-degradation detection: rate(argus_ib_counter_total{counter=\"symbol_error_count\"}[24h]) > threshold catches the 24-72h creep documented in El-Sayed & Schroeder DSN 2013 and the NVIDIA UFM Health Score guidance.",
            ib_counter_total.clone(),
        );

        let nic_pcie_current_width = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_nic_pcie_current_link_width",
            "Current negotiated PCIe lane count for the IB NIC. Compare against argus_nic_pcie_max_link_width. A drop from 16 to 8 is a hardware degradation invisible to IB error counters.",
            nic_pcie_current_width.clone(),
        );

        let nic_pcie_max_width = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_nic_pcie_max_link_width",
            "Maximum supported PCIe lane count for the IB NIC. Stable per hardware; ratio of current to max indicates lane degradation.",
            nic_pcie_max_width.clone(),
        );

        let nic_pcie_degraded = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_nic_pcie_degraded",
            "1 when the IB NIC's PCIe link is below its negotiated max (lane count OR generation); 0 when at max. Triggers operator attention to motherboard slot, contacts, or thermal throttling.",
            nic_pcie_degraded.clone(),
        );

        let nic_temperature_celsius = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_nic_temperature_celsius",
            "IB NIC temperature in degrees Celsius, read via the kernel hwmon framework. Sustained values above 75-85°C predict hardware failure hours-to-days in advance per NVIDIA/Mellanox field-failure data.",
            nic_temperature_celsius.clone(),
        );

        let ebpf_cq_kprobes_attached = Gauge::default();
        registry.register(
            "argus_ebpf_cq_kprobes_attached",
            "1 when the eBPF CQ-jitter kprobes (post_send + poll_cq) attached successfully at startup; 0 when one or both failed. Zero means cq_jitter metrics will remain zero regardless of RDMA activity — the data path is dead. Investigate with: grep -E 'mlx5_ib_post_send|mlx5_ib_poll_cq|rxe_post_send|rxe_poll_cq' /proc/kallsyms",
            ebpf_cq_kprobes_attached.clone(),
        );

        let ebpf_slab_latency_attached = Gauge::default();
        registry.register(
            "argus_ebpf_slab_latency_attached",
            "1 when the eBPF slab-allocation latency kprobe pair attached successfully at startup; 0 when one or both failed. Zero means slab latency metrics will remain zero — only allocation counts (from tracepoints) will be valid.",
            ebpf_slab_latency_attached.clone(),
        );

        let metrics = ArgusPrometheusMetrics {
            health_state,
            health_score,
            event_count,
            alert_count,
            state_transitions,
            irq_total,
            irq_skew_pct,
            irq_dominant_cpu,
            irq_total_rate,
            slab_alloc_count,
            slab_avg_latency_ns,
            slab_max_latency_ns,
            cq_completion_count,
            cq_avg_latency_ns,
            cq_max_latency_ns,
            cq_stall_count,
            cq_p99_latency_ns,
            ib_error_delta_total,
            ib_symbol_errors,
            ib_link_downed,
            ib_link_error_recovery,
            ib_port_rcv_errors,
            ib_port_xmit_discards,
            ib_port_xmit_wait,
            ib_throughput_rcv_bytes,
            ib_throughput_xmit_bytes,
            ib_throughput_rcv_pkts,
            ib_throughput_xmit_pkts,
            ib_rxe_duplicate_request,
            ib_rxe_seq_error,
            ib_rxe_retry_exceeded,
            ib_rxe_send_error,
            ib_mlx5_local_ack_timeout_err,
            ib_mlx5_packet_seq_err,
            ib_mlx5_implied_nak_seq_err,
            ib_mlx5_out_of_buffer,
            ib_mlx5_out_of_sequence,
            ib_mlx5_req_cqe_error,
            ib_mlx5_resp_cqe_error,
            ib_mlx5_roce_adp_retrans,
            ib_mlx5_roce_slow_restart,
            ib_mlx5_np_cnp_sent,
            ib_mlx5_rp_cnp_handled,
            napi_utilization_pct,
            health_score_raw,
            health_score_effective,
            health_score_ewma,
            health_score_peak_hold,
            scheduler_desired_state,
            scheduler_observed_state,
            scheduler_drain_total,
            scheduler_resume_total,
            scheduler_errors_total,
            scheduler_last_action_ts,
            scheduler_drain_duration_secs,
            scheduler_drain_rejected,
            capability_coverage,
            capability_grade,
            sample_contribution_millis,
            cq_latency_p50_ns,
            cq_latency_p95_ns,
            cq_latency_p99_ns,
            cq_latency_p999_ns,
            timescale_state,
            timescale_score_millis,
            burst_classification,
            ebpf_lru_evictions,
            ib_port_idle_seconds,
            ib_fabric_idle,
            ib_max_idle_seconds,
            hw_counter_polls_total,
            hw_counter_last_read_secs,
            ib_counter_total,
            nic_pcie_current_width,
            nic_pcie_max_width,
            nic_pcie_degraded,
            nic_temperature_celsius,
            ebpf_cq_kprobes_attached,
            ebpf_slab_latency_attached,
        };

        Self {
            registry,
            metrics,
            prev_health: HealthState::Healthy,
        }
    }

    /// Record eBPF LRU map miss deltas.
    pub fn update_lru_evictions(&self, cq_misses: u64, slab_misses: u64) {
        if cq_misses > 0 {
            self.metrics
                .ebpf_lru_evictions
                .get_or_create(&vec![("map".to_string(), "cq".to_string())])
                .inc_by(cq_misses);
        }
        if slab_misses > 0 {
            self.metrics
                .ebpf_lru_evictions
                .get_or_create(&vec![("map".to_string(), "slab".to_string())])
                .inc_by(slab_misses);
        }
    }

    /// Update all gauges and counters from aggregated metrics.
    pub fn update(&mut self, metrics: &AggregatedMetrics, health: HealthState, event_count: u64) {
        let state_val: i64 = match health {
            HealthState::Healthy => 0,
            HealthState::Degraded => 1,
            HealthState::Critical => 2,
            HealthState::Recovering => 3,
        };
        self.metrics.health_state.set(state_val);
        self.metrics
            .health_score
            .set((metrics.composite_health_score * 1000.0) as i64);

        // State transitions
        if health != self.prev_health {
            self.metrics
                .state_transitions
                .get_or_create(&vec![
                    ("from".to_string(), self.prev_health.to_string()),
                    ("to".to_string(), health.to_string()),
                ])
                .inc();
            self.prev_health = health;
        }

        // Events (cumulative total — set, don't increment)
        self.metrics.event_count.set(event_count as i64);

        // Slab
        if metrics.slab_metrics.alloc_count > 0 {
            self.metrics
                .slab_alloc_count
                .inc_by(metrics.slab_metrics.alloc_count);
        }
        self.metrics
            .slab_avg_latency_ns
            .set(metrics.slab_metrics.avg_latency_ns() as i64);
        self.metrics
            .slab_max_latency_ns
            .set(metrics.slab_metrics.max_latency_ns as i64);

        // CQ jitter (from cq_jitter, not rdma_metrics)
        if metrics.cq_jitter.completion_count > 0 {
            self.metrics
                .cq_completion_count
                .inc_by(metrics.cq_jitter.completion_count);
        }
        self.metrics
            .cq_avg_latency_ns
            .set(metrics.cq_jitter.avg_latency_ns() as i64);
        self.metrics
            .cq_max_latency_ns
            .set(metrics.cq_jitter.max_latency_ns as i64);
        if metrics.cq_jitter.stall_count > 0 {
            self.metrics
                .cq_stall_count
                .inc_by(metrics.cq_jitter.stall_count);
        }
        self.metrics
            .cq_p99_latency_ns
            .set(metrics.cq_jitter.estimated_p99_ns() as i64);

        // IRQ per-CPU (detail) + aggregate skew metrics
        let dist = &metrics.interrupt_distribution;
        for (i, &count) in dist.per_cpu_counts.iter().enumerate() {
            let counter = self
                .metrics
                .irq_total
                .get_or_create(&vec![("cpu".to_string(), i.to_string())]);
            if count > 0 {
                counter.inc_by(count);
            }
        }
        let n = dist.per_cpu_counts.len() as f64;
        let imbalance = if n > 1.0 {
            let ideal_pct = 100.0 / n;
            let max_pct = dist.dominant_cpu_pct();
            ((max_pct - ideal_pct) / (100.0 - ideal_pct) * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };
        self.metrics.irq_skew_pct.set(imbalance as i64);
        let dominant_cpu = dist
            .per_cpu_counts
            .iter()
            .enumerate()
            .max_by_key(|(_, &c)| c)
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.metrics.irq_dominant_cpu.set(dominant_cpu as i64);
        self.metrics
            .irq_total_rate
            .set(dist.total_count as i64);

        // NAPI utilization
        let napi_util = if metrics.network_metrics.napi_total_budget > 0 {
            metrics.network_metrics.napi_total_work as f64
                / metrics.network_metrics.napi_total_budget as f64
                * 100.0
        } else {
            0.0
        };
        self.metrics.napi_utilization_pct.set(napi_util as i64);

        // IB fabric idle visibility — operators distinguish "no traffic but
        // we're still watching the link" from "monitoring is offline."
        // Hardware error counters always fire regardless of this state.
        for port in &metrics.ib_port_idle {
            self.metrics
                .ib_port_idle_seconds
                .get_or_create(&vec![
                    ("device".to_string(), port.device.clone()),
                    ("port".to_string(), port.port.to_string()),
                ])
                .set(port.idle_seconds as i64);
        }
        self.metrics
            .ib_fabric_idle
            .set(if metrics.ib_fabric_idle() { 1 } else { 0 });
        self.metrics
            .ib_max_idle_seconds
            .set(metrics.ib_max_idle_seconds() as i64);

        // IB counters (aggregate — includes both hard and soft/rxe errors)
        self.metrics
            .ib_error_delta_total
            .set(metrics.ib_counter_deltas.total_all_errors_delta() as i64);
    }

    /// Update per-device/port IB counter gauges.
    /// Call once per device per window with the device name, port, and device type.
    /// Soft-RoCE (rxe) metrics are only emitted when `device_type` is `SoftRoCE`.
    /// Increment the poll-heartbeat for a labelled port and stamp the
    /// "last read" timestamp. The point of this is operator confidence:
    /// when every error-delta gauge reads 0 (which is the correct state
    /// on a healthy idle link), the operator can still see this counter
    /// climbing window-by-window and confirm the sysfs reader is alive.
    /// If this stays flat across multiple scrapes, polling is broken.
    pub fn record_hw_counter_poll(&self, device: &str, port: &str) {
        let labels = vec![
            ("device".to_string(), device.to_string()),
            ("port".to_string(), port.to_string()),
        ];
        self.metrics.hw_counter_polls_total.get_or_create(&labels).inc();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.metrics
            .hw_counter_last_read_secs
            .get_or_create(&labels)
            .set(now_secs);
    }

    /// Record the eBPF kprobe attachment outcomes once at startup.
    /// Operators monitoring whether the slow-path eBPF features actually
    /// went live can alert on these gauges (= 0 means data path dead).
    pub fn set_ebpf_attachment_status(&self, cq_attached: bool, slab_latency_attached: bool) {
        self.metrics
            .ebpf_cq_kprobes_attached
            .set(i64::from(cq_attached));
        self.metrics
            .ebpf_slab_latency_attached
            .set(i64::from(slab_latency_attached));
    }

    /// Publish PCIe link state for every discovered IB NIC. Updates
    /// per-device gauges for current/max widths and a 0/1 degraded
    /// flag. The IB protocol doesn't reveal PCIe-level degradation —
    /// this is the only signal that catches it.
    pub fn update_nic_pcie(
        &self,
        readings: &[crate::sources::nic_health::PcieLinkState],
    ) {
        for r in readings {
            let labels = vec![
                ("device".to_string(), r.ib_device.clone()),
                ("max_speed".to_string(), r.max_speed.clone()),
            ];
            self.metrics.nic_pcie_current_width
                .get_or_create(&labels).set(i64::from(r.current_width));
            self.metrics.nic_pcie_max_width
                .get_or_create(&labels).set(i64::from(r.max_width));
            self.metrics.nic_pcie_degraded
                .get_or_create(&labels)
                .set(if r.is_degraded() { 1 } else { 0 });
        }
    }

    /// Publish NIC temperature for every device that has an hwmon
    /// thermal sensor available.
    pub fn update_nic_thermal(
        &self,
        readings: &[crate::sources::nic_health::NicThermal],
    ) {
        for r in readings {
            let labels = vec![("device".to_string(), r.ib_device.clone())];
            // Prometheus gauges are i64 internally; we report whole-degree
            // resolution which is far below the noise floor on NIC
            // thermals (typically ±2°C measurement variance).
            self.metrics.nic_temperature_celsius
                .get_or_create(&labels)
                .set(r.current_celsius.round() as i64);
        }
    }

    /// Publish absolute (cumulative-since-boot) IB counter values from
    /// the supplied snapshot, as the `argus_ib_counter_total` family.
    /// Call this once per window after `HwCounterReader::read_all()`.
    ///
    /// External Prometheus alerts can then compute long-window slopes,
    /// e.g.:
    ///     rate(argus_ib_counter_total{counter="symbol_error_count"}[6h])
    /// which catches the slow-creep degradation pattern that's
    /// invisible to single-window delta gauges.
    pub fn update_absolute_counters(
        &self,
        counters: &[crate::sources::hwcounters::AbsoluteCounter],
    ) {
        for c in counters {
            let labels = vec![
                ("device".to_string(), c.device.clone()),
                ("port".to_string(), c.port.to_string()),
                ("counter".to_string(), c.counter_name.clone()),
            ];
            // Note: this is a Gauge, not a Counter. We set the value
            // explicitly to the absolute we read from sysfs. rate()
            // over a Gauge that grows monotonically works identically
            // to rate() over a Counter for non-resetting values; the
            // only loss is Prometheus's auto-reset detection, which
            // doesn't apply because kernel counters never reset
            // mid-uptime anyway.
            self.metrics.ib_counter_total.get_or_create(&labels).set(c.value as i64);
        }
    }

    pub fn update_ib_counters(
        &self,
        device: &str,
        port: &str,
        deltas: &argus_common::IbCounterDeltas,
        device_type: crate::sources::hwcounters::DeviceType,
    ) {
        let labels = vec![
            ("device".to_string(), device.to_string()),
            ("port".to_string(), port.to_string()),
        ];

        self.metrics
            .ib_symbol_errors
            .get_or_create(&labels)
            .set(deltas.symbol_error_delta as i64);
        self.metrics
            .ib_link_downed
            .get_or_create(&labels)
            .set(deltas.link_downed_delta as i64);
        self.metrics
            .ib_link_error_recovery
            .get_or_create(&labels)
            .set(deltas.link_error_recovery_delta as i64);
        self.metrics
            .ib_port_rcv_errors
            .get_or_create(&labels)
            .set(deltas.port_rcv_errors_delta as i64);
        self.metrics
            .ib_port_xmit_discards
            .get_or_create(&labels)
            .set(deltas.port_xmit_discards_delta as i64);
        self.metrics
            .ib_port_xmit_wait
            .get_or_create(&labels)
            .set(deltas.port_xmit_wait_delta as i64);
        self.metrics
            .ib_throughput_rcv_bytes
            .get_or_create(&labels)
            .set((deltas.port_rcv_data_delta * 4) as i64);
        self.metrics
            .ib_throughput_xmit_bytes
            .get_or_create(&labels)
            .set((deltas.port_xmit_data_delta * 4) as i64);
        self.metrics
            .ib_throughput_rcv_pkts
            .get_or_create(&labels)
            .set(deltas.hw_rcv_pkts_delta as i64);
        self.metrics
            .ib_throughput_xmit_pkts
            .get_or_create(&labels)
            .set(deltas.hw_xmit_pkts_delta as i64);

        if device_type == crate::sources::hwcounters::DeviceType::SoftRoCE {
            self.metrics
                .ib_rxe_duplicate_request
                .get_or_create(&labels)
                .set(deltas.rxe_duplicate_request_delta as i64);
            self.metrics
                .ib_rxe_seq_error
                .get_or_create(&labels)
                .set(deltas.rxe_seq_error_delta as i64);
            self.metrics
                .ib_rxe_retry_exceeded
                .get_or_create(&labels)
                .set(deltas.rxe_retry_exceeded_delta as i64);
            self.metrics
                .ib_rxe_send_error
                .get_or_create(&labels)
                .set(deltas.rxe_send_error_delta as i64);
        }

        // Mellanox mlx5 extended counters — emitted for HardwareIB devices.
        // On non-mlx5 hardware these deltas are zero (the counter files
        // don't exist, sysfs reads return None silently, aggregator never
        // increments). Publishing them unconditionally for HardwareIB
        // makes the dashboard semantics consistent: "the counter is 0"
        // means "no errors this window," not "this counter is unsupported."
        if device_type == crate::sources::hwcounters::DeviceType::HardwareIB {
            self.metrics.ib_mlx5_local_ack_timeout_err
                .get_or_create(&labels).set(deltas.mlx5_local_ack_timeout_err_delta as i64);
            self.metrics.ib_mlx5_packet_seq_err
                .get_or_create(&labels).set(deltas.mlx5_packet_seq_err_delta as i64);
            self.metrics.ib_mlx5_implied_nak_seq_err
                .get_or_create(&labels).set(deltas.mlx5_implied_nak_seq_err_delta as i64);
            self.metrics.ib_mlx5_out_of_buffer
                .get_or_create(&labels).set(deltas.mlx5_out_of_buffer_delta as i64);
            self.metrics.ib_mlx5_out_of_sequence
                .get_or_create(&labels).set(deltas.mlx5_out_of_sequence_delta as i64);
            self.metrics.ib_mlx5_req_cqe_error
                .get_or_create(&labels).set(deltas.mlx5_req_cqe_error_delta as i64);
            self.metrics.ib_mlx5_resp_cqe_error
                .get_or_create(&labels).set(deltas.mlx5_resp_cqe_error_delta as i64);
            self.metrics.ib_mlx5_roce_adp_retrans
                .get_or_create(&labels).set(deltas.mlx5_roce_adp_retrans_delta as i64);
            self.metrics.ib_mlx5_roce_slow_restart
                .get_or_create(&labels).set(deltas.mlx5_roce_slow_restart_delta as i64);
            self.metrics.ib_mlx5_np_cnp_sent
                .get_or_create(&labels).set(deltas.mlx5_np_cnp_sent_delta as i64);
            self.metrics.ib_mlx5_rp_cnp_handled
                .get_or_create(&labels).set(deltas.mlx5_rp_cnp_handled_delta as i64);
        }
    }

    /// Update scheduler metrics from reconciler events.
    pub fn update_scheduler(
        &self,
        desired: &crate::scheduler::DesiredNodeState,
        observed: &crate::scheduler::ObservedNodeState,
        events: &[crate::scheduler::SchedulerActionEvent],
        drain_duration_secs: f64,
        dry_run: bool,
        drain_rejections: u64,
    ) {
        use crate::scheduler::{DesiredNodeState, ObservedNodeState, SchedulerEventKind};

        let desired_val: i64 = match desired {
            DesiredNodeState::Available => 0,
            DesiredNodeState::Draining => 1,
            DesiredNodeState::HeldByOperator => 2,
        };
        self.metrics.scheduler_desired_state.set(desired_val);

        let observed_val: i64 = match observed {
            ObservedNodeState::Available => 0,
            ObservedNodeState::Draining => 1,
            ObservedNodeState::Drained => 2,
            ObservedNodeState::Down => 3,
            ObservedNodeState::Unknown => 4,
        };
        self.metrics.scheduler_observed_state.set(observed_val);

        self.metrics
            .scheduler_drain_duration_secs
            .set(drain_duration_secs as i64);

        let current_rejections = self.metrics.scheduler_drain_rejected.get();
        if drain_rejections > current_rejections {
            self.metrics
                .scheduler_drain_rejected
                .inc_by(drain_rejections - current_rejections);
        }

        let mode = if dry_run { "dry_run" } else { "live" };

        for event in events {
            match event.kind {
                SchedulerEventKind::Drained => {
                    self.metrics
                        .scheduler_drain_total
                        .get_or_create(&vec![("mode".to_string(), mode.to_string())])
                        .inc();
                    self.metrics.scheduler_last_action_ts.set(epoch_secs());
                }
                SchedulerEventKind::Resumed => {
                    self.metrics
                        .scheduler_resume_total
                        .get_or_create(&vec![("mode".to_string(), mode.to_string())])
                        .inc();
                    self.metrics.scheduler_last_action_ts.set(epoch_secs());
                }
                SchedulerEventKind::Error => {
                    self.metrics
                        .scheduler_errors_total
                        .get_or_create(&vec![("op".to_string(), "scheduler".to_string())])
                        .inc();
                }
                _ => {}
            }
        }
    }

    /// Update the capability-coverage gauge family. Call this once at
    /// startup (post-detection) and any time the registry is rebuilt.
    pub fn update_capability_coverage(&self, report: &argus_common::CoverageReport) {
        for cap in &report.capabilities {
            let backend = cap
                .active_backend
                .map(|b| b.name().to_string())
                .unwrap_or_else(|| "none".to_string());
            let labels = vec![
                ("capability".to_string(), cap.capability.name().to_string()),
                ("backend".to_string(), backend),
            ];
            self.metrics
                .capability_coverage
                .get_or_create(&labels)
                .set(cap.quality.as_i64());
        }
        let grade_val: i64 = match report.grade {
            argus_common::CoverageGrade::A => 3,
            argus_common::CoverageGrade::B => 2,
            argus_common::CoverageGrade::C => 1,
            argus_common::CoverageGrade::F => 0,
        };
        self.metrics.capability_grade.set(grade_val);
    }

    /// Record the most recent fusion contribution (in milliunits, 0-500).
    pub fn update_sample_contribution(&self, contribution: f64) {
        self.metrics
            .sample_contribution_millis
            .set((contribution * 1000.0) as i64);
    }

    /// Update per-timescale state and score gauges from the multi-timescale
    /// evaluator. Called once per window.
    pub fn update_timescales(&self, evaluator: &crate::detection::timescale::MultiTimescaleEvaluator) {
        for (ts, state) in evaluator.states() {
            let val: i64 = match state {
                argus_common::HealthState::Healthy => 0,
                argus_common::HealthState::Degraded => 1,
                argus_common::HealthState::Critical => 2,
                argus_common::HealthState::Recovering => 3,
            };
            self.metrics
                .timescale_state
                .get_or_create(&vec![("timescale".to_string(), ts.name().to_string())])
                .set(val);
        }
        for (ts, score) in evaluator.effective_scores() {
            self.metrics
                .timescale_score_millis
                .get_or_create(&vec![("timescale".to_string(), ts.name().to_string())])
                .set((score * 1000.0) as i64);
        }
    }

    /// Update burst classification gauges. The classifier supplies a
    /// pre-computed map of class → 0/1.
    pub fn update_burst_classification(&self, classes: &[(&str, bool)]) {
        for (class, active) in classes {
            self.metrics
                .burst_classification
                .get_or_create(&vec![("class".to_string(), (*class).to_string())])
                .set(if *active { 1 } else { 0 });
        }
    }

    /// Update the CQ latency percentile gauges from a `CompletionLatency`
    /// sample stream (filtered to the selected backend by the caller).
    /// Samples whose `device` label is one of "p50", "p95", "p99", "p999"
    /// drive the matching gauge; others are ignored.
    pub fn update_cq_latency_quantiles(&self, samples: &[argus_common::Sample]) {
        for s in samples {
            if s.capability != argus_common::Capability::CompletionLatency {
                continue;
            }
            let label = match s.device.as_deref() {
                Some(l) => l,
                None => continue,
            };
            let value = s.value as i64;
            match label {
                "p50" => self.metrics.cq_latency_p50_ns.set(value),
                "p95" => self.metrics.cq_latency_p95_ns.set(value),
                "p99" => self.metrics.cq_latency_p99_ns.set(value),
                "p999" => self.metrics.cq_latency_p999_ns.set(value),
                _ => 0,
            };
        }
    }

    /// Update smoothed health score component gauges.
    pub fn update_score_components(&self, score: &crate::detection::SmoothedHealthScore) {
        self.metrics
            .health_score_raw
            .set((score.raw() * 1000.0) as i64);
        self.metrics
            .health_score_effective
            .set((score.effective() * 1000.0) as i64);
        self.metrics
            .health_score_ewma
            .set((score.ewma() * 1000.0) as i64);
        self.metrics
            .health_score_peak_hold
            .set((score.peak_hold() * 1000.0) as i64);
    }

    /// Record an alert in Prometheus counters.
    pub fn record_alert(&self, kind: &str, severity: &str) {
        self.metrics
            .alert_count
            .get_or_create(&vec![
                ("kind".to_string(), kind.to_string()),
                ("severity".to_string(), severity.to_string()),
            ])
            .inc();
    }

    /// Encode all metrics as Prometheus text format.
    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut buf = String::new();
        encode(&mut buf, &self.registry)?;
        Ok(buf)
    }
}

impl Default for PrometheusExporter {
    fn default() -> Self {
        Self::new()
    }
}

fn epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Shared state for the metrics HTTP server.
pub type SharedExporter = Arc<Mutex<PrometheusExporter>>;

/// Shared health state for the /health endpoint.
pub type SharedHealthState = Arc<Mutex<HealthSnapshot>>;

/// Shared full status for the /status endpoint (TUI attach mode).
pub type SharedStatusState = Arc<Mutex<StatusSnapshot>>;

/// Shared reconciler handle for /scheduler/hold and /scheduler/release.
pub type SharedReconciler = Arc<Mutex<crate::scheduler::Reconciler>>;

/// Shared capability coverage snapshot for the `/coverage` endpoint.
pub type SharedCoverage = Arc<Mutex<argus_common::CoverageReport>>;

#[derive(Clone)]
pub struct HealthSnapshot {
    pub state: HealthState,
    pub uptime_secs: f64,
    pub events_processed: u64,
    pub last_window_ts: u64,
}

impl Default for HealthSnapshot {
    fn default() -> Self {
        Self {
            state: HealthState::Healthy,
            uptime_secs: 0.0,
            events_processed: 0,
            last_window_ts: 0,
        }
    }
}

/// Full agent status snapshot — serves the /status endpoint for TUI attach mode.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusSnapshot {
    pub state: HealthState,
    pub health_score: f64,
    pub uptime_secs: f64,
    pub events_processed: u64,
    pub metrics: argus_common::AggregatedMetrics,
    pub recent_alerts: Vec<argus_common::Alert>,
    pub source_name: String,
}

impl Default for StatusSnapshot {
    fn default() -> Self {
        Self {
            state: HealthState::Healthy,
            health_score: 0.0,
            uptime_secs: 0.0,
            events_processed: 0,
            metrics: argus_common::AggregatedMetrics::default(),
            recent_alerts: Vec::new(),
            source_name: String::new(),
        }
    }
}

/// TLS configuration for the metrics endpoint.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
}

/// Start an HTTP(S) server on `addr` that serves `/metrics`, `/health`, and `/status`.
///
/// When `tls` is `Some`, the server uses TLS (HTTPS). When `auth_token` is
/// `Some`, every request must include a matching `Authorization: Bearer <token>`
/// header or receive a 401.
/// Maximum concurrent connections to the metrics server.
const MAX_METRICS_CONNECTIONS: usize = 128;

/// Per-connection idle timeout.
const CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub async fn serve_metrics(
    exporter: SharedExporter,
    health: SharedHealthState,
    status: SharedStatusState,
    reconciler: Option<SharedReconciler>,
    coverage: Option<SharedCoverage>,
    addr: std::net::SocketAddr,
    tls: Option<TlsConfig>,
    auth_token: Option<String>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let tls_acceptor: Option<Arc<std::sync::RwLock<tokio_rustls::TlsAcceptor>>> =
        if let Some(ref tls_cfg) = tls {
            Some(Arc::new(std::sync::RwLock::new(build_tls_acceptor(tls_cfg)?)))
        } else {
            None
        };

    // SIGHUP handler for TLS certificate reload
    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .ok();
    #[cfg(not(unix))]
    let mut sighup: Option<futures_core::Never> = None;

    let listener = TcpListener::bind(addr).await?;
    let scheme = if tls.is_some() { "https" } else { "http" };
    tracing::info!(%addr, %scheme, component = "metrics", "metrics/health server listening");

    let auth_token: Option<Arc<str>> = auth_token.map(|t| Arc::from(t.as_str()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_METRICS_CONNECTIONS));

    loop {
        // Build a future that resolves on SIGHUP (or never if unavailable).
        let sighup_fut = async {
            #[cfg(unix)]
            if let Some(ref mut sig) = sighup {
                sig.recv().await;
                return;
            }
            std::future::pending::<()>().await;
            #[cfg(not(unix))]
            { std::future::pending::<()>().await; }
        };

        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                let exporter = exporter.clone();
                let health = health.clone();
                let status = status.clone();
                let reconciler = reconciler.clone();
                let coverage = coverage.clone();
                let auth = auth_token.clone();
                let sem = semaphore.clone();

                let permit = match sem.try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!(component = "metrics", "connection rejected: max connections reached");
                        drop(stream);
                        continue;
                    }
                };

                if let Some(ref tls_lock) = tls_acceptor {
                    let acceptor = tls_lock.read()
                        .map(|g| g.clone())
                        .unwrap_or_else(|p| p.into_inner().clone());
                    tokio::spawn(async move {
                        let _permit = permit;
                        let tls_stream = match tokio::time::timeout(
                            CONNECTION_TIMEOUT,
                            acceptor.accept(stream),
                        ).await {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                tracing::debug!(component = "metrics", "TLS handshake failed: {e}");
                                return;
                            }
                            Err(_) => {
                                tracing::debug!(component = "metrics", "TLS handshake timed out");
                                return;
                            }
                        };
                        let io = TokioIo::new(tls_stream);
                        let _ = tokio::time::timeout(
                            CONNECTION_TIMEOUT,
                            serve_connection(io, exporter, health, status, reconciler, coverage, auth),
                        ).await;
                    });
                } else {
                    let io = TokioIo::new(stream);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = tokio::time::timeout(
                            CONNECTION_TIMEOUT,
                            serve_connection(io, exporter, health, status, reconciler, coverage, auth),
                        ).await;
                    });
                }
            }
            _ = sighup_fut => {
                if let Some(ref tls_cfg) = tls {
                    match build_tls_acceptor(tls_cfg) {
                        Ok(new_acceptor) => {
                            if let Some(ref lock) = tls_acceptor {
                                if let Ok(mut guard) = lock.write() {
                                    *guard = new_acceptor;
                                }
                            }
                            tracing::info!(
                                component = "metrics",
                                "TLS certificates reloaded via SIGHUP"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                component = "metrics",
                                error = %e,
                                "TLS certificate reload failed — keeping existing certificates"
                            );
                        }
                    }
                } else {
                    tracing::debug!(component = "metrics", "SIGHUP received but TLS not configured");
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::info!(component = "metrics", "metrics server shutting down");
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn serve_connection<I>(
    io: I,
    exporter: SharedExporter,
    health: SharedHealthState,
    status: SharedStatusState,
    reconciler: Option<SharedReconciler>,
    coverage: Option<SharedCoverage>,
    auth_token: Option<Arc<str>>,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};

    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let exporter = exporter.clone();
        let health = health.clone();
        let status = status.clone();
        let reconciler = reconciler.clone();
        let coverage = coverage.clone();
        let auth = auth_token.clone();
        async move {
            if let Some(ref expected) = auth {
                let authorized = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .map_or(false, |t| constant_time_eq(t.as_bytes(), expected.as_bytes()));
                if !authorized {
                    return Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .body(Full::new(Bytes::from("unauthorized\n")))
                            .unwrap_or_else(|_| {
                                Response::new(Full::new(Bytes::from("unauthorized\n")))
                            }),
                    );
                }
            }

            match req.uri().path() {
                "/metrics" => {
                    let body = match exporter.lock() {
                        Ok(exp) => exp.encode().unwrap_or_default(),
                        Err(_) => String::from("# error: lock poisoned\n"),
                    };
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/plain; version=0.0.4")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap_or_else(|_| {
                                Response::new(Full::new(Bytes::from("internal error")))
                            }),
                    )
                }
                "/health" => {
                    match health.lock() {
                        Ok(snap) => {
                            let body = format!(
                                r#"{{"state":"{}","uptime_secs":{:.1},"events_processed":{},"last_window_ts":{}}}"#,
                                snap.state,
                                snap.uptime_secs,
                                snap.events_processed,
                                snap.last_window_ts,
                            );
                            Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                        }
                        Err(_) => {
                            Ok(Response::builder()
                                .status(StatusCode::SERVICE_UNAVAILABLE)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(r#"{"error":"health lock poisoned"}"#)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                        }
                    }
                }
                "/status" => {
                    match status.lock() {
                        Ok(snap) => {
                            let body = serde_json::to_string(&*snap).unwrap_or_else(|_| "{}".into());
                            Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                        }
                        Err(_) => {
                            Ok(Response::builder()
                                .status(StatusCode::SERVICE_UNAVAILABLE)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(r#"{"error":"status lock poisoned"}"#)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                        }
                    }
                }
                "/coverage" => {
                    if let Some(ref cov) = coverage {
                        let snap = cov.lock().map(|c| c.clone()).ok();
                        let body = match snap {
                            Some(report) => {
                                serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
                            }
                            None => r#"{"error":"coverage lock poisoned"}"#.to_string(),
                        };
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                    } else {
                        Ok(Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Full::new(Bytes::from(
                                r#"{"error":"coverage not configured"}"#,
                            )))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                    }
                }
                "/scheduler/hold" => {
                    if let Some(ref rc) = reconciler {
                        if let Ok(mut r) = rc.lock() {
                            let event = r.set_operator_hold();
                            let body = format!(r#"{{"status":"ok","message":"{}"}}"#, event.message);
                            Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                        } else {
                            Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Full::new(Bytes::from(r#"{"error":"lock poisoned"}"#)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                        }
                    } else {
                        Ok(Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Full::new(Bytes::from(
                                r#"{"error":"scheduler not configured"}"#,
                            )))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                    }
                }
                "/scheduler/release" => {
                    if let Some(ref rc) = reconciler {
                        if let Ok(mut r) = rc.lock() {
                            let event = r.release_operator_hold();
                            let body = format!(r#"{{"status":"ok","message":"{}"}}"#, event.message);
                            Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                        } else {
                            Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Full::new(Bytes::from(r#"{"error":"lock poisoned"}"#)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                        }
                    } else {
                        Ok(Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Full::new(Bytes::from(
                                r#"{"error":"scheduler not configured"}"#,
                            )))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                    }
                }
                _ => Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from("not found")))
                    .unwrap_or_else(|_| {
                        Response::new(Full::new(Bytes::from("not found")))
                    })),
            }
        }
    });

    if let Err(e) =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(io, service)
            .await
    {
        tracing::warn!("metrics server connection error: {e}");
    }
}

fn build_tls_acceptor(cfg: &TlsConfig) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::ServerConfig;

    let cert_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(&cfg.cert_path)
            .map_err(|e| {
                anyhow::anyhow!("failed to open TLS cert {}: {e}", cfg.cert_path.display())
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("failed to parse TLS cert chain: {e}"))?;

    let key = PrivateKeyDer::from_pem_file(&cfg.key_path)
        .map_err(|e| anyhow::anyhow!("failed to parse TLS key {}: {e}", cfg.key_path.display()))?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| anyhow::anyhow!("TLS server config error: {e}"))?;

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
        server_config,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::*;

    #[test]
    fn prometheus_encoding_works() {
        let mut exporter = PrometheusExporter::new();

        let metrics = AggregatedMetrics {
            slab_metrics: SlabMetrics {
                alloc_count: 100,
                total_latency_ns: 50_000,
                max_latency_ns: 800,
                ..Default::default()
            },
            cq_jitter: CqJitterMetrics {
                completion_count: 50,
                total_latency_ns: 100_000,
                max_latency_ns: 3000,
                stall_count: 2,
            },
            ..Default::default()
        };

        exporter.update(&metrics, HealthState::Healthy, 150);
        exporter.record_alert("interrupt_affinity_skew", "DEGRADED");

        let output = exporter.encode().expect("encoding should not fail");
        assert!(output.contains("argus_health_state"));
        assert!(output.contains("argus_slab_avg_latency_ns"));
        assert!(output.contains("argus_alerts_total"));
        assert!(output.contains("argus_cq_stalls_total"));
        assert!(output.contains("argus_health_score"));
    }

    #[test]
    fn health_state_encoding() {
        let mut exporter = PrometheusExporter::new();
        let metrics = AggregatedMetrics::default();

        exporter.update(&metrics, HealthState::Critical, 0);
        let output = exporter.encode().expect("encoding should not fail");
        assert!(output.contains("argus_health_state 2"));
    }

    #[test]
    fn state_transitions_counted() {
        let mut exporter = PrometheusExporter::new();
        let metrics = AggregatedMetrics::default();

        exporter.update(&metrics, HealthState::Degraded, 0);
        exporter.update(&metrics, HealthState::Critical, 0);

        let output = exporter.encode().expect("encoding should not fail");
        assert!(output.contains("argus_state_transitions_total"));
    }

    #[test]
    fn ib_counter_labels() {
        let exporter = PrometheusExporter::new();
        let deltas = IbCounterDeltas {
            symbol_error_delta: 5,
            link_downed_delta: 1,
            ..Default::default()
        };

        exporter.update_ib_counters(
            "mlx5_0",
            "1",
            &deltas,
            crate::sources::hwcounters::DeviceType::HardwareIB,
        );
        let output = exporter.encode().expect("encoding should not fail");
        assert!(output.contains("argus_ib_symbol_errors_delta"));
        assert!(output.contains("mlx5_0"));
        assert!(
            !output.contains("argus_ib_rxe_duplicate_request_delta{"),
            "rxe time series should not appear for HardwareIB devices"
        );
    }

    #[test]
    fn counters_increment_correctly() {
        let mut exporter = PrometheusExporter::new();

        let metrics = AggregatedMetrics {
            slab_metrics: SlabMetrics {
                alloc_count: 100,
                ..Default::default()
            },
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![60, 40],
                total_count: 100,
            },
            cq_jitter: CqJitterMetrics {
                completion_count: 25,
                stall_count: 3,
                ..Default::default()
            },
            ..Default::default()
        };

        exporter.update(&metrics, HealthState::Healthy, 200);

        let output = exporter.encode().expect("encoding should not fail");
        assert!(output.contains("argus_events"));
        assert!(output.contains("argus_slab_alloc_total"));
        assert!(output.contains("argus_irq_total"));
        assert!(output.contains("argus_cq_completions_total"));
    }
}

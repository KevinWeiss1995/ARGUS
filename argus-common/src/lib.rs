#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

use serde::{Deserialize, Serialize};
use std::fmt;

pub mod capability;
pub use capability::{
    BackendId, BackendOutcome, BackendProbeResult, Capability, CapabilityCoverage, CoverageGrade,
    CoverageReport, Quality, Sample,
};

// ---------------------------------------------------------------------------
// Event types emitted by eBPF probes (or mock/replay sources)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ArgusEvent {
    SlabAlloc(SlabAllocEvent),
    SlabFree(SlabFreeEvent),
    IrqEntry(IrqEntryEvent),
    NapiPoll(NapiPollEvent),
    NetifReceive(NetifReceiveEvent),
    CqCompletion(CqCompletionEvent),
    HardwareCounter(HardwareCounterEvent),
}

impl ArgusEvent {
    #[must_use]
    pub fn timestamp_ns(&self) -> u64 {
        match self {
            Self::SlabAlloc(e) => e.timestamp_ns,
            Self::SlabFree(e) => e.timestamp_ns,
            Self::IrqEntry(e) => e.timestamp_ns,
            Self::NapiPoll(e) => e.timestamp_ns,
            Self::NetifReceive(e) => e.timestamp_ns,
            Self::CqCompletion(e) => e.timestamp_ns,
            Self::HardwareCounter(e) => e.timestamp_ns,
        }
    }

    #[must_use]
    pub fn event_type_name(&self) -> &'static str {
        match self {
            Self::SlabAlloc(_) => "slab_alloc",
            Self::SlabFree(_) => "slab_free",
            Self::IrqEntry(_) => "irq_entry",
            Self::NapiPoll(_) => "napi_poll",
            Self::NetifReceive(_) => "netif_receive",
            Self::CqCompletion(_) => "cq_completion",
            Self::HardwareCounter(_) => "hw_counter",
        }
    }
}

// ---------------------------------------------------------------------------
// Individual event structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SlabAllocEvent {
    pub timestamp_ns: u64,
    pub cpu: u32,
    pub bytes_req: u32,
    pub bytes_alloc: u32,
    pub latency_ns: u64,
    pub numa_node: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SlabFreeEvent {
    pub timestamp_ns: u64,
    pub cpu: u32,
    pub bytes_freed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IrqEntryEvent {
    pub timestamp_ns: u64,
    pub cpu: u32,
    pub irq: u32,
    pub handler_name_hash: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NapiPollEvent {
    pub timestamp_ns: u64,
    pub cpu: u32,
    pub budget: u32,
    pub work_done: u32,
    pub dev_name_hash: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetifReceiveEvent {
    pub timestamp_ns: u64,
    pub cpu: u32,
    pub len: u32,
    pub dev_name_hash: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CqCompletionEvent {
    pub timestamp_ns: u64,
    pub cpu: u32,
    pub latency_ns: u64,
    pub queue_pair_num: u32,
    pub is_error: bool,
    pub opcode: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HardwareCounterEvent {
    pub timestamp_ns: u64,
    pub port_num: u32,
    pub counter: HardwareCounter,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HardwareCounter {
    // --- Standard IB counters (from counters/) ---
    SymbolErrors(u64),
    LinkDowned(u64),
    PortRcvErrors(u64),
    PortXmitDiscards(u64),
    /// Standard IB counter — value is in 4-byte units.
    PortRcvData(u64),
    /// Standard IB counter — value is in 4-byte units.
    PortXmitData(u64),
    PortRcvRemotePhysicalErrors(u64),
    LocalLinkIntegrityErrors(u64),
    ExcessiveBufferOverrunErrors(u64),
    /// Automatic link recovery attempts — increments *before* link_downed.
    /// The key early-warning signal for cable faults.
    LinkErrorRecovery(u64),
    // --- hw_counters (rxe/driver-specific) ---
    /// hw_counters rcvd_pkts — packet count.
    HwRcvPkts(u64),
    /// hw_counters sent_pkts — packet count.
    HwXmitPkts(u64),
    /// rxe hw_counters duplicate_request — operational on Soft-RoCE, NOT a link error.
    RxeDuplicateRequest(u64),
    /// rxe hw_counters rcvd_seq_err — operational on Soft-RoCE, NOT a link error.
    RxeSeqError(u64),
    /// rxe hw_counters retry_exceeded_err.
    RxeRetryExceeded(u64),
    /// rxe hw_counters send_err.
    RxeSendError(u64),
    /// Time spent waiting for credits to send. Non-zero indicates upstream congestion
    /// (the "victim buffer" effect on lossless IB fabrics).
    PortXmitWait(u64),

    // --- Mellanox mlx5-specific RoCE/IB extended counters ---
    //
    // These live at /sys/class/infiniband/mlx5_*/ports/<N>/hw_counters/
    // and are THE primary slow-degradation indicators on Mellanox
    // hardware per NVIDIA's published IB diagnostics guidance and the
    // mlx5_core OFED documentation. They have nothing to do with rxe
    // (which has different filenames in the same directory).

    /// Local ACK timeouts. Climbs when an RC connection's peer fails to
    /// acknowledge sends within the configured timeout. Slow-creep
    /// indicator of intermittent peer/path connectivity.
    Mlx5LocalAckTimeoutErr(u64),

    /// PSN sequence errors. Climbs on small amounts of packet loss /
    /// reordering. Per NVIDIA, the primary indicator of marginal
    /// network paths.
    Mlx5PacketSeqErr(u64),

    /// Implied NAKs from sequence errors. Companion signal to
    /// packet_seq_err — same root cause, RDMA-stack reaction.
    Mlx5ImpliedNakSeqErr(u64),

    /// Receive-buffer exhaustion events. Slow creep indicates
    /// undersized buffers OR sustained over-subscription.
    Mlx5OutOfBuffer(u64),

    /// Out-of-order packet arrivals. Climbs under adaptive routing /
    /// path-flap conditions in the fabric.
    Mlx5OutOfSequence(u64),

    /// Completion-queue errors on RDMA REQUEST work-requests. Direct
    /// indicator of RDMA-stack-level errors that bypass the IB error
    /// counters.
    Mlx5ReqCqeError(u64),

    /// Completion-queue errors on RDMA RESPONSE work-requests.
    Mlx5RespCqeError(u64),

    /// RoCE adaptive retransmissions. Indicates RoCE-level packet
    /// recovery activity — climbs when packets are silently dropped
    /// on the wire and need re-sending at the RoCE layer.
    Mlx5RoceAdpRetrans(u64),

    /// RoCE slow-restart activations. Climbs when RoCE has to fall
    /// back from its fast path. Sustained increase is a strong
    /// indicator of fabric or NIC trouble.
    Mlx5RoceSlowRestart(u64),

    /// Congestion Notification Packets sent from this Notification
    /// Point. Visibility into DCQCN congestion-control activity.
    Mlx5NpCnpSent(u64),

    /// Congestion Notification Packets handled at this Reaction
    /// Point. The counterpart of NpCnpSent — climbs when upstream
    /// fabric ECN-marks our traffic.
    Mlx5RpCnpHandled(u64),
}

// ---------------------------------------------------------------------------
// CQ Jitter / Micro-Stall metrics (from eBPF kprobes on mlx5/rxe CQ path)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CqJitterMetrics {
    /// Total CQ completions observed this window.
    pub completion_count: u64,
    /// Sum of all completion latencies (ns).
    pub total_latency_ns: u64,
    /// Maximum single-completion latency (ns).
    pub max_latency_ns: u64,
    /// Completions exceeding the stall threshold (>50us).
    pub stall_count: u64,
}

impl CqJitterMetrics {
    #[must_use]
    pub fn avg_latency_ns(&self) -> f64 {
        if self.completion_count == 0 {
            return 0.0;
        }
        self.total_latency_ns as f64 / self.completion_count as f64
    }

    /// Estimated p99 latency. With only count/sum/max available from the BPF
    /// stats map, we approximate p99 as max_latency * 0.9 when stalls are
    /// present, or avg * 2 otherwise. This is intentionally conservative —
    /// if we ever add histogram buckets in BPF, we can compute this exactly.
    #[must_use]
    pub fn estimated_p99_ns(&self) -> f64 {
        if self.stall_count > 0 {
            self.max_latency_ns as f64 * 0.9
        } else if self.completion_count > 0 {
            self.avg_latency_ns() * 2.0
        } else {
            0.0
        }
    }

    #[must_use]
    pub fn has_data(&self) -> bool {
        self.completion_count > 0
    }
}

// ---------------------------------------------------------------------------
// Node health classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HealthState {
    Healthy,
    Degraded,
    Critical,
    /// De-escalation holding state between Critical and Degraded.
    /// The node was Critical and conditions have improved, but we require
    /// a mandatory hold period before returning to Degraded/Healthy.
    /// Maps to Draining for scheduler purposes (same as Degraded).
    Recovering,
}

impl HealthState {
    /// For scheduler integration: Recovering behaves like Degraded.
    #[must_use]
    pub fn for_scheduler(self) -> Self {
        match self {
            Self::Recovering => Self::Degraded,
            other => other,
        }
    }
}

impl fmt::Display for HealthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "HEALTHY"),
            Self::Degraded => write!(f, "DEGRADED"),
            Self::Critical => write!(f, "CRITICAL"),
            Self::Recovering => write!(f, "RECOVERING"),
        }
    }
}

// ---------------------------------------------------------------------------
// Alerts emitted by the detection engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub timestamp_ns: u64,
    pub kind: AlertKind,
    pub severity: HealthState,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertKind {
    InterruptAffinitySkew {
        dominant_cpu: u32,
        dominant_pct: f64,
    },
    RdmaLatencySpike {
        current_latency_ns: u64,
        baseline_latency_ns: u64,
        ratio: f64,
    },
    SlabPressureCorrelation {
        slab_alloc_rate: u64,
        ib_error_delta: u64,
    },
    LinkEvent {
        port: u32,
        counter: String,
        value: u64,
    },
    RdmaLinkDegradation {
        symbol_error_delta: u64,
        link_downed_delta: u64,
        rcv_error_delta: u64,
        xmit_discard_delta: u64,
    },
    RisingErrorTrend {
        consecutive_windows: u32,
        current_delta: u64,
    },
    LatencyDrift {
        metric_name: String,
        z_score: f64,
        current_value: f64,
        ewma: f64,
    },
    ThroughputDrop {
        current_throughput: u64,
        ewma_throughput: f64,
        drop_pct: f64,
    },
    NapiSaturation {
        avg_work_per_poll: f64,
        avg_budget: f64,
        utilization_pct: f64,
    },
    CqJitterStall {
        stall_count: u64,
        max_latency_ns: u64,
        p99_estimate_ns: f64,
    },
    CongestionSpread {
        xmit_wait_delta: u64,
    },
    PcieBottleneck {
        cq_stalls: u64,
        slab_pressure: u64,
        ib_errors: u64,
    },
    /// Long-window slow-degradation signal. Fires when a low-magnitude
    /// error signal (symbol errors, RoCE retransmissions, etc.) has been
    /// sustained at a rate above the noise floor for hours. Distinct
    /// from RisingErrorTrend, which is a short-window per-counter
    /// monotonic rise. This is the El-Sayed & Schroeder (DSN 2013)
    /// "creep that predicts a catastrophic failure 24-72 hours later."
    SlowDegradation {
        /// Which metric tripped the long-window threshold.
        signal_name: String,
        /// Mean rate over the long window (events / window).
        sustained_rate: f64,
        /// Number of windows the rate stayed above the threshold.
        sustained_windows: u32,
        /// Approximate wall-clock seconds of sustained elevation.
        sustained_seconds: u64,
    },
    /// PCIe link to the IB NIC has downgraded below its negotiated
    /// max (e.g. x16 → x8, or PCIe 4.0 → PCIe 3.0). Often a hardware
    /// problem on the NIC or motherboard slot. Not detectable through
    /// IB error counters.
    PcieLaneDegradation {
        device: String,
        current_speed: String,
        max_speed: String,
        current_width: u32,
        max_width: u32,
    },
    /// NIC temperature exceeds a threshold. Climbing temperature
    /// predicts hardware failure hours-to-days in advance. Read via
    /// the hwmon link off the Mellanox PCI device.
    NicThermal {
        device: String,
        current_celsius: f64,
        threshold_celsius: f64,
    },
}

impl Alert {
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match &self.kind {
            AlertKind::InterruptAffinitySkew { .. } => "interrupt_affinity_skew",
            AlertKind::RdmaLatencySpike { .. } => "rdma_latency_spike",
            AlertKind::SlabPressureCorrelation { .. } => "slab_pressure_correlation",
            AlertKind::LinkEvent { .. } => "link_event",
            AlertKind::RdmaLinkDegradation { .. } => "rdma_link_degradation",
            AlertKind::RisingErrorTrend { .. } => "rising_error_trend",
            AlertKind::LatencyDrift { .. } => "latency_drift",
            AlertKind::ThroughputDrop { .. } => "throughput_drop",
            AlertKind::NapiSaturation { .. } => "napi_saturation",
            AlertKind::CqJitterStall { .. } => "cq_jitter_stall",
            AlertKind::CongestionSpread { .. } => "congestion_spread",
            AlertKind::PcieBottleneck { .. } => "pcie_bottleneck",
            AlertKind::SlowDegradation { .. } => "slow_degradation",
            AlertKind::PcieLaneDegradation { .. } => "pcie_lane_degradation",
            AlertKind::NicThermal { .. } => "nic_thermal",
        }
    }
}

// ---------------------------------------------------------------------------
// Aggregated metrics (output of the pipeline aggregator)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AggregatedMetrics {
    pub window_start_ns: u64,
    pub window_end_ns: u64,
    pub interrupt_distribution: InterruptDistribution,
    pub slab_metrics: SlabMetrics,
    pub rdma_metrics: RdmaMetrics,
    pub network_metrics: NetworkMetrics,
    pub ib_counter_deltas: IbCounterDeltas,
    pub cq_jitter: CqJitterMetrics,
    /// Composite health score (0.0 = perfectly healthy, 1.0 = maximally degraded).
    /// Computed by the detection engine from weighted signal combination.
    pub composite_health_score: f64,
    /// Per-port idle tracking. Each entry reports how long a discovered IB
    /// port has been observed with zero throughput. The agent continues
    /// passive monitoring of error counters regardless of idle state; this
    /// field exists so operators can distinguish "quiet fabric, monitored"
    /// from "monitoring offline."
    #[serde(default)]
    pub ib_port_idle: Vec<IbPortIdle>,
}

/// Per-port idle snapshot for surfaces like /status and Prometheus gauges.
/// Hardware error counters (symbol_error_delta, link_error_recovery_delta,
/// link_downed_delta) continue to fire regardless of idle_seconds — passive
/// monitoring of an idle link is still real monitoring.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IbPortIdle {
    pub device: String,
    pub port: u32,
    /// Wall-clock seconds since the last window in which this port observed
    /// any non-zero throughput. 0 means the port saw traffic this window.
    pub idle_seconds: u64,
}

impl AggregatedMetrics {
    /// True when at least one IB port is known and every discovered port has
    /// been idle for one window or more. Returns false when there are no
    /// known ports, so consumers can distinguish "fabric is idle" from
    /// "no fabric detected."
    #[must_use]
    pub fn ib_fabric_idle(&self) -> bool {
        if self.ib_port_idle.is_empty() {
            return false;
        }
        self.ib_port_idle.iter().all(|p| p.idle_seconds > 0)
    }

    /// Maximum idle-seconds across all known ports. 0 means at least one
    /// port has traffic; positive means fabric has been idle that long
    /// (passive monitoring still active).
    #[must_use]
    pub fn ib_max_idle_seconds(&self) -> u64 {
        self.ib_port_idle.iter().map(|p| p.idle_seconds).max().unwrap_or(0)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterruptDistribution {
    pub per_cpu_counts: Vec<u64>,
    pub total_count: u64,
}

impl InterruptDistribution {
    #[must_use]
    pub fn dominant_cpu_pct(&self) -> f64 {
        if self.total_count == 0 {
            return 0.0;
        }
        let max = self.per_cpu_counts.iter().copied().max().unwrap_or(0);
        max as f64 / self.total_count as f64 * 100.0
    }

    #[must_use]
    pub fn dominant_cpu(&self) -> Option<u32> {
        self.per_cpu_counts
            .iter()
            .enumerate()
            .max_by_key(|(_, &count)| count)
            .map(|(idx, _)| idx as u32)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SlabMetrics {
    pub alloc_count: u64,
    pub free_count: u64,
    pub total_latency_ns: u64,
    pub max_latency_ns: u64,
    pub total_bytes_req: u64,
    pub total_bytes_alloc: u64,
}

impl SlabMetrics {
    #[must_use]
    pub fn avg_latency_ns(&self) -> u64 {
        if self.alloc_count == 0 {
            return 0;
        }
        self.total_latency_ns / self.alloc_count
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RdmaMetrics {
    pub completion_count: u64,
    pub error_count: u64,
    pub total_latency_ns: u64,
    pub max_latency_ns: u64,
    pub retransmission_events: u64,
}

impl RdmaMetrics {
    #[must_use]
    pub fn avg_latency_ns(&self) -> u64 {
        if self.completion_count == 0 {
            return 0;
        }
        self.total_latency_ns / self.completion_count
    }

    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.completion_count == 0 {
            return 0.0;
        }
        self.error_count as f64 / self.completion_count as f64
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub packets_received: u64,
    pub bytes_received: u64,
    pub napi_polls: u64,
    pub napi_total_work: u64,
    pub napi_total_budget: u64,
}

/// Per-window deltas of InfiniBand hardware counters from sysfs.
/// These are computed as (current_absolute - previous_absolute) each window.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IbCounterDeltas {
    // --- Hard errors (always indicate real problems) ---
    pub symbol_error_delta: u64,
    pub link_downed_delta: u64,
    pub port_rcv_remote_physical_errors_delta: u64,
    pub local_link_integrity_errors_delta: u64,
    pub excessive_buffer_overrun_errors_delta: u64,
    /// Link recovery attempts — the key early-warning predictor of cable faults.
    /// Increments before link_downed; any delta > 0 is significant.
    pub link_error_recovery_delta: u64,
    // --- Standard IB error counters (from counters/) ---
    pub port_rcv_errors_delta: u64,
    pub port_xmit_discards_delta: u64,
    // --- Throughput counters ---
    /// Standard IB counter delta — in 4-byte units.
    pub port_rcv_data_delta: u64,
    /// Standard IB counter delta — in 4-byte units.
    pub port_xmit_data_delta: u64,
    /// hw_counters rcvd_pkts delta — packet count (rxe).
    pub hw_rcv_pkts_delta: u64,
    /// hw_counters sent_pkts delta — packet count (rxe).
    pub hw_xmit_pkts_delta: u64,
    /// Credit stall time — nonzero means upstream congestion is propagating.
    pub port_xmit_wait_delta: u64,
    // --- Soft/operational errors (normal on Soft-RoCE, tracked separately) ---
    pub rxe_duplicate_request_delta: u64,
    pub rxe_seq_error_delta: u64,
    pub rxe_retry_exceeded_delta: u64,
    pub rxe_send_error_delta: u64,

    // --- Mellanox mlx5-specific RoCE/IB extended counter deltas ---
    // See HardwareCounter::Mlx5* variants for documentation of what each
    // of these means. Tagged #[serde(default)] so older JSON snapshots
    // (and replay scenarios from prior releases) still load.
    #[serde(default)]
    pub mlx5_local_ack_timeout_err_delta: u64,
    #[serde(default)]
    pub mlx5_packet_seq_err_delta: u64,
    #[serde(default)]
    pub mlx5_implied_nak_seq_err_delta: u64,
    #[serde(default)]
    pub mlx5_out_of_buffer_delta: u64,
    #[serde(default)]
    pub mlx5_out_of_sequence_delta: u64,
    #[serde(default)]
    pub mlx5_req_cqe_error_delta: u64,
    #[serde(default)]
    pub mlx5_resp_cqe_error_delta: u64,
    #[serde(default)]
    pub mlx5_roce_adp_retrans_delta: u64,
    #[serde(default)]
    pub mlx5_roce_slow_restart_delta: u64,
    #[serde(default)]
    pub mlx5_np_cnp_sent_delta: u64,
    #[serde(default)]
    pub mlx5_rp_cnp_handled_delta: u64,
}

impl IbCounterDeltas {
    /// Aggregate Mellanox slow-degradation signal — sum of the four
    /// counters the literature consistently flags as primary indicators
    /// of marginal-link / intermittent-connection failure:
    ///
    ///   - local_ack_timeout_err  (intermittent peer/path)
    ///   - packet_seq_err         (small packet loss / reorder)
    ///   - implied_nak_seq_err    (RDMA-stack reaction to PSN errors)
    ///   - roce_adp_retrans       (RoCE-level retransmissions)
    ///
    /// Used by the slow-trend rule (and any other rule that wants a
    /// "is this link quietly going bad?" signal). Returns 0 on non-
    /// Mellanox hardware where these counters don't exist.
    #[must_use]
    pub fn mlx5_slow_degradation_signal(&self) -> u64 {
        self.mlx5_local_ack_timeout_err_delta
            .saturating_add(self.mlx5_packet_seq_err_delta)
            .saturating_add(self.mlx5_implied_nak_seq_err_delta)
            .saturating_add(self.mlx5_roce_adp_retrans_delta)
    }

    /// Aggregate Mellanox RDMA work-request error signal. Distinct
    /// from the slow-degradation signal because CQE errors are an
    /// immediate "this work request failed" report, not a creep
    /// indicator.
    #[must_use]
    pub fn mlx5_cqe_error_total(&self) -> u64 {
        self.mlx5_req_cqe_error_delta
            .saturating_add(self.mlx5_resp_cqe_error_delta)
    }
}

impl IbCounterDeltas {
    /// Hard errors: always indicate real link/hardware problems regardless of device type.
    #[must_use]
    pub fn total_hard_error_delta(&self) -> u64 {
        self.symbol_error_delta
            + self.link_downed_delta
            + self.port_rcv_remote_physical_errors_delta
            + self.local_link_integrity_errors_delta
            + self.excessive_buffer_overrun_errors_delta
    }

    /// Soft/operational errors from rxe hw_counters. Normal on Soft-RoCE during
    /// active traffic; only concerning when rate deviates from baseline.
    #[must_use]
    pub fn total_soft_error_delta(&self) -> u64 {
        self.rxe_duplicate_request_delta
            + self.rxe_seq_error_delta
            + self.rxe_retry_exceeded_delta
            + self.rxe_send_error_delta
    }

    /// All error deltas (hard + standard IB counters). Does NOT include soft/rxe errors.
    #[must_use]
    pub fn total_error_delta(&self) -> u64 {
        self.total_hard_error_delta() + self.port_rcv_errors_delta + self.port_xmit_discards_delta
    }

    /// All error deltas across all device types (hard + standard + soft/rxe).
    /// Used for display — shows any error activity regardless of source.
    #[must_use]
    pub fn total_all_errors_delta(&self) -> u64 {
        self.total_error_delta() + self.total_soft_error_delta()
    }

    /// Throughput in bytes from standard IB counters (4-byte units × 4).
    /// Returns 0 on rxe/Soft-RoCE where these counters don't exist.
    #[must_use]
    pub fn throughput_bytes(&self) -> u64 {
        (self.port_rcv_data_delta + self.port_xmit_data_delta) * 4
    }

    /// Throughput in packets from hw_counters (rxe rcvd_pkts + sent_pkts).
    /// Returns 0 on real IB where byte counters are used instead.
    #[must_use]
    pub fn throughput_pkts(&self) -> u64 {
        self.hw_rcv_pkts_delta + self.hw_xmit_pkts_delta
    }

    /// True if any traffic was observed in this window, from either source.
    #[must_use]
    pub fn has_traffic(&self) -> bool {
        self.throughput_bytes() > 0 || self.throughput_pkts() > 0
    }
}

// ---------------------------------------------------------------------------
// Test scenario format
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestScenario {
    pub name: String,
    pub description: String,
    pub events: Vec<ArgusEvent>,
    pub expected_states: Vec<ExpectedStateTransition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedStateTransition {
    pub after_event_index: usize,
    pub expected_state: HealthState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_state_display() {
        assert_eq!(HealthState::Healthy.to_string(), "HEALTHY");
        assert_eq!(HealthState::Degraded.to_string(), "DEGRADED");
        assert_eq!(HealthState::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn interrupt_distribution_empty() {
        let dist = InterruptDistribution::default();
        assert_eq!(dist.dominant_cpu_pct(), 0.0);
        assert_eq!(dist.dominant_cpu(), None);
    }

    #[test]
    fn interrupt_distribution_skewed() {
        let dist = InterruptDistribution {
            per_cpu_counts: vec![80, 10, 5, 5],
            total_count: 100,
        };
        assert_eq!(dist.dominant_cpu_pct(), 80.0);
        assert_eq!(dist.dominant_cpu(), Some(0));
    }

    #[test]
    fn slab_metrics_avg_latency() {
        let m = SlabMetrics {
            alloc_count: 100,
            total_latency_ns: 5000,
            ..Default::default()
        };
        assert_eq!(m.avg_latency_ns(), 50);
    }

    #[test]
    fn slab_metrics_avg_latency_zero() {
        let m = SlabMetrics::default();
        assert_eq!(m.avg_latency_ns(), 0);
    }

    #[test]
    fn rdma_metrics_error_rate() {
        let m = RdmaMetrics {
            completion_count: 1000,
            error_count: 5,
            ..Default::default()
        };
        assert!((m.error_rate() - 0.005).abs() < f64::EPSILON);
    }

    #[test]
    fn event_serialization_roundtrip() {
        let event = ArgusEvent::SlabAlloc(SlabAllocEvent {
            timestamp_ns: 1_000_000,
            cpu: 0,
            bytes_req: 64,
            bytes_alloc: 64,
            latency_ns: 150,
            numa_node: 0,
        });
        let json = serde_json::to_string(&event).unwrap();
        let back: ArgusEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn event_type_names() {
        let event = ArgusEvent::CqCompletion(CqCompletionEvent {
            timestamp_ns: 0,
            cpu: 0,
            latency_ns: 100,
            queue_pair_num: 1,
            is_error: false,
            opcode: 0,
        });
        assert_eq!(event.event_type_name(), "cq_completion");
    }
}

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

use serde::{Deserialize, Serialize};
use std::fmt;

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
    /// hw_counters rcvd_pkts — packet count (rxe hw_counters).
    HwRcvPkts(u64),
    /// hw_counters sent_pkts — packet count (rxe hw_counters).
    HwXmitPkts(u64),
}

// ---------------------------------------------------------------------------
// Node health classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HealthState {
    Healthy,
    Degraded,
    Critical,
}

impl fmt::Display for HealthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "HEALTHY"),
            Self::Degraded => write!(f, "DEGRADED"),
            Self::Critical => write!(f, "CRITICAL"),
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
    /// Composite health score (0.0 = perfectly healthy, 1.0 = maximally degraded).
    /// Computed by the detection engine from weighted signal combination.
    pub composite_health_score: f64,
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
    pub symbol_error_delta: u64,
    pub link_downed_delta: u64,
    pub port_rcv_errors_delta: u64,
    pub port_xmit_discards_delta: u64,
    pub port_rcv_remote_physical_errors_delta: u64,
    pub local_link_integrity_errors_delta: u64,
    pub excessive_buffer_overrun_errors_delta: u64,
    /// Standard IB counter delta — in 4-byte units.
    pub port_rcv_data_delta: u64,
    /// Standard IB counter delta — in 4-byte units.
    pub port_xmit_data_delta: u64,
    /// hw_counters rcvd_pkts delta — packet count (rxe).
    pub hw_rcv_pkts_delta: u64,
    /// hw_counters sent_pkts delta — packet count (rxe).
    pub hw_xmit_pkts_delta: u64,
}

impl IbCounterDeltas {
    #[must_use]
    pub fn total_error_delta(&self) -> u64 {
        self.symbol_error_delta
            + self.link_downed_delta
            + self.port_rcv_errors_delta
            + self.port_xmit_discards_delta
            + self.port_rcv_remote_physical_errors_delta
            + self.local_link_integrity_errors_delta
            + self.excessive_buffer_overrun_errors_delta
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

//! Capability-driven signal model for portable RDMA observability.
//!
//! Signals are first-class; backends are pluggable. Detection rules consume
//! `Sample`s tagged with their `Capability`, `Quality`, and `confidence`.
//! When a backend is unavailable on a given fabric, providers report
//! `Quality::Absent` rather than fabricating zeros — and the fusion layer
//! gracefully ignores absent inputs.
//!
//! See `docs/architecture.md` (or the plan file) for fabric-specific
//! coverage tables.

#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};
use std::fmt;

/// Discrete signal categories the detection layer reasons about.
///
/// Each capability has multiple possible backends in `argus-agent` ranked
/// from highest fidelity to inferred-only. Backends are selected at runtime
/// based on detected fabric, driver, kernel, and privilege.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum Capability {
    /// Symbol errors, link downed, port_rcv_errors, port_xmit_discards.
    /// Universal — sysfs port counters work on every IB/RoCE/rxe device.
    LinkErrors,
    /// Bytes/packets observed per port.
    Throughput,
    /// CQ completion latency distribution (mean + percentiles).
    CompletionLatency,
    /// Per-QP or aggregate retransmission rate.
    /// Hardest capability to make portable; chain has ~6 tiers.
    RetransmitSignal,
    /// NAK send / receive rate (sender and receiver views).
    NakRate,
    /// PSN gap / out-of-order packet rate.
    OutOfOrder,
    /// Per-priority PFC pause durations and frame counts.
    /// `Quality::Absent` on InfiniBand (CBFC) and rxe (no PFC layer).
    PfcPause,
    /// ECN-marked packet rate (RoCEv2 only).
    EcnMarks,
    /// Congestion Notification Packet rate (RoCEv2/DCQCN).
    CnpRate,
    /// IB credit-based flow control stalls.
    /// `Quality::Absent` on RoCE (PFC takes its place).
    CreditStall,
    /// Per-QP attribution: which QP a sample applies to.
    QpAttribution,
    /// Mapping QP → owning process / cgroup for blast-radius reporting.
    ProcessAttribution,
    /// Active probe RTT to configured peers (Pingmesh-style).
    PeerLiveness,
}

impl Capability {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::LinkErrors => "link_errors",
            Self::Throughput => "throughput",
            Self::CompletionLatency => "completion_latency",
            Self::RetransmitSignal => "retransmit_signal",
            Self::NakRate => "nak_rate",
            Self::OutOfOrder => "out_of_order",
            Self::PfcPause => "pfc_pause",
            Self::EcnMarks => "ecn_marks",
            Self::CnpRate => "cnp_rate",
            Self::CreditStall => "credit_stall",
            Self::QpAttribution => "qp_attribution",
            Self::ProcessAttribution => "process_attribution",
            Self::PeerLiveness => "peer_liveness",
        }
    }

    /// All known capabilities, used for registry initialization and coverage iteration.
    #[must_use]
    pub fn all() -> &'static [Capability] {
        &[
            Self::LinkErrors,
            Self::Throughput,
            Self::CompletionLatency,
            Self::RetransmitSignal,
            Self::NakRate,
            Self::OutOfOrder,
            Self::PfcPause,
            Self::EcnMarks,
            Self::CnpRate,
            Self::CreditStall,
            Self::QpAttribution,
            Self::ProcessAttribution,
            Self::PeerLiveness,
        ]
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Backend fidelity tier.
///
/// `Quality` is **about the backend type**, not about runtime sample noise.
/// A direct hardware counter is High; an inference is Low. Use the
/// `confidence` field on `Sample` to capture sample-level noise.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash, Serialize, Deserialize)]
pub enum Quality {
    /// No data is being collected for this capability on this fabric.
    Absent = 0,
    /// Inferred from correlated signals (latency rise → infer PFC pause).
    Low = 1,
    /// Aggregate counter, or kprobe without per-QP attribution.
    Medium = 2,
    /// Direct hardware counter or precise kprobe with per-QP attribution.
    High = 3,
}

impl Quality {
    /// Multiplicative weight applied during confidence fusion.
    /// High=1.0, Medium=0.7, Low=0.4, Absent=0.0.
    #[must_use]
    pub fn weight(self) -> f64 {
        match self {
            Self::High => 1.0,
            Self::Medium => 0.7,
            Self::Low => 0.4,
            Self::Absent => 0.0,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Absent => "absent",
        }
    }

    /// Numeric encoding for Prometheus gauges (matches enum discriminant).
    #[must_use]
    pub fn as_i64(self) -> i64 {
        self as i64
    }
}

impl fmt::Display for Quality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Stable identifier for a backend implementation.
///
/// New backends should add a variant here. The string form is used in
/// Prometheus labels and the coverage report.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum BackendId {
    // LinkErrors / Throughput / CreditStall — sysfs is universal
    SysfsPortCounters,
    SysfsHwCounters,
    NetlinkRdmaStats,
    EthtoolStats,
    MadPerfquery,

    // CompletionLatency
    EbpfCqLatency,
    VerbsCqLatency,
    ThroughputProxyLatency,

    // RetransmitSignal
    EbpfRetx,
    EthtoolRetx,
    MadRetxProxy,
    WrRatioInference,
    LatencyProxyRetx,

    // NakRate
    EbpfNak,
    SysfsNak,
    CqErrorInference,

    // OutOfOrder
    EbpfOoo,
    EthtoolOoo,
    SysfsOoo,

    // PfcPause
    EthtoolPfc,
    NetlinkDcb,
    PfcInference,

    // EcnMarks / CnpRate
    EthtoolEcn,
    EthtoolCnp,
    QdiscRedInference,
    LatencyEcnInference,

    // CreditStall
    SysfsCreditStall,
    MadCreditStall,
    CreditStallInference,

    // QpAttribution
    EbpfQp,
    RdmaCoreQp,
    SysfsRxeQp,

    // ProcessAttribution
    EbpfQpProcess,
    RdmaCoreQpProcess,

    // PeerLiveness
    ActiveProber,

    // Generic/test
    Synthetic,
}

impl BackendId {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::SysfsPortCounters => "sysfs_port_counters",
            Self::SysfsHwCounters => "sysfs_hw_counters",
            Self::NetlinkRdmaStats => "netlink_rdma_stats",
            Self::EthtoolStats => "ethtool_stats",
            Self::MadPerfquery => "mad_perfquery",
            Self::EbpfCqLatency => "ebpf_cq_latency",
            Self::VerbsCqLatency => "verbs_cq_latency",
            Self::ThroughputProxyLatency => "throughput_proxy_latency",
            Self::EbpfRetx => "ebpf_retx",
            Self::EthtoolRetx => "ethtool_retx",
            Self::MadRetxProxy => "mad_retx_proxy",
            Self::WrRatioInference => "wr_ratio_inference",
            Self::LatencyProxyRetx => "latency_proxy_retx",
            Self::EbpfNak => "ebpf_nak",
            Self::SysfsNak => "sysfs_nak",
            Self::CqErrorInference => "cq_error_inference",
            Self::EbpfOoo => "ebpf_ooo",
            Self::EthtoolOoo => "ethtool_ooo",
            Self::SysfsOoo => "sysfs_ooo",
            Self::EthtoolPfc => "ethtool_pfc",
            Self::NetlinkDcb => "netlink_dcb",
            Self::PfcInference => "pfc_inference",
            Self::EthtoolEcn => "ethtool_ecn",
            Self::EthtoolCnp => "ethtool_cnp",
            Self::QdiscRedInference => "qdisc_red_inference",
            Self::LatencyEcnInference => "latency_ecn_inference",
            Self::SysfsCreditStall => "sysfs_credit_stall",
            Self::MadCreditStall => "mad_credit_stall",
            Self::CreditStallInference => "credit_stall_inference",
            Self::EbpfQp => "ebpf_qp",
            Self::RdmaCoreQp => "rdma_core_qp",
            Self::SysfsRxeQp => "sysfs_rxe_qp",
            Self::EbpfQpProcess => "ebpf_qp_process",
            Self::RdmaCoreQpProcess => "rdma_core_qp_process",
            Self::ActiveProber => "active_prober",
            Self::Synthetic => "synthetic",
        }
    }
}

impl fmt::Display for BackendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One observation produced by a `CapabilityProvider`.
///
/// `value` and `confidence` are independent: `Quality` reflects backend
/// type (sysfs vs inference); `confidence` reflects how trustworthy *this
/// particular sample* is (sample noise, baseline maturity, signal presence).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sample {
    pub capability: Capability,
    /// Numeric value. Units are capability-specific; see `Capability` docs.
    pub value: f64,
    /// 0.0..=1.0. Multiplied by `Quality::weight()` during fusion.
    pub confidence: f64,
    pub quality: Quality,
    pub origin: BackendId,
    pub timestamp_ns: u64,
    /// Per-QP attribution if the backend can provide it.
    pub qp_num: Option<u32>,
    /// Per-port attribution. None means whole-device or fabric-wide.
    pub port: Option<u32>,
    /// Per-priority for PFC samples (0..=7).
    pub priority: Option<u8>,
    /// Optional device name for multi-device hosts.
    pub device: Option<String>,
}

impl Sample {
    /// Effective weight for fusion: `quality.weight() * confidence`.
    #[must_use]
    pub fn effective_weight(&self) -> f64 {
        self.quality.weight() * self.confidence.clamp(0.0, 1.0)
    }

    #[must_use]
    pub fn is_actionable(&self) -> bool {
        self.quality != Quality::Absent && self.confidence > 0.0
    }
}

// ---------------------------------------------------------------------------
// Coverage report — operator-visible
// ---------------------------------------------------------------------------

/// Coverage achieved for a single capability across all probed backends.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityCoverage {
    pub capability: Capability,
    pub active_backend: Option<BackendId>,
    pub quality: Quality,
    pub fallback_chain: Vec<BackendProbeResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendProbeResult {
    pub backend: BackendId,
    pub declared_quality: Quality,
    pub outcome: BackendOutcome,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BackendOutcome {
    Available { observed_quality: Quality },
    Unavailable { reason: String },
}

/// Overall coverage grade — surfaced at startup and via `/coverage`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CoverageGrade {
    /// All critical capabilities are at High quality.
    A,
    /// All critical capabilities at >= Medium; some non-critical may be Absent.
    B,
    /// One or more critical capabilities at Low or Absent (degraded mode).
    C,
    /// No RDMA fabric detected, or so many capabilities Absent that detection is unreliable.
    F,
}

impl CoverageGrade {
    #[must_use]
    pub fn as_char(self) -> char {
        match self {
            Self::A => 'A',
            Self::B => 'B',
            Self::C => 'C',
            Self::F => 'F',
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageReport {
    pub grade: CoverageGrade,
    pub fabric: Option<String>,
    pub capabilities: Vec<CapabilityCoverage>,
}

impl CoverageReport {
    #[must_use]
    pub fn quality_for(&self, cap: Capability) -> Quality {
        self.capabilities
            .iter()
            .find(|c| c.capability == cap)
            .map_or(Quality::Absent, |c| c.quality)
    }

    /// Multiplicative weight for a rule whose inputs include `caps`.
    ///
    /// Uses the **maximum** quality across consulted inputs ("best evidence
    /// wins"). Rationale: rules typically combine a dominant signal (e.g.,
    /// LinkErrors at High) with corroborating signals (e.g.,
    /// RetransmitSignal at Low via inference). The dominant signal alone
    /// is usually enough to trust the rule's verdict; we don't want to
    /// throw away the boost just because one tier is degraded. When *all*
    /// inputs are Absent the weight is 0 — a rule with no fabric data
    /// cannot lift the score.
    #[must_use]
    pub fn input_weight(&self, caps: &[Capability]) -> f64 {
        if caps.is_empty() {
            return 1.0;
        }
        caps.iter()
            .map(|c| self.quality_for(*c).weight())
            .fold(0.0_f64, f64::max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_weights_ordered() {
        assert!(Quality::High.weight() > Quality::Medium.weight());
        assert!(Quality::Medium.weight() > Quality::Low.weight());
        assert_eq!(Quality::Absent.weight(), 0.0);
    }

    #[test]
    fn sample_effective_weight_combines_quality_and_confidence() {
        let s = Sample {
            capability: Capability::LinkErrors,
            value: 1.0,
            confidence: 0.5,
            quality: Quality::High,
            origin: BackendId::SysfsPortCounters,
            timestamp_ns: 0,
            qp_num: None,
            port: Some(1),
            priority: None,
            device: None,
        };
        assert!((s.effective_weight() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn absent_quality_is_not_actionable() {
        let mut s = Sample {
            capability: Capability::PfcPause,
            value: 0.0,
            confidence: 1.0,
            quality: Quality::Absent,
            origin: BackendId::Synthetic,
            timestamp_ns: 0,
            qp_num: None,
            port: None,
            priority: None,
            device: None,
        };
        assert!(!s.is_actionable());
        s.quality = Quality::Low;
        assert!(s.is_actionable());
    }

    #[test]
    fn coverage_report_max_input_weight() {
        let report = CoverageReport {
            grade: CoverageGrade::B,
            fabric: Some("rocev2".into()),
            capabilities: vec![
                CapabilityCoverage {
                    capability: Capability::Throughput,
                    active_backend: Some(BackendId::SysfsPortCounters),
                    quality: Quality::High,
                    fallback_chain: vec![],
                },
                CapabilityCoverage {
                    capability: Capability::PfcPause,
                    active_backend: Some(BackendId::PfcInference),
                    quality: Quality::Low,
                    fallback_chain: vec![],
                },
            ],
        };
        // Max-based: best evidence wins → High weight.
        let w = report.input_weight(&[Capability::Throughput, Capability::PfcPause]);
        assert!((w - 1.0).abs() < 1e-9, "expected max 1.0, got {w}");
        // All-absent capabilities should produce zero weight.
        let w_absent = report.input_weight(&[Capability::CnpRate, Capability::EcnMarks]);
        assert!(w_absent.abs() < 1e-9, "expected 0.0, got {w_absent}");
    }
}

use argus_common::{AggregatedMetrics, Alert, AlertKind, HealthState};

/// A detection rule evaluates aggregated metrics and optionally produces an alert.
///
/// Stateless rules implement `evaluate`. Stateful rules (with EWMA/trend tracking)
/// override `evaluate_mut` instead; the engine calls `evaluate_mut` when available.
pub trait DetectionRule: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, metrics: &AggregatedMetrics) -> Option<Alert>;

    /// Stateful evaluation. Default delegates to `evaluate`.
    /// Override for rules that maintain internal state across windows.
    fn evaluate_mut(&mut self, metrics: &AggregatedMetrics) -> Option<Alert> {
        self.evaluate(metrics)
    }
}

// ---------------------------------------------------------------------------
// Interrupt Affinity Skew: >threshold% on a single CPU
// ---------------------------------------------------------------------------

pub struct InterruptAffinitySkewRule {
    pub threshold_pct: f64,
}

impl Default for InterruptAffinitySkewRule {
    fn default() -> Self {
        Self {
            threshold_pct: 70.0,
        }
    }
}

impl DetectionRule for InterruptAffinitySkewRule {
    fn name(&self) -> &str {
        "interrupt_affinity_skew"
    }

    fn evaluate(&self, metrics: &AggregatedMetrics) -> Option<Alert> {
        let dist = &metrics.interrupt_distribution;
        if dist.total_count < 10 {
            return None;
        }

        let dominant_pct = dist.dominant_cpu_pct();
        if dominant_pct >= self.threshold_pct {
            Some(Alert {
                timestamp_ns: metrics.window_end_ns,
                kind: AlertKind::InterruptAffinitySkew {
                    dominant_cpu: dist.dominant_cpu().unwrap_or(0),
                    dominant_pct,
                },
                severity: if dominant_pct >= 90.0 {
                    HealthState::Critical
                } else {
                    HealthState::Degraded
                },
                message: format!(
                    "Interrupt affinity skew: CPU {} handling {dominant_pct:.1}% of interrupts",
                    dist.dominant_cpu().unwrap_or(0)
                ),
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// RDMA Latency Spike: current latency > baseline * spike_factor
// (mock/replay mode only — live eBPF cannot measure CQ latency)
// ---------------------------------------------------------------------------

pub struct RdmaLatencySpikeRule {
    pub spike_factor: f64,
    pub baseline_latency_ns: u64,
    pub min_completions: u64,
}

impl Default for RdmaLatencySpikeRule {
    fn default() -> Self {
        Self {
            spike_factor: 5.0,
            baseline_latency_ns: 2_000,
            min_completions: 10,
        }
    }
}

impl DetectionRule for RdmaLatencySpikeRule {
    fn name(&self) -> &str {
        "rdma_latency_spike"
    }

    fn evaluate(&self, metrics: &AggregatedMetrics) -> Option<Alert> {
        let rdma = &metrics.rdma_metrics;
        if rdma.completion_count < self.min_completions {
            return None;
        }

        let avg_latency = rdma.avg_latency_ns();
        let threshold = (self.baseline_latency_ns as f64 * self.spike_factor) as u64;

        if avg_latency >= threshold {
            let ratio = avg_latency as f64 / self.baseline_latency_ns as f64;
            Some(Alert {
                timestamp_ns: metrics.window_end_ns,
                kind: AlertKind::RdmaLatencySpike {
                    current_latency_ns: avg_latency,
                    baseline_latency_ns: self.baseline_latency_ns,
                    ratio,
                },
                severity: if ratio >= 10.0 {
                    HealthState::Critical
                } else {
                    HealthState::Degraded
                },
                message: format!("RDMA latency spike: {avg_latency}ns ({ratio:.1}x baseline)"),
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// RDMA Link Degradation: fires on IB hardware counter deltas from sysfs
// ---------------------------------------------------------------------------

pub struct RdmaLinkDegradationRule {
    /// Minimum total error delta across all counters to trigger.
    pub min_error_delta: u64,
}

impl Default for RdmaLinkDegradationRule {
    fn default() -> Self {
        Self { min_error_delta: 1 }
    }
}

impl DetectionRule for RdmaLinkDegradationRule {
    fn name(&self) -> &str {
        "rdma_link_degradation"
    }

    fn evaluate(&self, metrics: &AggregatedMetrics) -> Option<Alert> {
        let d = &metrics.ib_counter_deltas;
        let total = d.total_error_delta();
        if total < self.min_error_delta {
            return None;
        }

        let is_critical = d.link_downed_delta > 0 || d.port_rcv_errors_delta > 100;

        let mut parts = Vec::new();
        if d.symbol_error_delta > 0 {
            parts.push(format!("symbol_err+{}", d.symbol_error_delta));
        }
        if d.link_downed_delta > 0 {
            parts.push(format!("link_down+{}", d.link_downed_delta));
        }
        if d.port_rcv_errors_delta > 0 {
            parts.push(format!("rcv_err+{}", d.port_rcv_errors_delta));
        }
        if d.port_xmit_discards_delta > 0 {
            parts.push(format!("xmit_disc+{}", d.port_xmit_discards_delta));
        }
        if d.port_rcv_remote_physical_errors_delta > 0 {
            parts.push(format!(
                "remote_phys+{}",
                d.port_rcv_remote_physical_errors_delta
            ));
        }
        if d.local_link_integrity_errors_delta > 0 {
            parts.push(format!(
                "link_integ+{}",
                d.local_link_integrity_errors_delta
            ));
        }
        if d.excessive_buffer_overrun_errors_delta > 0 {
            parts.push(format!(
                "buf_overrun+{}",
                d.excessive_buffer_overrun_errors_delta
            ));
        }

        Some(Alert {
            timestamp_ns: metrics.window_end_ns,
            kind: AlertKind::RdmaLinkDegradation {
                symbol_error_delta: d.symbol_error_delta,
                link_downed_delta: d.link_downed_delta,
                rcv_error_delta: d.port_rcv_errors_delta,
                xmit_discard_delta: d.port_xmit_discards_delta,
            },
            severity: if is_critical {
                HealthState::Critical
            } else {
                HealthState::Degraded
            },
            message: format!("IB link degradation: {}", parts.join(", ")),
        })
    }
}

// ---------------------------------------------------------------------------
// Slab Pressure Correlation: high slab alloc rate + IB error counters rising
// ---------------------------------------------------------------------------

pub struct SlabPressureRule {
    /// Minimum slab allocations in the window to consider.
    pub min_allocs: u64,
    /// Alloc rate threshold (allocs/window) above which pressure is suspected.
    pub alloc_rate_threshold: u64,
}

impl Default for SlabPressureRule {
    fn default() -> Self {
        Self {
            min_allocs: 100,
            alloc_rate_threshold: 5_000,
        }
    }
}

impl DetectionRule for SlabPressureRule {
    fn name(&self) -> &str {
        "slab_pressure_correlation"
    }

    fn evaluate(&self, metrics: &AggregatedMetrics) -> Option<Alert> {
        let slab = &metrics.slab_metrics;
        if slab.alloc_count < self.min_allocs {
            return None;
        }

        let ib_errors = metrics.ib_counter_deltas.total_error_delta();

        if slab.alloc_count >= self.alloc_rate_threshold && ib_errors > 0 {
            Some(Alert {
                timestamp_ns: metrics.window_end_ns,
                kind: AlertKind::SlabPressureCorrelation {
                    slab_alloc_rate: slab.alloc_count,
                    ib_error_delta: ib_errors,
                },
                severity: if ib_errors > 100 {
                    HealthState::Critical
                } else {
                    HealthState::Degraded
                },
                message: format!(
                    "Slab pressure correlated with IB errors: {} allocs/window, {} IB errors",
                    slab.alloc_count, ib_errors
                ),
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Predictive: Rising IB Error Trend
// Fires when IB error deltas have been monotonically increasing for N windows.
// ---------------------------------------------------------------------------

use super::rolling_stats::{RollingStats, TrendTracker};

pub struct RisingErrorTrendRule {
    pub min_consecutive_windows: u32,
    trend: TrendTracker,
}

impl RisingErrorTrendRule {
    #[must_use]
    pub fn new(min_consecutive_windows: u32) -> Self {
        Self {
            min_consecutive_windows,
            trend: TrendTracker::new(),
        }
    }
}

impl Default for RisingErrorTrendRule {
    fn default() -> Self {
        Self::new(3)
    }
}

impl DetectionRule for RisingErrorTrendRule {
    fn name(&self) -> &str {
        "rising_error_trend"
    }

    fn evaluate(&self, _metrics: &AggregatedMetrics) -> Option<Alert> {
        None
    }

    fn evaluate_mut(&mut self, metrics: &AggregatedMetrics) -> Option<Alert> {
        let total = metrics.ib_counter_deltas.total_error_delta();
        let consecutive = self.trend.push(total as f64);

        if consecutive >= self.min_consecutive_windows && total > 0 {
            Some(Alert {
                timestamp_ns: metrics.window_end_ns,
                kind: AlertKind::RisingErrorTrend {
                    consecutive_windows: consecutive,
                    current_delta: total,
                },
                severity: if consecutive >= self.min_consecutive_windows * 2 {
                    HealthState::Critical
                } else {
                    HealthState::Degraded
                },
                message: format!(
                    "IB errors rising for {consecutive} consecutive windows (current delta: {total})"
                ),
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Predictive: Latency Drift (slab alloc latency deviates from EWMA baseline)
// ---------------------------------------------------------------------------

pub struct LatencyDriftRule {
    pub z_threshold: f64,
    stats: RollingStats,
}

impl LatencyDriftRule {
    #[must_use]
    pub fn new(z_threshold: f64) -> Self {
        Self {
            z_threshold,
            stats: RollingStats::new(0.1),
        }
    }
}

impl Default for LatencyDriftRule {
    fn default() -> Self {
        Self::new(3.0)
    }
}

impl DetectionRule for LatencyDriftRule {
    fn name(&self) -> &str {
        "latency_drift"
    }

    fn evaluate(&self, _metrics: &AggregatedMetrics) -> Option<Alert> {
        None
    }

    fn evaluate_mut(&mut self, metrics: &AggregatedMetrics) -> Option<Alert> {
        let latency = metrics.slab_metrics.avg_latency_ns() as f64;
        let z = self.stats.z_score(latency);
        self.stats.push(latency);

        if self.stats.is_warmed_up() && z.abs() >= self.z_threshold {
            Some(Alert {
                timestamp_ns: metrics.window_end_ns,
                kind: AlertKind::LatencyDrift {
                    metric_name: "slab_avg_latency_ns".into(),
                    z_score: z,
                    current_value: latency,
                    ewma: self.stats.mean(),
                },
                severity: if z.abs() >= self.z_threshold * 2.0 {
                    HealthState::Critical
                } else {
                    HealthState::Degraded
                },
                message: format!(
                    "Slab latency drift: {latency:.0}ns (z={z:.1}, baseline={:.0}ns)",
                    self.stats.mean()
                ),
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Predictive: Throughput Drop (port data counters declining significantly)
// ---------------------------------------------------------------------------

pub struct ThroughputDropRule {
    pub drop_threshold_pct: f64,
    stats: RollingStats,
}

impl ThroughputDropRule {
    #[must_use]
    pub fn new(drop_threshold_pct: f64) -> Self {
        Self {
            drop_threshold_pct,
            stats: RollingStats::new(0.1),
        }
    }
}

impl Default for ThroughputDropRule {
    fn default() -> Self {
        Self::new(50.0)
    }
}

impl DetectionRule for ThroughputDropRule {
    fn name(&self) -> &str {
        "throughput_drop"
    }

    fn evaluate(&self, _metrics: &AggregatedMetrics) -> Option<Alert> {
        None
    }

    fn evaluate_mut(&mut self, metrics: &AggregatedMetrics) -> Option<Alert> {
        let d = &metrics.ib_counter_deltas;
        let throughput = if d.throughput_bytes() > 0 {
            d.throughput_bytes() as f64
        } else {
            d.throughput_pkts() as f64
        };
        let ewma = self.stats.mean();
        self.stats.push(throughput);

        if !self.stats.is_warmed_up() || ewma < 1.0 {
            return None;
        }

        let drop_pct = (1.0 - throughput / ewma) * 100.0;
        if drop_pct >= self.drop_threshold_pct {
            Some(Alert {
                timestamp_ns: metrics.window_end_ns,
                kind: AlertKind::ThroughputDrop {
                    current_throughput: throughput as u64,
                    ewma_throughput: ewma,
                    drop_pct,
                },
                severity: if drop_pct >= 80.0 {
                    HealthState::Critical
                } else {
                    HealthState::Degraded
                },
                message: format!(
                    "Throughput drop: {drop_pct:.0}% below baseline ({throughput:.0} vs {ewma:.0})"
                ),
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Predictive: NAPI Saturation (work/poll approaching budget)
// ---------------------------------------------------------------------------

pub struct NapiSaturationRule {
    pub utilization_threshold_pct: f64,
    pub min_polls: u64,
}

impl Default for NapiSaturationRule {
    fn default() -> Self {
        Self {
            utilization_threshold_pct: 85.0,
            min_polls: 10,
        }
    }
}

impl DetectionRule for NapiSaturationRule {
    fn name(&self) -> &str {
        "napi_saturation"
    }

    fn evaluate(&self, metrics: &AggregatedMetrics) -> Option<Alert> {
        let net = &metrics.network_metrics;
        if net.napi_polls < self.min_polls || net.napi_total_budget == 0 {
            return None;
        }

        let avg_work = net.napi_total_work as f64 / net.napi_polls as f64;
        let avg_budget = net.napi_total_budget as f64 / net.napi_polls as f64;

        if avg_budget < 1.0 {
            return None;
        }

        let utilization = avg_work / avg_budget * 100.0;

        if utilization >= self.utilization_threshold_pct {
            Some(Alert {
                timestamp_ns: metrics.window_end_ns,
                kind: AlertKind::NapiSaturation {
                    avg_work_per_poll: avg_work,
                    avg_budget,
                    utilization_pct: utilization,
                },
                severity: if utilization >= 95.0 {
                    HealthState::Critical
                } else {
                    HealthState::Degraded
                },
                message: format!(
                    "NAPI saturation: {utilization:.0}% budget utilization ({avg_work:.0}/{avg_budget:.0} per poll)"
                ),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::{IbCounterDeltas, InterruptDistribution, RdmaMetrics, SlabMetrics};

    #[test]
    fn irq_skew_below_threshold() {
        let rule = InterruptAffinitySkewRule::default();
        let metrics = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![30, 25, 25, 20],
                total_count: 100,
            },
            ..Default::default()
        };
        assert!(rule.evaluate(&metrics).is_none());
    }

    #[test]
    fn irq_skew_above_threshold_degraded() {
        let rule = InterruptAffinitySkewRule::default();
        let metrics = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![75, 10, 10, 5],
                total_count: 100,
            },
            ..Default::default()
        };
        let alert = rule.evaluate(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Degraded);
    }

    #[test]
    fn irq_skew_extreme_is_critical() {
        let rule = InterruptAffinitySkewRule::default();
        let metrics = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![95, 2, 2, 1],
                total_count: 100,
            },
            ..Default::default()
        };
        let alert = rule.evaluate(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Critical);
    }

    #[test]
    fn irq_skew_needs_minimum_samples() {
        let rule = InterruptAffinitySkewRule::default();
        let metrics = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![5, 0, 0, 0],
                total_count: 5,
            },
            ..Default::default()
        };
        assert!(rule.evaluate(&metrics).is_none());
    }

    #[test]
    fn rdma_spike_below_threshold() {
        let rule = RdmaLatencySpikeRule::default();
        let metrics = AggregatedMetrics {
            rdma_metrics: RdmaMetrics {
                completion_count: 100,
                total_latency_ns: 200_000,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(rule.evaluate(&metrics).is_none());
    }

    #[test]
    fn rdma_spike_above_threshold() {
        let rule = RdmaLatencySpikeRule::default();
        let metrics = AggregatedMetrics {
            rdma_metrics: RdmaMetrics {
                completion_count: 100,
                total_latency_ns: 1_500_000,
                ..Default::default()
            },
            ..Default::default()
        };
        let alert = rule.evaluate(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Degraded);
        if let AlertKind::RdmaLatencySpike { ratio, .. } = alert.kind {
            assert!(ratio >= 5.0);
        } else {
            panic!("wrong alert kind");
        }
    }

    #[test]
    fn link_degradation_no_errors() {
        let rule = RdmaLinkDegradationRule::default();
        let metrics = AggregatedMetrics::default();
        assert!(rule.evaluate(&metrics).is_none());
    }

    #[test]
    fn link_degradation_symbol_errors_degraded() {
        let rule = RdmaLinkDegradationRule::default();
        let metrics = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                symbol_error_delta: 5,
                ..Default::default()
            },
            ..Default::default()
        };
        let alert = rule.evaluate(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Degraded);
    }

    #[test]
    fn link_degradation_link_down_critical() {
        let rule = RdmaLinkDegradationRule::default();
        let metrics = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                link_downed_delta: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let alert = rule.evaluate(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Critical);
    }

    #[test]
    fn link_degradation_many_rcv_errors_critical() {
        let rule = RdmaLinkDegradationRule::default();
        let metrics = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                port_rcv_errors_delta: 200,
                ..Default::default()
            },
            ..Default::default()
        };
        let alert = rule.evaluate(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Critical);
    }

    #[test]
    fn slab_pressure_no_correlation() {
        let rule = SlabPressureRule::default();
        let metrics = AggregatedMetrics {
            slab_metrics: SlabMetrics {
                alloc_count: 10_000,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            rule.evaluate(&metrics).is_none(),
            "high allocs alone without IB errors should not trigger"
        );
    }

    #[test]
    fn slab_pressure_with_ib_errors() {
        let rule = SlabPressureRule::default();
        let metrics = AggregatedMetrics {
            slab_metrics: SlabMetrics {
                alloc_count: 10_000,
                ..Default::default()
            },
            ib_counter_deltas: IbCounterDeltas {
                symbol_error_delta: 3,
                ..Default::default()
            },
            ..Default::default()
        };
        let alert = rule.evaluate(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Degraded);
    }
}

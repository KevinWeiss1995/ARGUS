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
    pub num_cpus: u32,
}

impl InterruptAffinitySkewRule {
    /// Compute the effective threshold, scaled by CPU count.
    /// On 2 CPUs: perfect = 50%, effective = max(70, 50+45) = 95%
    /// On 4 CPUs: perfect = 25%, effective = max(70, 25+45) = 70%
    /// On 8 CPUs: perfect = 12.5%, effective = max(70, 12.5+45) = 70%
    fn effective_threshold(&self) -> f64 {
        let perfect_share = 100.0 / self.num_cpus.max(1) as f64;
        f64::max(self.threshold_pct, perfect_share + 45.0)
    }
}

impl Default for InterruptAffinitySkewRule {
    fn default() -> Self {
        Self {
            threshold_pct: 70.0,
            num_cpus: 4,
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

        // On very small systems, require a meaningful sample count to avoid
        // spurious alerts from the first few windows of data.
        if self.num_cpus <= 2 && dist.total_count < 1000 {
            return None;
        }

        let dominant_pct = dist.dominant_cpu_pct();
        let effective = self.effective_threshold();

        if dominant_pct >= effective {
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
// RDMA Link Degradation: state-machine based cable fault progression tracker
//
// Models the real failure sequence:
//   Nominal → ElevatedErrors → LinkRecovering → LinkDown
//
// Uses rate-based detection (errors/throughput) with EWMA baselines and
// configurable error budgets to eliminate false positives from noise.
// ---------------------------------------------------------------------------

/// Internal state tracking cable health progression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkHealthState {
    /// No significant errors — healthy link.
    Nominal,
    /// Error rates are elevated above baseline. Possible early degradation.
    ElevatedErrors,
    /// link_error_recovery is incrementing — active cable fault in progress.
    LinkRecovering,
    /// link_downed has fired — link is down.
    LinkDown,
}

pub struct RdmaLinkDegradationRule {
    symbol_error_rate: RollingStats,
    rcv_error_rate: RollingStats,
    soft_error_rate: RollingStats,
    link_state: LinkHealthState,
    /// Errors per window below which we stay silent (noise floor).
    error_budget: u64,
    z_threshold: f64,
    /// Consecutive windows spent in ElevatedErrors state.
    elevated_windows: u32,
    /// Absolute error rate ceiling (errors / traffic). Above this = always alert,
    /// regardless of EWMA. Prevents "boiling frog" where sustained errors
    /// become the new normal.
    absolute_error_rate_ceiling: f64,
}

impl RdmaLinkDegradationRule {
    #[must_use]
    pub fn new(z_threshold: f64, error_budget: u64) -> Self {
        Self {
            // Clamped at 3x baseline: EWMA can't adapt beyond 3× the initial error rate
            symbol_error_rate: RollingStats::with_clamp(0.1, 3.0),
            rcv_error_rate: RollingStats::with_clamp(0.1, 3.0),
            soft_error_rate: RollingStats::with_clamp(0.1, 3.0),
            link_state: LinkHealthState::Nominal,
            error_budget,
            z_threshold,
            elevated_windows: 0,
            absolute_error_rate_ceiling: 0.05,
        }
    }
}

impl Default for RdmaLinkDegradationRule {
    fn default() -> Self {
        Self::new(3.0, 5)
    }
}

fn format_error_parts(d: &argus_common::IbCounterDeltas) -> String {
    let mut parts = Vec::new();
    if d.symbol_error_delta > 0 {
        parts.push(format!("sym+{}", d.symbol_error_delta));
    }
    if d.link_error_recovery_delta > 0 {
        parts.push(format!("recovery+{}", d.link_error_recovery_delta));
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
    parts.join(", ")
}

impl DetectionRule for RdmaLinkDegradationRule {
    fn name(&self) -> &str {
        "rdma_link_degradation"
    }

    fn evaluate(&self, _metrics: &AggregatedMetrics) -> Option<Alert> {
        None
    }

    fn evaluate_mut(&mut self, metrics: &AggregatedMetrics) -> Option<Alert> {
        let d = &metrics.ib_counter_deltas;
        let ts = metrics.window_end_ns;

        // --- Compute per-signal error rates (normalized by throughput) ---
        let throughput = (d.throughput_bytes().max(d.throughput_pkts())).max(1) as f64;
        let sym_rate = d.symbol_error_delta as f64 / throughput;
        let rcv_rate = (d.port_rcv_errors_delta + d.port_xmit_discards_delta) as f64 / throughput;
        let soft_rate = d.total_soft_error_delta() as f64 / throughput;

        let sym_z = self.symbol_error_rate.z_score(sym_rate);
        let rcv_z = self.rcv_error_rate.z_score(rcv_rate);
        let soft_z = self.soft_error_rate.z_score(soft_rate);

        self.symbol_error_rate.push(sym_rate);
        self.rcv_error_rate.push(rcv_rate);
        self.soft_error_rate.push(soft_rate);

        let warmed = self.symbol_error_rate.is_warmed_up();
        let error_summary = format_error_parts(d);

        // --- Immediate: link_downed → LinkDown (always critical, no budget) ---
        if d.link_downed_delta > 0 {
            self.link_state = LinkHealthState::LinkDown;
            self.elevated_windows = 0;
            return Some(Alert {
                timestamp_ns: ts,
                kind: AlertKind::RdmaLinkDegradation {
                    symbol_error_delta: d.symbol_error_delta,
                    link_downed_delta: d.link_downed_delta,
                    rcv_error_delta: d.port_rcv_errors_delta,
                    xmit_discard_delta: d.port_xmit_discards_delta,
                },
                severity: HealthState::Critical,
                message: format!("LINK DOWN — replace cable. {error_summary}"),
            });
        }

        // --- link_error_recovery incrementing → LinkRecovering (critical) ---
        if d.link_error_recovery_delta > 0 {
            self.link_state = LinkHealthState::LinkRecovering;
            self.elevated_windows = 0;
            return Some(Alert {
                timestamp_ns: ts,
                kind: AlertKind::RdmaLinkDegradation {
                    symbol_error_delta: d.symbol_error_delta,
                    link_downed_delta: d.link_downed_delta,
                    rcv_error_delta: d.port_rcv_errors_delta,
                    xmit_discard_delta: d.port_xmit_discards_delta,
                },
                severity: HealthState::Critical,
                message: format!(
                    "Link recovery active (+{}) — cable fault in progress. {error_summary}",
                    d.link_error_recovery_delta
                ),
            });
        }

        // --- Excessive hard errors in a single window (above budget) ---
        let hard = d.total_hard_error_delta();
        if hard > self.error_budget {
            self.elevated_windows += 1;
            self.link_state = LinkHealthState::ElevatedErrors;
            let severity = if hard > self.error_budget * 10 {
                HealthState::Critical
            } else {
                HealthState::Degraded
            };
            return Some(Alert {
                timestamp_ns: ts,
                kind: AlertKind::RdmaLinkDegradation {
                    symbol_error_delta: d.symbol_error_delta,
                    link_downed_delta: d.link_downed_delta,
                    rcv_error_delta: d.port_rcv_errors_delta,
                    xmit_discard_delta: d.port_xmit_discards_delta,
                },
                severity,
                message: format!(
                    "IB errors above budget ({hard} > {}): {error_summary}",
                    self.error_budget
                ),
            });
        }

        // --- Absolute error rate ceiling (layer 2: catches sustained degradation) ---
        // If the error-to-traffic ratio exceeds the ceiling, alert regardless of
        // EWMA state. This prevents the "boiling frog" scenario where the EWMA
        // adapts to elevated errors and stops flagging them.
        let total_errors = d.total_all_errors_delta();
        if total_errors > 0 && d.has_traffic() {
            let total_rate = total_errors as f64 / throughput;
            if total_rate >= self.absolute_error_rate_ceiling {
                self.elevated_windows += 1;
                self.link_state = LinkHealthState::ElevatedErrors;
                let severity = if total_rate >= self.absolute_error_rate_ceiling * 3.0
                    || self.elevated_windows >= 3
                {
                    HealthState::Critical
                } else {
                    HealthState::Degraded
                };
                return Some(Alert {
                    timestamp_ns: ts,
                    kind: AlertKind::RdmaLinkDegradation {
                        symbol_error_delta: d.symbol_error_delta,
                        link_downed_delta: 0,
                        rcv_error_delta: d.port_rcv_errors_delta,
                        xmit_discard_delta: d.port_xmit_discards_delta,
                    },
                    severity,
                    message: format!(
                        "Error rate {:.1}% exceeds ceiling ({:.1}%): {error_summary} (elevated {}/window)",
                        total_rate * 100.0,
                        self.absolute_error_rate_ceiling * 100.0,
                        self.elevated_windows
                    ),
                });
            }
        }

        // --- Rate-based anomaly detection (layer 3: only after warmup) ---
        if warmed {
            let max_z = sym_z.max(rcv_z).max(soft_z);

            if max_z >= self.z_threshold && total_errors > 0 {
                self.elevated_windows += 1;
                self.link_state = LinkHealthState::ElevatedErrors;

                let severity = if max_z >= self.z_threshold * 2.0 || self.elevated_windows >= 3 {
                    HealthState::Critical
                } else {
                    HealthState::Degraded
                };

                let dominant = if sym_z >= rcv_z && sym_z >= soft_z {
                    format!("symbol_error rate (z={sym_z:.1})")
                } else if rcv_z >= soft_z {
                    format!("rcv_error rate (z={rcv_z:.1})")
                } else {
                    format!("soft_error rate (z={soft_z:.1})")
                };

                return Some(Alert {
                    timestamp_ns: ts,
                    kind: AlertKind::RdmaLinkDegradation {
                        symbol_error_delta: d.symbol_error_delta,
                        link_downed_delta: 0,
                        rcv_error_delta: d.port_rcv_errors_delta,
                        xmit_discard_delta: d.port_xmit_discards_delta,
                    },
                    severity,
                    message: format!(
                        "Error rate anomaly: {dominant}, {error_summary} (elevated {}/window)",
                        self.elevated_windows
                    ),
                });
            }
        }

        // --- No significant errors: trend toward nominal ---
        if self.elevated_windows > 0 {
            self.elevated_windows = self.elevated_windows.saturating_sub(1);
        }
        if self.elevated_windows == 0 {
            self.link_state = LinkHealthState::Nominal;
        }
        None
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
            // Floor clamp at 0.5: EWMA can't drop below 50% of initial throughput.
            // This prevents the baseline from adapting to degraded throughput,
            // keeping drops detectable even when sustained.
            stats: RollingStats::with_floor(0.1, 0.5),
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
        let rule = InterruptAffinitySkewRule {
            threshold_pct: 70.0,
            num_cpus: 4,
        };
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
        let rule = InterruptAffinitySkewRule {
            threshold_pct: 70.0,
            num_cpus: 4,
        };
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
        let rule = InterruptAffinitySkewRule {
            threshold_pct: 70.0,
            num_cpus: 4,
        };
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
        let rule = InterruptAffinitySkewRule {
            threshold_pct: 70.0,
            num_cpus: 4,
        };
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
    fn irq_skew_2cpu_relaxed_threshold() {
        let rule = InterruptAffinitySkewRule {
            threshold_pct: 70.0,
            num_cpus: 2,
        };
        // 90% on 2 CPUs: effective threshold = max(70, 50+45) = 95%, so no alert
        let metrics = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![9000, 1000],
                total_count: 10000,
            },
            ..Default::default()
        };
        assert!(
            rule.evaluate(&metrics).is_none(),
            "90% on 2 CPUs should NOT trigger (effective threshold ~95%)"
        );
    }

    #[test]
    fn irq_skew_2cpu_above_relaxed_threshold() {
        let rule = InterruptAffinitySkewRule {
            threshold_pct: 70.0,
            num_cpus: 2,
        };
        // 97% on 2 CPUs: above effective threshold of 95%
        let metrics = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![9700, 300],
                total_count: 10000,
            },
            ..Default::default()
        };
        let alert = rule.evaluate(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Critical);
    }

    #[test]
    fn irq_skew_2cpu_low_sample_suppressed() {
        let rule = InterruptAffinitySkewRule {
            threshold_pct: 70.0,
            num_cpus: 2,
        };
        // 99% but only 500 samples on 2-CPU system — suppressed
        let metrics = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![495, 5],
                total_count: 500,
            },
            ..Default::default()
        };
        assert!(
            rule.evaluate(&metrics).is_none(),
            "low sample count on 2-CPU system should be suppressed"
        );
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
        let mut rule = RdmaLinkDegradationRule::default();
        let metrics = AggregatedMetrics::default();
        assert!(rule.evaluate_mut(&metrics).is_none());
    }

    #[test]
    fn link_degradation_link_down_always_critical() {
        let mut rule = RdmaLinkDegradationRule::default();
        let metrics = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                link_downed_delta: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let alert = rule.evaluate_mut(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Critical);
        assert!(alert.message.contains("LINK DOWN"));
    }

    #[test]
    fn link_degradation_recovery_is_critical() {
        let mut rule = RdmaLinkDegradationRule::default();
        let metrics = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                link_error_recovery_delta: 3,
                symbol_error_delta: 2,
                ..Default::default()
            },
            ..Default::default()
        };
        let alert = rule.evaluate_mut(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Critical);
        assert!(alert.message.contains("recovery"));
    }

    #[test]
    fn link_degradation_hard_errors_within_budget_silent() {
        let mut rule = RdmaLinkDegradationRule::new(3.0, 5);
        let metrics = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                symbol_error_delta: 3,
                ..Default::default()
            },
            ..Default::default()
        };
        // 3 symbol errors is within budget of 5 — should NOT alert
        assert!(
            rule.evaluate_mut(&metrics).is_none(),
            "errors within budget should be silent"
        );
    }

    #[test]
    fn link_degradation_hard_errors_above_budget_alert() {
        let mut rule = RdmaLinkDegradationRule::new(3.0, 5);
        let metrics = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                symbol_error_delta: 10,
                ..Default::default()
            },
            ..Default::default()
        };
        let alert = rule.evaluate_mut(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Degraded);
        assert!(alert.message.contains("above budget"));
    }

    #[test]
    fn link_degradation_massive_hard_errors_critical() {
        let mut rule = RdmaLinkDegradationRule::new(3.0, 5);
        let metrics = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                symbol_error_delta: 100,
                ..Default::default()
            },
            ..Default::default()
        };
        let alert = rule.evaluate_mut(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Critical);
    }

    #[test]
    fn link_degradation_rxe_soft_errors_no_alert_during_warmup() {
        let mut rule = RdmaLinkDegradationRule::default();
        for _ in 0..4 {
            let metrics = AggregatedMetrics {
                ib_counter_deltas: IbCounterDeltas {
                    rxe_duplicate_request_delta: 100,
                    rxe_seq_error_delta: 50,
                    hw_rcv_pkts_delta: 100_000,
                    hw_xmit_pkts_delta: 100_000,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(
                rule.evaluate_mut(&metrics).is_none(),
                "should not alert during warmup"
            );
        }
    }

    #[test]
    fn link_degradation_rxe_steady_soft_errors_no_alert() {
        let mut rule = RdmaLinkDegradationRule::default();
        for _ in 0..15 {
            let metrics = AggregatedMetrics {
                ib_counter_deltas: IbCounterDeltas {
                    rxe_duplicate_request_delta: 100,
                    rxe_seq_error_delta: 50,
                    hw_rcv_pkts_delta: 100_000,
                    hw_xmit_pkts_delta: 100_000,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(
                rule.evaluate_mut(&metrics).is_none(),
                "steady soft error rate should never alert"
            );
        }
    }

    #[test]
    fn link_degradation_rate_anomaly_after_warmup() {
        let mut rule = RdmaLinkDegradationRule::new(3.0, 5);
        // Warm up with low error rates
        for _ in 0..10 {
            let metrics = AggregatedMetrics {
                ib_counter_deltas: IbCounterDeltas {
                    symbol_error_delta: 1,
                    port_rcv_data_delta: 1_000_000,
                    port_xmit_data_delta: 1_000_000,
                    ..Default::default()
                },
                ..Default::default()
            };
            rule.evaluate_mut(&metrics);
        }
        // Spike: 500x the normal symbol error rate
        let spike = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                symbol_error_delta: 500,
                port_rcv_data_delta: 1_000_000,
                port_xmit_data_delta: 1_000_000,
                ..Default::default()
            },
            ..Default::default()
        };
        // 500 > budget(5) — should fire on the budget check
        let alert = rule.evaluate_mut(&spike).unwrap();
        assert!(alert.severity == HealthState::Degraded || alert.severity == HealthState::Critical);
    }

    #[test]
    fn link_degradation_cable_failure_sequence() {
        let mut rule = RdmaLinkDegradationRule::new(3.0, 5);
        // Step 1: elevated symbol errors
        let m1 = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                symbol_error_delta: 20,
                ..Default::default()
            },
            ..Default::default()
        };
        let a1 = rule.evaluate_mut(&m1).unwrap();
        assert_eq!(a1.severity, HealthState::Degraded);

        // Step 2: link_error_recovery fires
        let m2 = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                link_error_recovery_delta: 2,
                symbol_error_delta: 15,
                ..Default::default()
            },
            ..Default::default()
        };
        let a2 = rule.evaluate_mut(&m2).unwrap();
        assert_eq!(a2.severity, HealthState::Critical);
        assert!(a2.message.contains("recovery"));

        // Step 3: link_downed
        let m3 = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                link_downed_delta: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let a3 = rule.evaluate_mut(&m3).unwrap();
        assert_eq!(a3.severity, HealthState::Critical);
        assert!(a3.message.contains("LINK DOWN"));
    }

    #[test]
    fn link_degradation_returns_to_nominal() {
        let mut rule = RdmaLinkDegradationRule::new(3.0, 5);
        // Fire an alert
        let bad = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                symbol_error_delta: 20,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(rule.evaluate_mut(&bad).is_some());

        // Several clean windows should return to nominal (elevated_windows drains)
        for _ in 0..5 {
            let clean = AggregatedMetrics::default();
            rule.evaluate_mut(&clean);
        }
        let clean = AggregatedMetrics::default();
        assert!(rule.evaluate_mut(&clean).is_none());
    }

    #[test]
    fn link_degradation_absolute_ceiling_catches_sustained_errors() {
        let mut rule = RdmaLinkDegradationRule::new(3.0, 5);
        // Warm up with low soft error rate (0.075% = 150/200K)
        for _ in 0..10 {
            let metrics = AggregatedMetrics {
                ib_counter_deltas: IbCounterDeltas {
                    rxe_duplicate_request_delta: 100,
                    rxe_seq_error_delta: 50,
                    hw_rcv_pkts_delta: 100_000,
                    hw_xmit_pkts_delta: 100_000,
                    ..Default::default()
                },
                ..Default::default()
            };
            rule.evaluate_mut(&metrics);
        }

        // Now inject sustained 20% error rate (40K errors / 200K pkts).
        // The EWMA z-score alone would eventually adapt and stop alerting.
        // The absolute ceiling (5%) should catch this every window.
        for i in 0..20 {
            let metrics = AggregatedMetrics {
                ib_counter_deltas: IbCounterDeltas {
                    rxe_duplicate_request_delta: 20_000,
                    rxe_seq_error_delta: 20_000,
                    hw_rcv_pkts_delta: 100_000,
                    hw_xmit_pkts_delta: 100_000,
                    ..Default::default()
                },
                ..Default::default()
            };
            let result = rule.evaluate_mut(&metrics);
            assert!(
                result.is_some(),
                "window {i}: 20% error rate should always alert (absolute ceiling)"
            );
        }
    }

    #[test]
    fn link_degradation_ewma_clamped_keeps_detecting() {
        let mut rule = RdmaLinkDegradationRule::new(3.0, 5);
        // Warm up
        for _ in 0..10 {
            let metrics = AggregatedMetrics {
                ib_counter_deltas: IbCounterDeltas {
                    symbol_error_delta: 1,
                    port_rcv_data_delta: 1_000_000,
                    port_xmit_data_delta: 1_000_000,
                    ..Default::default()
                },
                ..Default::default()
            };
            rule.evaluate_mut(&metrics);
        }

        // Sustained elevated errors (above budget). Because the EWMA is clamped,
        // the z-score should remain high even after many windows.
        let mut alert_count = 0;
        for _ in 0..30 {
            let metrics = AggregatedMetrics {
                ib_counter_deltas: IbCounterDeltas {
                    symbol_error_delta: 100,
                    port_rcv_data_delta: 1_000_000,
                    port_xmit_data_delta: 1_000_000,
                    ..Default::default()
                },
                ..Default::default()
            };
            if rule.evaluate_mut(&metrics).is_some() {
                alert_count += 1;
            }
        }
        assert!(
            alert_count >= 25,
            "clamped EWMA should keep alerting on sustained errors, got {alert_count}/30"
        );
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

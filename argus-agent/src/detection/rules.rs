use argus_common::{AggregatedMetrics, Alert, AlertKind, HealthState};

/// A detection rule evaluates aggregated metrics and optionally produces an alert.
pub trait DetectionRule: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, metrics: &AggregatedMetrics) -> Option<Alert>;
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
            parts.push(format!("link_integ+{}", d.local_link_integrity_errors_delta));
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

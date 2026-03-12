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
                message: format!(
                    "RDMA latency spike: {avg_latency}ns ({ratio:.1}x baseline)"
                ),
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Slab Pressure Correlation: slab latency spike + CQ backlog
// ---------------------------------------------------------------------------

pub struct SlabPressureRule {
    pub slab_spike_factor: f64,
    pub slab_baseline_ns: u64,
    pub min_allocs: u64,
}

impl Default for SlabPressureRule {
    fn default() -> Self {
        Self {
            slab_spike_factor: 5.0,
            slab_baseline_ns: 500,
            min_allocs: 10,
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

        let avg_latency = slab.avg_latency_ns();
        let threshold = (self.slab_baseline_ns as f64 * self.slab_spike_factor) as u64;

        if avg_latency >= threshold {
            let rdma_backlog = metrics.rdma_metrics.completion_count;
            Some(Alert {
                timestamp_ns: metrics.window_end_ns,
                kind: AlertKind::SlabPressureCorrelation {
                    slab_latency_ns: avg_latency,
                    slab_baseline_ns: self.slab_baseline_ns,
                    cq_backlog: rdma_backlog,
                },
                severity: if avg_latency >= (self.slab_baseline_ns as f64 * 10.0) as u64 {
                    HealthState::Critical
                } else {
                    HealthState::Degraded
                },
                message: format!(
                    "Slab pressure: avg latency {avg_latency}ns (baseline {}ns), CQ backlog: {rdma_backlog}",
                    self.slab_baseline_ns
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
    use argus_common::{InterruptDistribution, RdmaMetrics, SlabMetrics};

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
    fn slab_pressure_below_threshold() {
        let rule = SlabPressureRule::default();
        let metrics = AggregatedMetrics {
            slab_metrics: SlabMetrics {
                alloc_count: 100,
                total_latency_ns: 50_000,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(rule.evaluate(&metrics).is_none());
    }

    #[test]
    fn slab_pressure_above_threshold() {
        let rule = SlabPressureRule::default();
        let metrics = AggregatedMetrics {
            slab_metrics: SlabMetrics {
                alloc_count: 100,
                total_latency_ns: 300_000,
                ..Default::default()
            },
            ..Default::default()
        };
        let alert = rule.evaluate(&metrics).unwrap();
        assert_eq!(alert.severity, HealthState::Degraded);
    }
}

pub mod rolling_stats;
pub mod rules;

use argus_common::{AggregatedMetrics, Alert, HealthState};
use rules::{
    DetectionRule, InterruptAffinitySkewRule, LatencyDriftRule, NapiSaturationRule,
    RdmaLatencySpikeRule, RdmaLinkDegradationRule, RisingErrorTrendRule, SlabPressureRule,
    ThroughputDropRule,
};

use crate::config::DetectionConfig;

/// Evaluates aggregated metrics against detection rules and maintains health state.
/// Implements hysteresis: requires N consecutive windows above threshold to transition
/// to Degraded/Critical, and M clean windows to return to Healthy.
pub struct DetectionEngine {
    rules: Vec<Box<dyn DetectionRule>>,
    current_state: HealthState,
    consecutive_degraded: u32,
    consecutive_healthy: u32,
    degraded_threshold: u32,
    healthy_threshold: u32,
}

impl DetectionEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(&DetectionConfig::default())
    }

    /// How many consecutive degraded windows before transitioning state.
    const DEFAULT_DEGRADED_THRESHOLD: u32 = 2;
    /// How many consecutive clean windows before returning to healthy.
    const DEFAULT_HEALTHY_THRESHOLD: u32 = 2;

    #[must_use]
    pub fn with_config(config: &DetectionConfig) -> Self {
        Self {
            rules: vec![
                // Reactive rules (threshold-based)
                Box::new(InterruptAffinitySkewRule {
                    threshold_pct: config.irq_skew_threshold_pct,
                    num_cpus: config.num_cpus,
                }),
                Box::new(RdmaLatencySpikeRule {
                    spike_factor: config.rdma_spike_factor,
                    baseline_latency_ns: config.rdma_baseline_latency_ns,
                    min_completions: 10,
                }),
                Box::new(RdmaLinkDegradationRule::default()),
                Box::new(SlabPressureRule {
                    min_allocs: config.slab_pressure_min_allocs,
                    alloc_rate_threshold: config.slab_pressure_alloc_rate_threshold,
                }),
                // Predictive rules (trend/EWMA-based)
                Box::new(RisingErrorTrendRule::default()),
                Box::new(LatencyDriftRule::default()),
                Box::new(ThroughputDropRule::default()),
                Box::new(NapiSaturationRule::default()),
            ],
            current_state: HealthState::Healthy,
            consecutive_degraded: 0,
            consecutive_healthy: 0,
            degraded_threshold: Self::DEFAULT_DEGRADED_THRESHOLD,
            healthy_threshold: Self::DEFAULT_HEALTHY_THRESHOLD,
        }
    }

    /// Evaluate all rules against current metrics.
    /// Uses hysteresis: requires N consecutive windows with alerts before
    /// transitioning, and M clean windows before returning to Healthy.
    pub fn evaluate(&mut self, metrics: &AggregatedMetrics) -> Vec<Alert> {
        let mut new_alerts = Vec::new();
        let mut worst_state = HealthState::Healthy;

        for rule in &mut self.rules {
            if let Some(alert) = rule.evaluate_mut(metrics) {
                if severity_rank(alert.severity) > severity_rank(worst_state) {
                    worst_state = alert.severity;
                }
                new_alerts.push(alert);
            }
        }

        // Hysteresis logic
        if severity_rank(worst_state) > severity_rank(HealthState::Healthy) {
            self.consecutive_degraded += 1;
            self.consecutive_healthy = 0;
        } else {
            self.consecutive_healthy += 1;
            self.consecutive_degraded = 0;
        }

        let previous = self.current_state;

        // Transition to worse state: require consecutive_degraded >= threshold
        if severity_rank(worst_state) > severity_rank(previous)
            && self.consecutive_degraded >= self.degraded_threshold
        {
            self.current_state = worst_state;
        }
        // Transition to better state: require consecutive_healthy >= threshold
        else if severity_rank(worst_state) < severity_rank(previous)
            && self.consecutive_healthy >= self.healthy_threshold
        {
            self.current_state = worst_state;
        }
        // Same severity level: update in case it changed within the same tier
        else if severity_rank(worst_state) == severity_rank(previous) {
            self.current_state = worst_state;
        }

        if self.current_state != previous {
            new_alerts
        } else {
            vec![]
        }
    }

    #[must_use]
    pub fn current_state(&self) -> HealthState {
        self.current_state
    }

    /// Compute a composite health score (0.0 = healthy, 1.0 = critical).
    /// Weights multiple signals for a more nuanced view than discrete states.
    #[must_use]
    pub fn compute_health_score(metrics: &AggregatedMetrics, num_cpus: u32) -> f64 {
        let mut score = 0.0_f64;

        // IRQ skew component (0..0.3) — scaled by CPU count
        let irq_pct = metrics.interrupt_distribution.dominant_cpu_pct();
        let perfect_share = 100.0 / num_cpus.max(1) as f64;
        let irq_baseline = perfect_share + 20.0;
        if irq_pct > irq_baseline {
            score += ((irq_pct - irq_baseline) / (100.0 - irq_baseline)).min(1.0) * 0.3;
        }

        // Hard IB error component (0..0.35) — only real hardware errors
        let hard_errors = metrics.ib_counter_deltas.total_hard_error_delta();
        if hard_errors > 0 {
            score += (hard_errors as f64 / 50.0).min(1.0) * 0.25;
        }
        if metrics.ib_counter_deltas.link_downed_delta > 0 {
            score += 0.1;
        }

        // Slab pressure component (0..0.15)
        let slab_latency = metrics.slab_metrics.avg_latency_ns();
        if slab_latency > 1000 {
            score += ((slab_latency as f64 - 1000.0) / 10000.0).min(1.0) * 0.15;
        }

        // NAPI saturation component (0..0.2)
        if metrics.network_metrics.napi_polls > 0 && metrics.network_metrics.napi_total_budget > 0 {
            let avg_work = metrics.network_metrics.napi_total_work as f64
                / metrics.network_metrics.napi_polls as f64;
            let avg_budget = metrics.network_metrics.napi_total_budget as f64
                / metrics.network_metrics.napi_polls as f64;
            if avg_budget > 0.0 {
                let util = avg_work / avg_budget;
                if util > 0.7 {
                    score += ((util - 0.7) / 0.3).min(1.0) * 0.2;
                }
            }
        }

        score.min(1.0)
    }

    pub fn reset(&mut self) {
        self.current_state = HealthState::Healthy;
        self.consecutive_degraded = 0;
        self.consecutive_healthy = 0;
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn severity_rank(state: HealthState) -> u8 {
    match state {
        HealthState::Healthy => 0,
        HealthState::Degraded => 1,
        HealthState::Critical => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::InterruptDistribution;

    /// Helper: evaluate N times for hysteresis to kick in.
    fn evaluate_n(engine: &mut DetectionEngine, metrics: &AggregatedMetrics, n: u32) -> Vec<Alert> {
        let mut last = vec![];
        for _ in 0..n {
            last = engine.evaluate(metrics);
        }
        last
    }

    #[test]
    fn healthy_metrics_produce_no_alerts() {
        let mut engine = DetectionEngine::new();
        let metrics = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![25, 25, 25, 25],
                total_count: 100,
            },
            ..Default::default()
        };
        let alerts = engine.evaluate(&metrics);
        assert!(alerts.is_empty());
        assert_eq!(engine.current_state(), HealthState::Healthy);
    }

    #[test]
    fn skewed_interrupts_trigger_alert_after_hysteresis() {
        let mut engine = DetectionEngine::new();
        let metrics = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![80, 10, 5, 5],
                total_count: 100,
            },
            ..Default::default()
        };
        // First evaluation: hysteresis not yet met
        let first = engine.evaluate(&metrics);
        assert!(
            first.is_empty(),
            "single window should not trigger due to hysteresis"
        );
        assert_eq!(engine.current_state(), HealthState::Healthy);

        // Second evaluation: hysteresis met
        let second = engine.evaluate(&metrics);
        assert!(
            !second.is_empty(),
            "second consecutive window should trigger"
        );
        assert_eq!(engine.current_state(), HealthState::Degraded);
    }

    #[test]
    fn reset_returns_to_healthy() {
        let mut engine = DetectionEngine::new();
        let metrics = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![80, 10, 5, 5],
                total_count: 100,
            },
            ..Default::default()
        };
        evaluate_n(&mut engine, &metrics, 2);
        engine.reset();
        assert_eq!(engine.current_state(), HealthState::Healthy);
    }

    #[test]
    fn repeated_degraded_deduplicates() {
        let mut engine = DetectionEngine::new();
        let metrics = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![80, 10, 5, 5],
                total_count: 100,
            },
            ..Default::default()
        };

        let alerts = evaluate_n(&mut engine, &metrics, 2);
        assert!(!alerts.is_empty(), "transition should emit alerts");

        // Third eval at same state: should not re-emit
        let third = engine.evaluate(&metrics);
        assert!(third.is_empty(), "same state should not re-emit alerts");

        engine.reset();
        let after_reset = evaluate_n(&mut engine, &metrics, 2);
        assert!(
            !after_reset.is_empty(),
            "alert fires again after reset + hysteresis"
        );
    }
}

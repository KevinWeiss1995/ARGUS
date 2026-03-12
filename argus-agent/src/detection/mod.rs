pub mod rules;

use argus_common::{AggregatedMetrics, Alert, HealthState};
use rules::{DetectionRule, InterruptAffinitySkewRule, RdmaLatencySpikeRule, SlabPressureRule};

/// Evaluates aggregated metrics against detection rules and maintains health state.
pub struct DetectionEngine {
    rules: Vec<Box<dyn DetectionRule>>,
    current_state: HealthState,
}

impl DetectionEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: vec![
                Box::new(InterruptAffinitySkewRule::default()),
                Box::new(RdmaLatencySpikeRule::default()),
                Box::new(SlabPressureRule::default()),
            ],
            current_state: HealthState::Healthy,
        }
    }

    /// Evaluate all rules against current metrics.
    /// Only returns alerts when the overall health state transitions (e.g. Healthy -> Degraded),
    /// preventing floods of identical alerts while the condition persists.
    pub fn evaluate(&mut self, metrics: &AggregatedMetrics) -> Vec<Alert> {
        let mut new_alerts = Vec::new();
        let mut worst_state = HealthState::Healthy;

        for rule in &self.rules {
            if let Some(alert) = rule.evaluate(metrics) {
                if severity_rank(alert.severity) > severity_rank(worst_state) {
                    worst_state = alert.severity;
                }
                new_alerts.push(alert);
            }
        }

        let previous = self.current_state;
        self.current_state = worst_state;

        if worst_state != previous {
            new_alerts
        } else {
            vec![]
        }
    }

    #[must_use]
    pub fn current_state(&self) -> HealthState {
        self.current_state
    }

    pub fn reset(&mut self) {
        self.current_state = HealthState::Healthy;
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
    fn skewed_interrupts_trigger_alert() {
        let mut engine = DetectionEngine::new();
        let metrics = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![80, 10, 5, 5],
                total_count: 100,
            },
            ..Default::default()
        };
        let alerts = engine.evaluate(&metrics);
        assert!(!alerts.is_empty());
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
        engine.evaluate(&metrics);
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

        let first = engine.evaluate(&metrics);
        assert!(!first.is_empty(), "first transition should emit alerts");

        let second = engine.evaluate(&metrics);
        assert!(second.is_empty(), "same state should not re-emit alerts");

        engine.reset();
        let after_reset = engine.evaluate(&metrics);
        assert!(!after_reset.is_empty(), "alert fires again after window reset");
    }
}

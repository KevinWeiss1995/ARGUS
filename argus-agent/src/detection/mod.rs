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

    /// Evaluate all rules against current metrics. Returns any new alerts.
    pub fn evaluate(&mut self, metrics: &AggregatedMetrics) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let mut worst_state = HealthState::Healthy;

        for rule in &self.rules {
            if let Some(alert) = rule.evaluate(metrics) {
                if severity_rank(alert.severity) > severity_rank(worst_state) {
                    worst_state = alert.severity;
                }
                alerts.push(alert);
            }
        }

        self.current_state = worst_state;
        alerts
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
}

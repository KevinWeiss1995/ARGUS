pub mod prometheus;

use argus_common::Alert;
use std::collections::VecDeque;

/// Collects alerts and metrics for external consumption.
/// Uses a bounded VecDeque so oldest-first eviction is O(1) even at high
/// `max_alerts`, versus the O(N) cost of `Vec::remove(0)`.
pub struct TelemetryCollector {
    recent_alerts: VecDeque<Alert>,
    max_alerts: usize,
}

impl TelemetryCollector {
    #[must_use]
    pub fn new(max_alerts: usize) -> Self {
        Self {
            recent_alerts: VecDeque::with_capacity(max_alerts),
            max_alerts,
        }
    }

    pub fn record_alert(&mut self, alert: Alert) {
        if self.recent_alerts.len() >= self.max_alerts {
            self.recent_alerts.pop_front();
        }
        self.recent_alerts.push_back(alert);
    }

    /// Snapshot of retained alerts in chronological order.
    #[must_use]
    pub fn recent_alerts(&self) -> Vec<Alert> {
        self.recent_alerts.iter().cloned().collect()
    }

    pub fn clear(&mut self) {
        self.recent_alerts.clear();
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self {
        Self::new(1000)
    }
}

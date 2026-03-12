pub mod prometheus;

use argus_common::Alert;

/// Collects alerts and metrics for external consumption.
pub struct TelemetryCollector {
    recent_alerts: Vec<Alert>,
    max_alerts: usize,
}

impl TelemetryCollector {
    #[must_use]
    pub fn new(max_alerts: usize) -> Self {
        Self {
            recent_alerts: Vec::new(),
            max_alerts,
        }
    }

    pub fn record_alert(&mut self, alert: Alert) {
        self.recent_alerts.push(alert);
        if self.recent_alerts.len() > self.max_alerts {
            self.recent_alerts.remove(0);
        }
    }

    #[must_use]
    pub fn recent_alerts(&self) -> &[Alert] {
        &self.recent_alerts
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

//! Autonomous response engine for ARGUS.
//!
//! When the detection engine fires a critical alert, configured action handlers
//! can take automated responses: webhook notifications, SLURM node draining,
//! or port disabling. All actions are opt-in, rate-limited, and audit-logged.
//!
//! # Safety
//! Actions that affect node state (drain, port-disable) require explicit CLI
//! flags and cannot be triggered without operator consent. A dry-run mode
//! is available for testing. All actions are logged to an audit trail.

use argus_common::Alert;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::sources::process_resolver::BlastRadius;

/// Trait for autonomous response handlers.
pub trait ActionHandler: Send + Sync {
    fn name(&self) -> &str;
    fn on_alert(&self, alert: &Alert, blast_radius: &BlastRadius) -> Result<(), String>;
}

/// Configuration for the action engine, parsed from CLI.
/// Note: SLURM drain is now handled by the scheduler module (state-driven
/// reconciliation), not by the fire-and-forget action system.
#[derive(Debug, Clone, Default)]
pub struct ActionConfig {
    pub webhook_url: Option<String>,
    pub port_disable: bool,
    pub dry_run: bool,
}

/// Central action dispatcher with rate limiting and audit logging.
pub struct ActionEngine {
    handlers: Vec<Box<dyn ActionHandler>>,
    rate_limit: Duration,
    last_action: Option<Instant>,
    dry_run: bool,
    audit_log: VecDeque<AuditEntry>,
    audit_log_capacity: usize,
}

/// Cap on retained audit entries before FIFO eviction.
/// At one alert/sec, this holds ~2.7 hours of audit history.
const DEFAULT_AUDIT_LOG_CAPACITY: usize = 10_000;

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: Instant,
    pub handler: String,
    pub alert_kind: String,
    pub result: String,
    pub dry_run: bool,
}

impl ActionEngine {
    pub fn from_config(config: &ActionConfig) -> Self {
        let mut handlers: Vec<Box<dyn ActionHandler>> = Vec::new();

        // Log action is always enabled
        handlers.push(Box::new(LogAction));

        if let Some(ref url) = config.webhook_url {
            handlers.push(Box::new(WebhookAction { url: url.clone() }));
        }

        if config.port_disable {
            handlers.push(Box::new(PortDisableAction));
        }

        Self {
            handlers,
            rate_limit: Duration::from_secs(60),
            last_action: None,
            dry_run: config.dry_run,
            audit_log: VecDeque::with_capacity(DEFAULT_AUDIT_LOG_CAPACITY),
            audit_log_capacity: DEFAULT_AUDIT_LOG_CAPACITY,
        }
    }

    /// Dispatch an alert to all configured handlers, respecting rate limiting.
    pub fn dispatch(&mut self, alert: &Alert, blast_radius: &BlastRadius) {
        if let Some(last) = self.last_action {
            let elapsed = last.elapsed();
            if elapsed < self.rate_limit {
                let remaining = self
                    .rate_limit
                    .checked_sub(elapsed)
                    .unwrap_or(Duration::ZERO);
                debug!(
                    alert = alert.kind_name(),
                    severity = %alert.severity,
                    remaining_ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
                    "action engine rate-limited: dropping alert"
                );
                return;
            }
        }

        let now = Instant::now();
        self.last_action = Some(now);

        for handler in &self.handlers {
            let result = if self.dry_run {
                info!(
                    handler = handler.name(),
                    alert = alert.kind_name(),
                    "[DRY RUN] would execute action"
                );
                Ok(())
            } else {
                handler.on_alert(alert, blast_radius)
            };

            let entry = AuditEntry {
                timestamp: now,
                handler: handler.name().into(),
                alert_kind: alert.kind_name().into(),
                result: match &result {
                    Ok(()) => "ok".into(),
                    Err(e) => format!("error: {e}"),
                },
                dry_run: self.dry_run,
            };
            if self.audit_log.len() >= self.audit_log_capacity {
                self.audit_log.pop_front();
            }
            self.audit_log.push_back(entry);

            if let Err(e) = result {
                warn!(handler = handler.name(), "action failed: {e}");
            }
        }
    }

    /// Returns the most recent audit entries in chronological order.
    #[must_use]
    pub fn audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.iter().cloned().collect()
    }

    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }
}

// ---------------------------------------------------------------------------
// Built-in action handlers
// ---------------------------------------------------------------------------

/// Always-on structured logging of actions.
struct LogAction;

impl ActionHandler for LogAction {
    fn name(&self) -> &str {
        "log"
    }

    fn on_alert(&self, alert: &Alert, blast_radius: &BlastRadius) -> Result<(), String> {
        info!(
            kind = alert.kind_name(),
            severity = %alert.severity,
            message = %alert.message,
            affected = blast_radius.summary(),
            "ARGUS action: alert"
        );
        Ok(())
    }
}

/// POST alert JSON to a configurable webhook URL (PagerDuty, Slack, custom).
struct WebhookAction {
    url: String,
}

impl ActionHandler for WebhookAction {
    fn name(&self) -> &str {
        "webhook"
    }

    fn on_alert(&self, alert: &Alert, blast_radius: &BlastRadius) -> Result<(), String> {
        let payload = serde_json::json!({
            "source": "argus",
            "severity": alert.severity.to_string(),
            "kind": alert.kind_name(),
            "message": alert.message,
            "affected": blast_radius.summary(),
            "timestamp_ns": alert.timestamp_ns,
        });

        // Use a blocking HTTP client to avoid async in the action path.
        // In production, this would use reqwest or ureq.
        // For now, we shell out to curl for simplicity and zero extra deps.
        let json_str = serde_json::to_string(&payload).map_err(|e| e.to_string())?;

        let output = std::process::Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                &json_str,
                "--max-time",
                "5",
                &self.url,
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/usr/local/bin")
            .output()
            .map_err(|e| format!("curl failed: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("webhook POST failed: {stderr}"));
        }

        info!(url = %self.url, "webhook delivered");
        Ok(())
    }
}

/// Disable an IB port via sysfs admin_state. Requires --action-port-disable.
///
/// SAFETY: `AlertKind::RdmaLinkDegradation` currently aggregates counter deltas
/// across all ports on this node and does NOT identify which port degraded.
/// To avoid taking down healthy unrelated fabric links on multi-port nodes,
/// this handler only acts when the node has exactly one IB port. On nodes
/// with 0 or >1 ports it logs and declines to act.
struct PortDisableAction;

impl PortDisableAction {
    /// Return Some(admin_state_path) if exactly one IB port is present.
    fn sole_port() -> Result<std::path::PathBuf, String> {
        let ib_path = std::path::Path::new("/sys/class/infiniband");
        let devices = std::fs::read_dir(ib_path)
            .map_err(|e| format!("read /sys/class/infiniband: {e}"))?;

        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        for device in devices.flatten() {
            let ports_dir = device.path().join("ports");
            let ports = match std::fs::read_dir(&ports_dir) {
                Ok(p) => p,
                Err(_) => continue,
            };
            for port in ports.flatten() {
                let admin_state = port.path().join("admin_state");
                if admin_state.exists() {
                    candidates.push(admin_state);
                }
            }
        }

        match candidates.len() {
            0 => Err("no IB ports with admin_state found".into()),
            1 => Ok(candidates.pop().unwrap()),
            n => Err(format!(
                "{n} IB ports present; refusing to disable — AlertKind does not \
                 identify the affected port"
            )),
        }
    }
}

impl ActionHandler for PortDisableAction {
    fn name(&self) -> &str {
        "port_disable"
    }

    fn on_alert(&self, alert: &Alert, _blast_radius: &BlastRadius) -> Result<(), String> {
        if alert.severity != argus_common::HealthState::Critical {
            return Ok(());
        }

        if let argus_common::AlertKind::RdmaLinkDegradation {
            link_downed_delta, ..
        } = &alert.kind
        {
            if *link_downed_delta == 0 {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        let admin_state = Self::sole_port()?;
        std::fs::write(&admin_state, "0")
            .map_err(|e| format!("write {}: {e}", admin_state.display()))?;
        info!(path = %admin_state.display(), "IB port disabled");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::{AlertKind, HealthState};

    fn make_alert(severity: HealthState) -> Alert {
        Alert {
            timestamp_ns: 1_000_000_000,
            kind: AlertKind::RdmaLinkDegradation {
                symbol_error_delta: 10,
                link_downed_delta: 1,
                rcv_error_delta: 0,
                xmit_discard_delta: 0,
            },
            severity,
            message: "test alert".into(),
        }
    }

    #[test]
    fn action_engine_from_default_config() {
        let config = ActionConfig::default();
        let engine = ActionEngine::from_config(&config);
        // LogAction is always present
        assert_eq!(engine.handler_count(), 1);
    }

    #[test]
    fn action_engine_with_all_handlers() {
        let config = ActionConfig {
            webhook_url: Some("http://example.com/hook".into()),
            port_disable: true,
            dry_run: true,
        };
        let engine = ActionEngine::from_config(&config);
        assert_eq!(engine.handler_count(), 3);
    }

    #[test]
    fn dry_run_does_not_execute() {
        let config = ActionConfig {
            dry_run: true,
            ..Default::default()
        };
        let mut engine = ActionEngine::from_config(&config);
        let alert = make_alert(HealthState::Critical);
        let blast = BlastRadius::default();

        engine.dispatch(&alert, &blast);
        assert_eq!(engine.audit_log().len(), 1);
        assert!(engine.audit_log()[0].dry_run);
    }

    #[test]
    fn rate_limiting_skips_rapid_fire() {
        let config = ActionConfig::default();
        let mut engine = ActionEngine::from_config(&config);
        let alert = make_alert(HealthState::Critical);
        let blast = BlastRadius::default();

        engine.dispatch(&alert, &blast);
        engine.dispatch(&alert, &blast);
        // Second dispatch should be rate-limited
        assert_eq!(engine.audit_log().len(), 1);
    }
}

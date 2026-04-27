use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

use tracing::debug;

use super::{NodeStateReport, ObservedNodeState, SchedulerBackend, SchedulerError};

const ARGUS_REASON_PREFIX: &str = "ARGUS:";

pub struct SlurmBackend {
    scontrol_path: PathBuf,
}

impl SlurmBackend {
    pub fn new() -> Self {
        Self {
            scontrol_path: PathBuf::from("/usr/bin/scontrol"),
        }
    }

    fn run_scontrol(&self, args: &[&str]) -> Result<String, SchedulerError> {
        let output = Command::new(&self.scontrol_path)
            .args(args)
            .env("SLURM_TIME_FORMAT", "standard")
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    SchedulerError::Unreachable(format!(
                        "scontrol not found at {}",
                        self.scontrol_path.display()
                    ))
                } else {
                    SchedulerError::CommandFailed(format!("scontrol exec error: {e}"))
                }
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.contains("Invalid node name") || stderr.contains("not found") {
                return Err(SchedulerError::NodeNotFound {
                    node: args.last().unwrap_or(&"?").to_string(),
                });
            }
            if stderr.contains("Access denied") || stderr.contains("Permission denied") {
                return Err(SchedulerError::PermissionDenied(stderr));
            }
            return Err(SchedulerError::CommandFailed(format!(
                "scontrol exit {}: {stderr}",
                output.status.code().unwrap_or(-1)
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl Default for SlurmBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedulerBackend for SlurmBackend {
    fn name(&self) -> &str {
        "slurm"
    }

    fn get_node_state(&self, node: &str) -> Result<NodeStateReport, SchedulerError> {
        let output = self.run_scontrol(&["show", "node", node, "-o"])?;

        let state_raw = extract_field(&output, "State=").ok_or_else(|| {
            SchedulerError::UnexpectedState(format!(
                "no State= field in scontrol output for {node}"
            ))
        })?;

        let reason = extract_field(&output, "Reason=");

        let responsive = !state_raw.contains('*');
        let state = parse_slurm_state(&state_raw);
        let managed_by_self = reason
            .as_ref()
            .map_or(false, |r| r.starts_with(ARGUS_REASON_PREFIX));

        debug!(
            node,
            state_raw,
            ?state,
            reason = reason.as_deref().unwrap_or("none"),
            managed_by_self,
            responsive,
            "parsed SLURM node state"
        );

        Ok(NodeStateReport {
            state,
            reason,
            managed_by_self,
            responsive,
        })
    }

    fn drain_node(&self, node: &str, reason: &str) -> Result<(), SchedulerError> {
        let full_reason = if reason.starts_with(ARGUS_REASON_PREFIX) {
            reason.to_string()
        } else {
            format!("{ARGUS_REASON_PREFIX} {reason}")
        };
        self.run_scontrol(&[
            "update",
            &format!("NodeName={node}"),
            "State=DRAIN",
            &format!("Reason={full_reason}"),
        ])?;
        Ok(())
    }

    fn resume_node(&self, node: &str) -> Result<(), SchedulerError> {
        self.run_scontrol(&["update", &format!("NodeName={node}"), "State=RESUME"])?;
        Ok(())
    }
}

/// Extract a field value from scontrol one-line output.
/// Handles both space-delimited and quoted values.
fn extract_field(output: &str, field: &str) -> Option<String> {
    let start = output.find(field)? + field.len();
    let rest = &output[start..];
    let end = rest.find(' ').unwrap_or(rest.len());
    let value = rest[..end].trim().to_string();
    if value.is_empty() || value == "(null)" {
        None
    } else {
        Some(value)
    }
}

/// Parse SLURM compound state into ObservedNodeState (M3 fix).
///
/// Real SLURM states are compound: `IDLE+DRAIN`, `MIXED+DRAIN`, `DOWN*+DRAIN`.
/// The `*` suffix means "not responding." We split on `+`, check components,
/// and prioritize: DOWN > DRAIN > active states.
pub fn parse_slurm_state(raw: &str) -> ObservedNodeState {
    let clean = raw.replace('*', "");
    let components: HashSet<&str> = clean.split('+').map(str::trim).collect();

    if components.contains("DOWN") {
        return ObservedNodeState::Down;
    }

    if components.contains("DRAINING") {
        return ObservedNodeState::Draining;
    }

    if components.contains("DRAINED") {
        return ObservedNodeState::Drained;
    }

    if components.contains("DRAIN") {
        let has_running = components.iter().any(|c| {
            matches!(*c, "ALLOC" | "ALLOCATED" | "MIXED" | "COMPLETING")
        });
        return if has_running {
            ObservedNodeState::Draining
        } else {
            ObservedNodeState::Drained
        };
    }

    if components
        .iter()
        .any(|c| matches!(*c, "IDLE" | "ALLOC" | "ALLOCATED" | "MIXED" | "COMPLETING"))
    {
        return ObservedNodeState::Available;
    }

    ObservedNodeState::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_idle() {
        assert_eq!(parse_slurm_state("IDLE"), ObservedNodeState::Available);
    }

    #[test]
    fn parse_alloc() {
        assert_eq!(parse_slurm_state("ALLOC"), ObservedNodeState::Available);
        assert_eq!(parse_slurm_state("ALLOCATED"), ObservedNodeState::Available);
    }

    #[test]
    fn parse_mixed() {
        assert_eq!(parse_slurm_state("MIXED"), ObservedNodeState::Available);
    }

    #[test]
    fn parse_completing() {
        assert_eq!(parse_slurm_state("COMPLETING"), ObservedNodeState::Available);
    }

    #[test]
    fn parse_idle_drain() {
        assert_eq!(parse_slurm_state("IDLE+DRAIN"), ObservedNodeState::Drained);
    }

    #[test]
    fn parse_mixed_drain() {
        assert_eq!(parse_slurm_state("MIXED+DRAIN"), ObservedNodeState::Draining);
    }

    #[test]
    fn parse_alloc_drain() {
        assert_eq!(parse_slurm_state("ALLOC+DRAIN"), ObservedNodeState::Draining);
    }

    #[test]
    fn parse_allocated_completing() {
        assert_eq!(
            parse_slurm_state("ALLOCATED+COMPLETING"),
            ObservedNodeState::Available
        );
    }

    #[test]
    fn parse_down() {
        assert_eq!(parse_slurm_state("DOWN"), ObservedNodeState::Down);
    }

    #[test]
    fn parse_down_star() {
        assert_eq!(parse_slurm_state("DOWN*"), ObservedNodeState::Down);
    }

    #[test]
    fn parse_down_star_drain() {
        assert_eq!(parse_slurm_state("DOWN*+DRAIN"), ObservedNodeState::Down);
    }

    #[test]
    fn parse_drained() {
        assert_eq!(parse_slurm_state("DRAINED"), ObservedNodeState::Drained);
    }

    #[test]
    fn parse_draining() {
        assert_eq!(parse_slurm_state("DRAINING"), ObservedNodeState::Draining);
    }

    #[test]
    fn parse_unknown_state() {
        assert_eq!(parse_slurm_state("FUTURE"), ObservedNodeState::Unknown);
    }

    #[test]
    fn asterisk_means_unresponsive() {
        let raw = "DOWN*";
        assert!(raw.contains('*'));
        let state = parse_slurm_state(raw);
        assert_eq!(state, ObservedNodeState::Down);
    }

    #[test]
    fn extract_state_field() {
        let line = "NodeName=node07 Arch=x86_64 CoresPerSocket=2 CPUAlloc=0 State=IDLE+DRAIN Reason=ARGUS: health=CRITICAL";
        let state = extract_field(line, "State=");
        assert_eq!(state, Some("IDLE+DRAIN".to_string()));
    }

    #[test]
    fn extract_reason_field() {
        let line = "NodeName=node07 State=IDLE+DRAIN Reason=ARGUS: health=CRITICAL";
        let reason = extract_field(line, "Reason=");
        assert_eq!(reason, Some("ARGUS:".to_string()));
    }

    #[test]
    fn extract_null_reason() {
        let line = "NodeName=node07 State=IDLE Reason=(null)";
        let reason = extract_field(line, "Reason=");
        assert_eq!(reason, None);
    }

    #[test]
    fn managed_by_self_detection() {
        let reason = Some("ARGUS: health=CRITICAL".to_string());
        assert!(reason
            .as_ref()
            .map_or(false, |r| r.starts_with(ARGUS_REASON_PREFIX)));

        let reason2 = Some("maintenance window".to_string());
        assert!(!reason2
            .as_ref()
            .map_or(false, |r| r.starts_with(ARGUS_REASON_PREFIX)));
    }
}

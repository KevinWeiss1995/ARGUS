//! Discover available kernel functions for kprobe attachment via /proc/kallsyms.
//!
//! The RDMA CQ jitter probe needs to kprobe driver-specific functions (mlx5 or rxe).
//! This module scans kallsyms at startup to determine which functions are available,
//! allowing graceful degradation when neither is present.

use std::collections::HashSet;

/// Resolved kprobe targets for CQ jitter measurement.
#[derive(Debug, Clone)]
pub struct KprobeTargets {
    /// Function to kprobe for WR submission (captures submit timestamp).
    pub wr_submit: Option<String>,
    /// Function to kprobe for CQ poll (computes completion latency).
    pub cq_poll: Option<String>,
}

impl KprobeTargets {
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.wr_submit.is_some() && self.cq_poll.is_some()
    }

    #[must_use]
    pub fn driver_name(&self) -> &str {
        if let Some(ref f) = self.cq_poll {
            if f.starts_with("mlx5") {
                return "mlx5";
            }
            if f.starts_with("rxe") {
                return "rxe";
            }
        }
        "unknown"
    }
}

/// Preferred kprobe targets, ordered by priority (mlx5 first, rxe fallback).
const SUBMIT_CANDIDATES: &[&str] = &["mlx5_ib_post_send", "rxe_post_send"];
const POLL_CANDIDATES: &[&str] = &["mlx5_ib_poll_cq", "rxe_poll_cq"];

/// Scan /proc/kallsyms and resolve kprobe targets.
/// Returns targets with the highest-priority available functions.
pub fn discover_kprobe_targets() -> KprobeTargets {
    let available = read_kallsyms_functions();

    let wr_submit = SUBMIT_CANDIDATES
        .iter()
        .find(|&&f| available.contains(f))
        .map(|&s| s.to_string());

    let cq_poll = POLL_CANDIDATES
        .iter()
        .find(|&&f| available.contains(f))
        .map(|&s| s.to_string());

    if let (Some(ref submit), Some(ref poll)) = (&wr_submit, &cq_poll) {
        tracing::info!(submit, poll, "CQ jitter kprobe targets resolved");
    } else {
        tracing::info!(
            ?wr_submit,
            ?cq_poll,
            "CQ jitter kprobes not fully available — micro-stall detection disabled"
        );
    }

    KprobeTargets { wr_submit, cq_poll }
}

fn read_kallsyms_functions() -> HashSet<String> {
    let mut funcs = HashSet::new();

    let content = match std::fs::read_to_string("/proc/kallsyms") {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("cannot read /proc/kallsyms: {e}");
            return funcs;
        }
    };

    for line in content.lines() {
        // Format: "address type name [module]"
        let mut parts = line.split_whitespace();
        let _addr = parts.next();
        let sym_type = parts.next().unwrap_or("");
        let name = parts.next().unwrap_or("");

        // Only consider text (function) symbols
        if matches!(sym_type, "t" | "T") && !name.is_empty() {
            funcs.insert(name.to_string());
        }
    }

    funcs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_available_when_both_present() {
        let t = KprobeTargets {
            wr_submit: Some("mlx5_ib_post_send".into()),
            cq_poll: Some("mlx5_ib_poll_cq".into()),
        };
        assert!(t.is_available());
        assert_eq!(t.driver_name(), "mlx5");
    }

    #[test]
    fn targets_unavailable_when_partial() {
        let t = KprobeTargets {
            wr_submit: Some("mlx5_ib_post_send".into()),
            cq_poll: None,
        };
        assert!(!t.is_available());
    }

    #[test]
    fn rxe_driver_detected() {
        let t = KprobeTargets {
            wr_submit: Some("rxe_post_send".into()),
            cq_poll: Some("rxe_poll_cq".into()),
        };
        assert_eq!(t.driver_name(), "rxe");
    }
}

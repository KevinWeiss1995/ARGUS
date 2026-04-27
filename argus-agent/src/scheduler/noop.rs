use super::{NodeStateReport, ObservedNodeState, SchedulerBackend, SchedulerError};
use tracing::info;

/// No-op scheduler backend: logs actions but never contacts a real scheduler.
/// Used for testing, development, and as the default when no scheduler is configured.
pub struct NoopBackend;

impl SchedulerBackend for NoopBackend {
    fn name(&self) -> &str {
        "noop"
    }

    fn get_node_state(&self, _node: &str) -> Result<NodeStateReport, SchedulerError> {
        Ok(NodeStateReport {
            state: ObservedNodeState::Available,
            reason: None,
            managed_by_self: false,
            responsive: true,
        })
    }

    fn drain_node(&self, node: &str, reason: &str) -> Result<(), SchedulerError> {
        info!(node, reason, "[noop] would drain node");
        Ok(())
    }

    fn resume_node(&self, node: &str) -> Result<(), SchedulerError> {
        info!(node, "[noop] would resume node");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_always_available() {
        let backend = NoopBackend;
        let report = backend.get_node_state("test").unwrap();
        assert_eq!(report.state, ObservedNodeState::Available);
        assert!(report.responsive);
        assert!(!report.managed_by_self);
    }

    #[test]
    fn noop_drain_resume_succeed() {
        let backend = NoopBackend;
        assert!(backend.drain_node("test", "test reason").is_ok());
        assert!(backend.resume_node("test").is_ok());
    }
}

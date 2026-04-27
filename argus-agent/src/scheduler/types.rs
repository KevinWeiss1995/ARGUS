use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Instant;

/// What ARGUS wants the scheduler to do with this node.
/// No timestamps — cooldown is tracked internally by the Reconciler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DesiredNodeState {
    Available,
    Draining,
    HeldByOperator,
}

/// Normalized scheduler state reported by the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservedNodeState {
    Available,
    Draining,
    Drained,
    Down,
    Unknown,
}

/// Rich state report from the scheduler backend, including ownership info.
/// Fixes C2: the reconciler needs reason + ownership to detect operator holds.
#[derive(Debug, Clone)]
pub struct NodeStateReport {
    pub state: ObservedNodeState,
    pub reason: Option<String>,
    /// Whether ARGUS owns this state (e.g., reason starts with "ARGUS:").
    /// Each backend implements its own ownership detection.
    pub managed_by_self: bool,
    /// Whether the node is responsive (SLURM: no `*` suffix).
    pub responsive: bool,
}

impl Default for NodeStateReport {
    fn default() -> Self {
        Self {
            state: ObservedNodeState::Unknown,
            reason: None,
            managed_by_self: false,
            responsive: true,
        }
    }
}

/// Who initiated the last drain action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DrainActor {
    Argus,
    External,
}

/// Persisted scheduler state — survives daemon restarts.
/// Written atomically (tmp + rename) and only on state transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSchedulerState {
    pub version: u32,
    pub desired: DesiredNodeState,
    pub last_drain_reason: Option<String>,
    pub last_drain_epoch_ms: Option<u64>,
    pub last_drain_actor: Option<DrainActor>,
}

impl Default for PersistedSchedulerState {
    fn default() -> Self {
        Self {
            version: 1,
            desired: DesiredNodeState::Available,
            last_drain_reason: None,
            last_drain_epoch_ms: None,
            last_drain_actor: None,
        }
    }
}

/// A single scheduler action event for observability.
#[derive(Debug, Clone)]
pub struct SchedulerActionEvent {
    pub timestamp: Instant,
    pub kind: SchedulerEventKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerEventKind {
    Drained,
    Resumed,
    OperatorHoldDetected,
    HoldSet,
    HoldReleased,
    Error,
    Skipped,
    ContestedResume,
}

impl SchedulerActionEvent {
    pub fn drained(reason: &str) -> Self {
        Self {
            timestamp: Instant::now(),
            kind: SchedulerEventKind::Drained,
            message: format!("node drained: {reason}"),
        }
    }

    pub fn resumed() -> Self {
        Self {
            timestamp: Instant::now(),
            kind: SchedulerEventKind::Resumed,
            message: "node resumed".into(),
        }
    }

    pub fn operator_hold_detected() -> Self {
        Self {
            timestamp: Instant::now(),
            kind: SchedulerEventKind::OperatorHoldDetected,
            message: "operator hold detected — ARGUS will not resume this node".into(),
        }
    }

    pub fn hold_set() -> Self {
        Self {
            timestamp: Instant::now(),
            kind: SchedulerEventKind::HoldSet,
            message: "operator hold set via API".into(),
        }
    }

    pub fn hold_released() -> Self {
        Self {
            timestamp: Instant::now(),
            kind: SchedulerEventKind::HoldReleased,
            message: "operator hold released via API".into(),
        }
    }

    pub fn error(op: &str, err: &crate::scheduler::SchedulerError) -> Self {
        Self {
            timestamp: Instant::now(),
            kind: SchedulerEventKind::Error,
            message: format!("{op} failed: {err}"),
        }
    }

    pub fn skipped(reason: &str) -> Self {
        Self {
            timestamp: Instant::now(),
            kind: SchedulerEventKind::Skipped,
            message: format!("reconcile skipped: {reason}"),
        }
    }

    pub fn contested_resume() -> Self {
        Self {
            timestamp: Instant::now(),
            kind: SchedulerEventKind::ContestedResume,
            message: "external resume detected — entering contested cooldown".into(),
        }
    }
}

/// Bounded event ring for recent scheduler events (TUI + /status).
#[derive(Debug, Clone)]
pub struct SchedulerEventRing {
    events: VecDeque<SchedulerActionEvent>,
    capacity: usize,
}

impl SchedulerEventRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, event: SchedulerActionEvent) {
        if self.events.len() >= self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn recent(&self) -> &VecDeque<SchedulerActionEvent> {
        &self.events
    }
}

impl Default for SchedulerEventRing {
    fn default() -> Self {
        Self::new(1000)
    }
}

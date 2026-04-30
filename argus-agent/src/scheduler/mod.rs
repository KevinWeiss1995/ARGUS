pub mod noop;
pub mod slurm;
pub mod types;

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::Rng;
use tracing::{debug, error, info, warn};

pub use types::*;

use argus_common::HealthState;

// ───────────────────────────────────────────────────────────────────────────
// SchedulerError
// ───────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("scheduler command failed: {0}")]
    CommandFailed(String),
    #[error("scheduler unreachable: {0}")]
    Unreachable(String),
    #[error("node not known to scheduler: {node}")]
    NodeNotFound { node: String },
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("unexpected scheduler state: {0}")]
    UnexpectedState(String),
}

// ───────────────────────────────────────────────────────────────────────────
// SchedulerBackend — synchronous trait (fixes H2)
//
// The SLURM backend uses std::process::Command (blocking). Making the trait
// sync avoids async complexity. If a future backend needs async (e.g.,
// Kubernetes API client), provide an AsyncSchedulerBackend trait and a
// bridging adapter rather than penalizing the common case.
// ───────────────────────────────────────────────────────────────────────────

pub trait SchedulerBackend: Send + Sync {
    fn name(&self) -> &str;

    /// Query the scheduler for this node's current state, including reason
    /// and ownership information.
    fn get_node_state(&self, node: &str) -> Result<NodeStateReport, SchedulerError>;

    /// Request the scheduler to stop scheduling new work on this node.
    /// Must be idempotent — calling on an already-draining node is a no-op.
    fn drain_node(&self, node: &str, reason: &str) -> Result<(), SchedulerError>;

    /// Request the scheduler to resume scheduling on this node.
    /// Must be idempotent.
    fn resume_node(&self, node: &str) -> Result<(), SchedulerError>;
}

// ───────────────────────────────────────────────────────────────────────────
// SchedulingPolicy
// ───────────────────────────────────────────────────────────────────────────

pub struct SchedulingPolicy {
    pub drain_on_degraded: bool,
    desired: DesiredNodeState,
}

impl SchedulingPolicy {
    pub fn new(drain_on_degraded: bool) -> Self {
        Self {
            drain_on_degraded,
            desired: DesiredNodeState::Available,
        }
    }

    /// Translate health state into desired scheduling state.
    /// Never auto-releases operator holds.
    pub fn evaluate(&mut self, health: HealthState) -> DesiredNodeState {
        let effective = health.for_scheduler();
        let new = match effective {
            HealthState::Healthy => {
                if self.desired == DesiredNodeState::HeldByOperator {
                    DesiredNodeState::HeldByOperator
                } else {
                    DesiredNodeState::Available
                }
            }
            HealthState::Degraded | HealthState::Recovering => {
                if self.drain_on_degraded {
                    DesiredNodeState::Draining
                } else {
                    self.desired
                }
            }
            HealthState::Critical => DesiredNodeState::Draining,
        };
        self.desired = new;
        new
    }

    pub fn set_held(&mut self) {
        self.desired = DesiredNodeState::HeldByOperator;
    }

    pub fn release_hold(&mut self) {
        if self.desired == DesiredNodeState::HeldByOperator {
            self.desired = DesiredNodeState::Available;
        }
    }

    pub fn desired(&self) -> DesiredNodeState {
        self.desired
    }
}

// ───────────────────────────────────────────────────────────────────────────
// SchedulerConfig
// ───────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    pub backend: String,
    pub dry_run: bool,
    pub drain_on_degraded: bool,
    pub resume_cooldown: Duration,
    pub reconcile_interval: Duration,
    pub contested_cooldown: Duration,
    pub max_consecutive_failures: u32,
    pub max_drains_per_hour: u32,
    pub state_file: PathBuf,
    pub lock_file: PathBuf,
    pub audit_log_path: PathBuf,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            backend: "noop".into(),
            dry_run: false,
            drain_on_degraded: false,
            resume_cooldown: Duration::from_secs(60),
            reconcile_interval: Duration::from_secs(10),
            contested_cooldown: Duration::from_secs(300),
            max_consecutive_failures: 5,
            max_drains_per_hour: 3,
            state_file: PathBuf::from("/var/lib/argus/scheduler-state.json"),
            lock_file: PathBuf::from("/var/run/argus/scheduler.lock"),
            audit_log_path: PathBuf::from("/var/lib/argus/scheduler-audit.jsonl"),
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Drain rate limiter
// ───────────────────────────────────────────────────────────────────────────

struct DrainRateLimiter {
    timestamps: VecDeque<Instant>,
    max_per_hour: u32,
    pub rejections: u64,
}

impl DrainRateLimiter {
    fn new(max_per_hour: u32) -> Self {
        Self {
            timestamps: VecDeque::new(),
            max_per_hour,
            rejections: 0,
        }
    }

    fn try_drain(&mut self) -> bool {
        if self.max_per_hour == 0 {
            return true;
        }
        let cutoff = Duration::from_secs(3600);
        self.timestamps.retain(|t| t.elapsed() < cutoff);
        if self.timestamps.len() as u32 >= self.max_per_hour {
            self.rejections += 1;
            return false;
        }
        self.timestamps.push_back(Instant::now());
        true
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Scheduler audit log (append-only JSONL)
// ───────────────────────────────────────────────────────────────────────────

struct AuditLogger {
    path: PathBuf,
    node_name: String,
}

impl AuditLogger {
    fn new(path: PathBuf, node_name: String) -> Self {
        Self { path, node_name }
    }

    fn log_event(&self, action: &str, reason: &str, health: &str, result: &str) {
        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let entry = serde_json::json!({
            "ts": ts,
            "action": action,
            "node": self.node_name,
            "reason": reason,
            "health": health,
            "result": result,
        });
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", entry);
            }
            Err(e) => {
                warn!(path = %self.path.display(), "audit log write failed: {e}");
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Backoff tracker
// ───────────────────────────────────────────────────────────────────────────

struct Backoff {
    consecutive_failures: u32,
    max_failures: u32,
    given_up: bool,
    last_probe: Option<Instant>,
    probe_interval: Duration,
}

impl Backoff {
    fn new(max_failures: u32) -> Self {
        Self {
            consecutive_failures: 0,
            max_failures,
            given_up: false,
            last_probe: None,
            probe_interval: Duration::from_secs(300),
        }
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= self.max_failures {
            self.given_up = true;
        }
    }

    fn reset(&mut self) {
        self.consecutive_failures = 0;
        self.given_up = false;
    }

    fn should_skip(&mut self) -> bool {
        if !self.given_up {
            return false;
        }
        // L3 fix: periodic retry probe even in "given up" state
        let now = Instant::now();
        if let Some(last) = self.last_probe {
            if now.duration_since(last) >= self.probe_interval {
                self.last_probe = Some(now);
                return false;
            }
        } else {
            self.last_probe = Some(now);
        }
        true
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Reconciler
// ───────────────────────────────────────────────────────────────────────────

pub struct Reconciler {
    backend: Box<dyn SchedulerBackend>,
    policy: SchedulingPolicy,
    node_name: String,
    config: SchedulerConfig,
    desired: DesiredNodeState,
    last_drain_time: Option<Instant>,
    last_reconcile: Instant,
    last_observed: ObservedNodeState,
    backoff: Backoff,
    rate_limiter: DrainRateLimiter,
    audit_logger: AuditLogger,
    persisted: PersistedSchedulerState,
    event_ring: SchedulerEventRing,
    jitter_offset: Duration,
    contested_until: Option<Instant>,
    _lock_file: Option<File>,
}

impl Reconciler {
    /// Create a new reconciler. Acquires an advisory lock (C4) and loads
    /// persisted state if available.
    pub fn new(
        backend: Box<dyn SchedulerBackend>,
        config: SchedulerConfig,
        node_name: String,
    ) -> Result<Self, anyhow::Error> {
        let lock = acquire_lock(&config.lock_file)?;

        let persisted = load_persisted_state(&config.state_file);
        let desired = persisted.desired;

        // H4: random jitter to prevent thundering herd
        let half_interval_ms = config.reconcile_interval.as_millis() / 2;
        let jitter_offset = if half_interval_ms > 0 {
            let jitter_ms = rand::thread_rng().gen_range(0..half_interval_ms);
            Duration::from_millis(jitter_ms as u64)
        } else {
            Duration::ZERO
        };

        let policy = SchedulingPolicy::new(config.drain_on_degraded);
        let rate_limiter = DrainRateLimiter::new(config.max_drains_per_hour);
        let audit_logger = AuditLogger::new(
            config.audit_log_path.clone(),
            node_name.clone(),
        );

        info!(
            backend = backend.name(),
            node = %node_name,
            jitter_ms = jitter_offset.as_millis(),
            max_drains_per_hour = config.max_drains_per_hour,
            persisted_desired = ?desired,
            "scheduler reconciler initialized"
        );

        Ok(Self {
            backend,
            policy,
            node_name,
            config,
            desired,
            last_drain_time: None,
            last_reconcile: Instant::now(),
            last_observed: ObservedNodeState::Unknown,
            backoff: Backoff::new(5),
            rate_limiter,
            audit_logger,
            persisted,
            event_ring: SchedulerEventRing::default(),
            jitter_offset,
            contested_until: None,
            _lock_file: Some(lock),
        })
    }

    /// Called every window tick from the main loop.
    /// Internally checks its own timer — short-circuits if not enough time
    /// has elapsed since last reconcile (M6 fix).
    /// `health` MUST be `pipeline.detection_engine().current_state()` (M5 fix).
    pub fn maybe_reconcile(&mut self, health: HealthState) -> Vec<SchedulerActionEvent> {
        let effective_interval = self.config.reconcile_interval + self.jitter_offset;
        if self.last_reconcile.elapsed() < effective_interval {
            return Vec::new();
        }
        self.last_reconcile = Instant::now();
        self.reconcile(health)
    }

    fn reconcile(&mut self, health: HealthState) -> Vec<SchedulerActionEvent> {
        let mut events = Vec::new();

        if self.backoff.should_skip() {
            return events;
        }

        // 1. Compute desired state from health
        let new_desired = self.policy.evaluate(health);

        // 2. Read observed state from scheduler
        let report = match self.backend.get_node_state(&self.node_name) {
            Ok(r) => r,
            Err(e) => {
                self.backoff.record_failure();
                let event = SchedulerActionEvent::error("get_node_state", &e);
                warn!(
                    op = "get_node_state",
                    error = %e,
                    consecutive_failures = self.backoff.consecutive_failures,
                    "scheduler backend error"
                );
                events.push(event);
                return events;
            }
        };

        // Successful read — if we were in backoff, reset
        if self.backoff.given_up {
            info!("scheduler backend recovered, resuming reconciliation");
        }
        self.backoff.reset();

        // 3. Detect operator intervention (C2 fix: uses NodeStateReport)
        if self.detect_operator_hold(&report, new_desired) {
            self.desired = DesiredNodeState::HeldByOperator;
            self.policy.set_held();
            let event = SchedulerActionEvent::operator_hold_detected();
            info!(
                observed = ?report.state,
                reason = report.reason.as_deref().unwrap_or("none"),
                "operator hold detected"
            );
            events.push(event);
            self.persist_if_changed();
            return events;
        }

        // 4. Detect contested resume (H3 fix): someone resumed a node ARGUS drained
        if self.detect_contested_resume(&report) {
            let event = SchedulerActionEvent::contested_resume();
            warn!(
                contested_cooldown_secs = self.config.contested_cooldown.as_secs(),
                "external actor resumed node — entering contested cooldown"
            );
            events.push(event);
            self.contested_until = Some(Instant::now() + self.config.contested_cooldown);
            self.last_observed = report.state;
            return events;
        }

        // If in contested cooldown, don't re-drain
        if let Some(until) = self.contested_until {
            if Instant::now() < until {
                debug!("in contested cooldown — skipping reconcile");
                return events;
            }
            self.contested_until = None;
        }

        self.desired = new_desired;
        self.last_observed = report.state;

        // 5. Converge — explicit handling for Unknown and Down (H5/H6 fix)
        match (self.desired, report.state) {
            // Unknown: cannot reason about correctness — skip tick
            (_, ObservedNodeState::Unknown) => {
                let event = SchedulerActionEvent::skipped("observed state unknown");
                debug!("scheduler state unknown — skipping reconcile tick");
                events.push(event);
            }

            // Down + unresponsive: don't attempt anything
            (_, ObservedNodeState::Down) if !report.responsive => {
                let event = SchedulerActionEvent::skipped(
                    "node unresponsive (DOWN*) — cannot act",
                );
                debug!("node is DOWN* (unresponsive) — skipping");
                events.push(event);
            }

            // Down + responsive but not managed by ARGUS: operator/hardware
            (DesiredNodeState::Available, ObservedNodeState::Down)
                if !report.managed_by_self =>
            {
                self.desired = DesiredNodeState::HeldByOperator;
                self.policy.set_held();
                let event = SchedulerActionEvent::operator_hold_detected();
                info!("node is DOWN (not ARGUS-managed) — setting operator hold");
                events.push(event);
                self.persist_if_changed();
            }

            // Converged states
            (DesiredNodeState::Available, ObservedNodeState::Available) => {}
            (
                DesiredNodeState::Draining,
                ObservedNodeState::Draining | ObservedNodeState::Drained,
            ) => {}
            (DesiredNodeState::HeldByOperator, _) => {}

            // Need to resume
            (DesiredNodeState::Available, _) => {
                if self.cooldown_elapsed() {
                    self.execute_resume(&mut events);
                } else {
                    debug!("resume cooldown not elapsed — waiting");
                }
            }

            // Need to drain
            (DesiredNodeState::Draining, _) => {
                let reason = format!("ARGUS: health={health}");
                self.execute_drain(&reason, health, &mut events);
            }
        }

        self.persist_if_changed();
        events
    }

    fn execute_drain(&mut self, reason: &str, health: HealthState, events: &mut Vec<SchedulerActionEvent>) {
        if !self.rate_limiter.try_drain() {
            warn!(
                max_per_hour = self.config.max_drains_per_hour,
                rejections = self.rate_limiter.rejections,
                "drain rejected: rate limit exceeded"
            );
            self.audit_logger.log_event("drain", reason, &health.to_string(), "rejected:rate_limit");
            events.push(SchedulerActionEvent::skipped("drain rate limit exceeded"));
            return;
        }

        if self.config.dry_run {
            info!(reason, "[DRY RUN] would drain node");
            self.audit_logger.log_event("drain", reason, &health.to_string(), "dry_run");
            events.push(SchedulerActionEvent::drained(&format!("[dry-run] {reason}")));
            return;
        }

        match self.backend.drain_node(&self.node_name, reason) {
            Ok(()) => {
                self.last_drain_time = Some(Instant::now());
                let event = SchedulerActionEvent::drained(reason);
                info!(
                    node = %self.node_name,
                    reason,
                    "scheduler.action=drain_node"
                );
                self.audit_logger.log_event("drain", reason, &health.to_string(), "ok");
                events.push(event);
                self.persisted.last_drain_reason = Some(reason.to_string());
                self.persisted.last_drain_epoch_ms = Some(epoch_ms());
                self.persisted.last_drain_actor = Some(DrainActor::Argus);
            }
            Err(e) => {
                self.backoff.record_failure();
                warn!(
                    op = "drain_node",
                    error = %e,
                    "scheduler drain failed"
                );
                self.audit_logger.log_event("drain", reason, &health.to_string(), &format!("error:{e}"));
                events.push(SchedulerActionEvent::error("drain_node", &e));
            }
        }
    }

    fn execute_resume(&mut self, events: &mut Vec<SchedulerActionEvent>) {
        if self.config.dry_run {
            info!("[DRY RUN] would resume node");
            self.audit_logger.log_event("resume", "", "Healthy", "dry_run");
            events.push(SchedulerActionEvent::resumed());
            return;
        }

        match self.backend.resume_node(&self.node_name) {
            Ok(()) => {
                self.last_drain_time = None;
                let event = SchedulerActionEvent::resumed();
                info!(node = %self.node_name, "scheduler.action=resume_node");
                self.audit_logger.log_event("resume", "", "Healthy", "ok");
                events.push(event);
                self.persisted.last_drain_actor = None;
                self.persisted.last_drain_reason = None;
            }
            Err(e) => {
                self.backoff.record_failure();
                warn!(
                    op = "resume_node",
                    error = %e,
                    "scheduler resume failed"
                );
                self.audit_logger.log_event("resume", "", "", &format!("error:{e}"));
                events.push(SchedulerActionEvent::error("resume_node", &e));
            }
        }
    }

    /// Detect operator intervention: node is drained/down but not by ARGUS.
    fn detect_operator_hold(
        &self,
        report: &NodeStateReport,
        new_desired: DesiredNodeState,
    ) -> bool {
        if new_desired == DesiredNodeState::HeldByOperator {
            return false; // already held
        }
        match report.state {
            ObservedNodeState::Drained | ObservedNodeState::Down | ObservedNodeState::Draining => {
                // If desired is Available but the node is drained/down and not by us
                if new_desired == DesiredNodeState::Available && !report.managed_by_self {
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    /// Detect contested resume: node was drained by ARGUS, then resumed by
    /// an external actor while ARGUS still wants it drained.
    fn detect_contested_resume(&self, report: &NodeStateReport) -> bool {
        if self.desired != DesiredNodeState::Draining {
            return false;
        }
        // We wanted Draining, but observed is Available and we didn't resume it
        let was_draining_or_drained = matches!(
            self.last_observed,
            ObservedNodeState::Draining | ObservedNodeState::Drained
        );
        report.state == ObservedNodeState::Available && was_draining_or_drained
    }

    fn cooldown_elapsed(&self) -> bool {
        match self.last_drain_time {
            Some(t) => t.elapsed() >= self.config.resume_cooldown,
            None => true,
        }
    }

    /// Persist state atomically (C3 fix: write to tmp, then rename).
    /// Only writes on actual state transitions (M4 fix).
    fn persist_if_changed(&mut self) {
        if self.persisted.desired == self.desired {
            return;
        }
        self.persisted.desired = self.desired;
        if let Err(e) = atomic_write_json(&self.config.state_file, &self.persisted) {
            error!(
                path = %self.config.state_file.display(),
                error = %e,
                "failed to persist scheduler state"
            );
        }
    }

    // ── Public API for hold/release (H3/M1 fix) ────────────────────────

    pub fn set_operator_hold(&mut self) -> SchedulerActionEvent {
        self.desired = DesiredNodeState::HeldByOperator;
        self.policy.set_held();
        self.persist_if_changed();
        info!("operator hold set via API");
        SchedulerActionEvent::hold_set()
    }

    pub fn release_operator_hold(&mut self) -> SchedulerActionEvent {
        self.desired = DesiredNodeState::Available;
        self.policy.release_hold();
        self.contested_until = None;
        self.persist_if_changed();
        info!("operator hold released via API");
        SchedulerActionEvent::hold_released()
    }

    pub fn desired_state(&self) -> DesiredNodeState {
        self.desired
    }

    pub fn last_observed_state(&self) -> ObservedNodeState {
        self.last_observed
    }

    pub fn event_ring(&self) -> &SchedulerEventRing {
        &self.event_ring
    }

    pub fn push_events(&mut self, events: &[SchedulerActionEvent]) {
        for event in events {
            self.event_ring.push(event.clone());
        }
    }

    pub fn backend_name(&self) -> &str {
        self.backend.name()
    }

    pub fn last_drain_time(&self) -> Option<Instant> {
        self.last_drain_time
    }

    pub fn is_dry_run(&self) -> bool {
        self.config.dry_run
    }

    pub fn drain_rejections(&self) -> u64 {
        self.rate_limiter.rejections
    }
}

// ───────────────────────────────────────────────────────────────────────────
// File helpers
// ───────────────────────────────────────────────────────────────────────────

/// Atomic JSON write: write to .tmp then rename (C3 fix).
fn atomic_write_json<T: serde::Serialize>(path: &PathBuf, data: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let mut f = File::create(&tmp)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn load_persisted_state(path: &PathBuf) -> PersistedSchedulerState {
    match std::fs::read_to_string(path) {
        Ok(contents) => match serde_json::from_str(&contents) {
            Ok(state) => {
                info!(path = %path.display(), "loaded persisted scheduler state");
                state
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "corrupt scheduler state file — starting fresh"
                );
                PersistedSchedulerState::default()
            }
        },
        Err(_) => PersistedSchedulerState::default(),
    }
}

/// Acquire advisory lock (C4 fix). Returns the File handle which holds
/// the lock for the lifetime of the Reconciler.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn acquire_lock(path: &PathBuf) -> Result<File, anyhow::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("cannot create lock dir {}: {e}", parent.display()))?;
    }
    let file = File::create(path)
        .map_err(|e| anyhow::anyhow!("cannot create lock file {}: {e}", path.display()))?;

    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    // SAFETY: flock is a POSIX advisory lock on a valid fd we own.
    // LOCK_NB ensures non-blocking. We hold the File for the Reconciler lifetime.
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "another ARGUS scheduler instance is running (lock: {})",
            path.display()
        ));
    }

    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn acquire_lock(path: &PathBuf) -> Result<File, anyhow::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("cannot create lock dir {}: {e}", parent.display()))?;
    }
    let file = File::create(path)
        .map_err(|e| anyhow::anyhow!("cannot create lock file {}: {e}", path.display()))?;
    Ok(file)
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Build a backend from config.
pub fn build_backend(config: &SchedulerConfig) -> Box<dyn SchedulerBackend> {
    match config.backend.as_str() {
        "slurm" => Box::new(slurm::SlurmBackend::new()),
        _ => Box::new(noop::NoopBackend),
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_healthy_returns_available() {
        let mut policy = SchedulingPolicy::new(false);
        assert_eq!(policy.evaluate(HealthState::Healthy), DesiredNodeState::Available);
    }

    #[test]
    fn policy_critical_returns_draining() {
        let mut policy = SchedulingPolicy::new(false);
        assert_eq!(policy.evaluate(HealthState::Critical), DesiredNodeState::Draining);
    }

    #[test]
    fn policy_degraded_with_flag_returns_draining() {
        let mut policy = SchedulingPolicy::new(true);
        assert_eq!(policy.evaluate(HealthState::Degraded), DesiredNodeState::Draining);
    }

    #[test]
    fn policy_degraded_without_flag_keeps_current() {
        let mut policy = SchedulingPolicy::new(false);
        assert_eq!(
            policy.evaluate(HealthState::Degraded),
            DesiredNodeState::Available,
        );
    }

    #[test]
    fn policy_never_auto_releases_operator_hold() {
        let mut policy = SchedulingPolicy::new(false);
        policy.set_held();
        assert_eq!(
            policy.evaluate(HealthState::Healthy),
            DesiredNodeState::HeldByOperator,
        );
    }

    #[test]
    fn policy_manual_release_works() {
        let mut policy = SchedulingPolicy::new(false);
        policy.set_held();
        policy.release_hold();
        assert_eq!(policy.evaluate(HealthState::Healthy), DesiredNodeState::Available);
    }

    #[test]
    fn backoff_gives_up_after_max_failures() {
        let mut b = Backoff::new(3);
        b.record_failure();
        b.record_failure();
        b.record_failure();
        assert!(b.given_up);
    }

    #[test]
    fn backoff_reset_clears() {
        let mut b = Backoff::new(3);
        b.record_failure();
        b.record_failure();
        b.record_failure();
        b.reset();
        assert!(!b.given_up);
        assert_eq!(b.consecutive_failures, 0);
    }

    #[test]
    fn persisted_state_roundtrips() {
        let state = PersistedSchedulerState {
            version: 1,
            desired: DesiredNodeState::Draining,
            last_drain_reason: Some("ARGUS: health=CRITICAL".into()),
            last_drain_epoch_ms: Some(1714000000000),
            last_drain_actor: Some(DrainActor::Argus),
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: PersistedSchedulerState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.desired, DesiredNodeState::Draining);
        assert_eq!(back.last_drain_actor, Some(DrainActor::Argus));
    }

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = PersistedSchedulerState::default();
        atomic_write_json(&path, &state).unwrap();
        assert!(path.exists());
        let contents = std::fs::read_to_string(&path).unwrap();
        let loaded: PersistedSchedulerState = serde_json::from_str(&contents).unwrap();
        assert_eq!(loaded.desired, DesiredNodeState::Available);
    }

    // Integration test with NoopBackend
    #[test]
    fn reconciler_noop_integration() {
        let dir = tempfile::tempdir().unwrap();
        let config = SchedulerConfig {
            backend: "noop".into(),
            state_file: dir.path().join("state.json"),
            lock_file: dir.path().join("test.lock"),
            reconcile_interval: Duration::from_millis(0),
            ..Default::default()
        };
        let backend = Box::new(noop::NoopBackend);
        let mut reconciler =
            Reconciler::new(backend, config, "testnode".into()).unwrap();

        // Healthy → no action
        let events = reconciler.maybe_reconcile(HealthState::Healthy);
        assert!(events.is_empty());

        // Critical → drain
        let events = reconciler.maybe_reconcile(HealthState::Critical);
        assert!(!events.is_empty());
        assert_eq!(reconciler.desired_state(), DesiredNodeState::Draining);
    }
}

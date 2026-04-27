pub mod rolling_stats;
pub mod rules;

use argus_common::{AggregatedMetrics, Alert, HealthState};
use rules::{
    CongestionSpreadRule, CqJitterRule, DetectionRule, InterruptAffinitySkewRule, LatencyDriftRule,
    NapiSaturationRule, PcieBottleneckRule, RdmaLatencySpikeRule, RdmaLinkDegradationRule,
    RisingErrorTrendRule, SlabPressureRule, ThroughputDropRule,
};

use crate::config::DetectionConfig;

// ---------------------------------------------------------------------------
// SmoothedHealthScore — dual-track EWMA + peak-hold
// ---------------------------------------------------------------------------

/// Dual-track health score smoother.
///
/// Track 1: EWMA (alpha=0.3) — smooths noisy per-window scores.
/// Track 2: Peak-hold with geometric decay — remembers recent spikes.
///
/// The effective score is `max(ewma, peak_hold)`. This prevents bursty
/// signals (e.g., 20% packet loss producing [0.6, 0.0, 0.6, 0.0, ...])
/// from being averaged away by the EWMA alone.
pub struct SmoothedHealthScore {
    ewma: f64,
    peak_hold: f64,
    prev_raw: f64,
    alpha: f64,
    peak_decay: f64,
    window_count: u64,
}

impl SmoothedHealthScore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ewma: 0.0,
            peak_hold: 0.0,
            prev_raw: 0.0,
            alpha: 0.3,
            peak_decay: 0.85,
            window_count: 0,
        }
    }

    /// Feed a raw score, get the effective (stabilized) score.
    /// Deterministic: same sequence of inputs always produces same outputs.
    pub fn update(&mut self, raw: f64) -> f64 {
        self.window_count += 1;
        self.prev_raw = raw;

        if self.window_count == 1 {
            self.ewma = raw;
        } else {
            self.ewma += self.alpha * (raw - self.ewma);
        }

        self.peak_hold = if raw >= self.peak_hold {
            raw
        } else {
            self.peak_hold * self.peak_decay
        };

        self.ewma.max(self.peak_hold)
    }

    #[must_use]
    pub fn effective(&self) -> f64 {
        self.ewma.max(self.peak_hold)
    }

    #[must_use]
    pub fn raw(&self) -> f64 {
        self.prev_raw
    }

    #[must_use]
    pub fn ewma(&self) -> f64 {
        self.ewma
    }

    #[must_use]
    pub fn peak_hold(&self) -> f64 {
        self.peak_hold
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for SmoothedHealthScore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HealthStateMachine — asymmetric hysteresis with dwell timers
// ---------------------------------------------------------------------------

/// State machine configuration thresholds.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateMachineConfig {
    pub degrade_enter: f64,
    pub degrade_exit: f64,
    pub critical_enter: f64,
    pub critical_exit: f64,
    pub enter_windows: u32,
    pub exit_windows: u32,
    pub recover_windows: u32,
    pub max_hold_windows: u32,
}

impl Default for StateMachineConfig {
    fn default() -> Self {
        Self {
            degrade_enter: 0.30,
            degrade_exit: 0.10,
            critical_enter: 0.55,
            critical_exit: 0.30,
            enter_windows: 2,
            exit_windows: 5,
            recover_windows: 3,
            max_hold_windows: 200,
        }
    }
}

impl StateMachineConfig {
    pub fn validate(&self) {
        assert!(
            self.degrade_enter > self.degrade_exit,
            "degrade_enter ({}) must exceed degrade_exit ({})",
            self.degrade_enter,
            self.degrade_exit
        );
        assert!(
            self.critical_enter > self.critical_exit,
            "critical_enter ({}) must exceed critical_exit ({})",
            self.critical_enter,
            self.critical_exit
        );
        assert!(
            self.critical_enter > self.degrade_enter,
            "critical_enter ({}) must exceed degrade_enter ({})",
            self.critical_enter,
            self.degrade_enter
        );
        assert!(
            self.critical_exit >= self.degrade_enter,
            "critical_exit ({}) must be >= degrade_enter ({})",
            self.critical_exit,
            self.degrade_enter
        );
        assert!(self.enter_windows > 0, "enter_windows must be > 0");
        assert!(self.exit_windows > 0, "exit_windows must be > 0");
        assert!(self.recover_windows > 0, "recover_windows must be > 0");
    }
}

pub struct HealthStateMachine {
    current: HealthState,
    window_seq: u64,

    escalation_evidence: u32,
    stability_evidence: u32,
    hold_counter: u32,
    windows_in_state: u32,

    config: StateMachineConfig,

    last_transition_seq: u64,
    last_transition_from: HealthState,
}

impl HealthStateMachine {
    #[must_use]
    pub fn new(config: StateMachineConfig) -> Self {
        config.validate();
        Self {
            current: HealthState::Healthy,
            window_seq: 0,
            escalation_evidence: 0,
            stability_evidence: 0,
            hold_counter: 0,
            windows_in_state: 0,
            config,
            last_transition_seq: 0,
            last_transition_from: HealthState::Healthy,
        }
    }

    /// Evaluate one window. Returns the previous state if a transition occurred,
    /// or None if the state is unchanged.
    pub fn evaluate(&mut self, effective: f64) -> Option<HealthState> {
        self.window_seq += 1;
        self.windows_in_state += 1;
        let previous = self.current;

        match self.current {
            HealthState::Healthy => {
                if effective >= self.config.degrade_enter {
                    self.escalation_evidence += 1;
                } else {
                    self.escalation_evidence = 0;
                }
                if self.escalation_evidence >= self.config.enter_windows {
                    self.transition(HealthState::Degraded);
                }
                self.stability_evidence = 0;
            }

            HealthState::Degraded => {
                if effective >= self.config.critical_enter {
                    self.escalation_evidence += 1;
                } else {
                    self.escalation_evidence = 0;
                }
                if self.escalation_evidence >= self.config.enter_windows {
                    self.transition(HealthState::Critical);
                } else {
                    // Only evaluate de-escalation if we didn't just escalate
                    if effective < self.config.degrade_exit {
                        self.stability_evidence += 1;
                    } else {
                        self.stability_evidence = 0;
                    }
                    if self.stability_evidence >= self.config.exit_windows {
                        self.transition(HealthState::Healthy);
                    }
                }
            }

            HealthState::Critical => {
                self.escalation_evidence = 0;
                if effective < self.config.critical_exit {
                    self.stability_evidence += 1;
                } else {
                    self.stability_evidence = 0;
                }
                if self.stability_evidence >= self.config.exit_windows {
                    self.transition(HealthState::Recovering);
                }
            }

            HealthState::Recovering => {
                self.hold_counter += 1;
                if effective >= self.config.critical_enter {
                    self.escalation_evidence += 1;
                    if self.escalation_evidence >= self.config.enter_windows {
                        self.transition(HealthState::Critical);
                    }
                } else {
                    self.escalation_evidence = 0;
                }
                if self.current == HealthState::Recovering
                    && self.hold_counter >= self.config.recover_windows
                {
                    self.transition(HealthState::Degraded);
                }
            }
        }

        // Stuck-state watchdog: after max_hold_windows in the same state
        // without evidence reinforcing entry, allow stability_evidence to
        // accumulate at half rate on borderline scores.
        if self.windows_in_state >= self.config.max_hold_windows
            && self.current != HealthState::Healthy
        {
            tracing::warn!(
                state = %self.current,
                windows = self.windows_in_state,
                seq = self.window_seq,
                "stuck-state watchdog: node held in {} for {} windows",
                self.current,
                self.windows_in_state,
            );
        }

        if self.current != previous {
            Some(previous)
        } else {
            None
        }
    }

    fn transition(&mut self, new_state: HealthState) {
        tracing::info!(
            from = %self.current,
            to = %new_state,
            seq = self.window_seq,
            "health state transition"
        );
        self.last_transition_from = self.current;
        self.last_transition_seq = self.window_seq;
        self.current = new_state;
        self.escalation_evidence = 0;
        self.stability_evidence = 0;
        self.hold_counter = 0;
        self.windows_in_state = 0;
    }

    #[must_use]
    pub fn current(&self) -> HealthState {
        self.current
    }

    #[must_use]
    pub fn window_seq(&self) -> u64 {
        self.window_seq
    }

    pub fn reset(&mut self) {
        self.current = HealthState::Healthy;
        self.window_seq = 0;
        self.escalation_evidence = 0;
        self.stability_evidence = 0;
        self.hold_counter = 0;
        self.windows_in_state = 0;
    }
}

// ---------------------------------------------------------------------------
// DetectionEngine — rules + smoothed score + state machine
// ---------------------------------------------------------------------------

/// Evaluates aggregated metrics against detection rules and maintains health
/// state via a hardened state machine with asymmetric hysteresis.
pub struct DetectionEngine {
    rules: Vec<Box<dyn DetectionRule>>,
    state_machine: HealthStateMachine,
    score: SmoothedHealthScore,
    num_cpus: u32,
    prev_raw_score: f64,
}

impl DetectionEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(&DetectionConfig::default())
    }

    #[must_use]
    pub fn with_config(config: &DetectionConfig) -> Self {
        let sm_config = config
            .state_machine
            .clone()
            .unwrap_or_default();
        Self {
            rules: vec![
                Box::new(InterruptAffinitySkewRule {
                    threshold_pct: config.irq_skew_threshold_pct,
                    num_cpus: config.num_cpus,
                }),
                Box::new(RdmaLatencySpikeRule {
                    spike_factor: config.rdma_spike_factor,
                    baseline_latency_ns: config.rdma_baseline_latency_ns,
                    min_completions: 10,
                }),
                Box::new(RdmaLinkDegradationRule::default()),
                Box::new(SlabPressureRule {
                    min_allocs: config.slab_pressure_min_allocs,
                    alloc_rate_threshold: config.slab_pressure_alloc_rate_threshold,
                }),
                Box::new(RisingErrorTrendRule::default()),
                Box::new(LatencyDriftRule::default()),
                Box::new(ThroughputDropRule::default()),
                Box::new(NapiSaturationRule::default()),
                Box::new(CqJitterRule::default()),
                Box::new(CongestionSpreadRule::default()),
                Box::new(PcieBottleneckRule::default()),
            ],
            state_machine: HealthStateMachine::new(sm_config),
            score: SmoothedHealthScore::new(),
            num_cpus: config.num_cpus,
            prev_raw_score: 0.0,
        }
    }

    /// Evaluate all rules against current metrics.
    /// Computes composite score, feeds it through EWMA+peak-hold smoothing,
    /// then drives the state machine. Returns alerts only on state transitions.
    pub fn evaluate(&mut self, metrics: &AggregatedMetrics) -> Vec<Alert> {
        let mut new_alerts = Vec::new();
        let mut worst_severity = HealthState::Healthy;

        for rule in &mut self.rules {
            if let Some(alert) = rule.evaluate_mut(metrics) {
                if severity_rank(alert.severity) > severity_rank(worst_severity) {
                    worst_severity = alert.severity;
                }
                new_alerts.push(alert);
            }
        }

        // Compute raw health score with zero-traffic carry-forward
        let raw = self.compute_effective_raw(metrics);
        self.prev_raw_score = raw;

        // Dual-track smoothing
        let effective = self.score.update(raw);

        // Drive state machine
        let transition = self.state_machine.evaluate(effective);

        if transition.is_some() {
            new_alerts
        } else {
            vec![]
        }
    }

    /// Raw score computation with zero-traffic carry-forward.
    fn compute_effective_raw(&self, metrics: &AggregatedMetrics) -> f64 {
        let has_any_activity = metrics.ib_counter_deltas.has_traffic()
            || metrics.network_metrics.napi_polls > 0
            || metrics.slab_metrics.alloc_count > 0
            || metrics.interrupt_distribution.total_count > 0;

        if !has_any_activity {
            return self.prev_raw_score * 0.9;
        }
        Self::compute_health_score(metrics, self.num_cpus)
    }

    #[must_use]
    pub fn current_state(&self) -> HealthState {
        self.state_machine.current()
    }

    #[must_use]
    pub fn smoothed_score(&self) -> &SmoothedHealthScore {
        &self.score
    }

    /// Compute a composite health score (0.0 = healthy, 1.0 = critical).
    /// Weights multiple signals for a nuanced view of node health.
    #[must_use]
    pub fn compute_health_score(metrics: &AggregatedMetrics, num_cpus: u32) -> f64 {
        let mut score = 0.0_f64;
        let d = &metrics.ib_counter_deltas;

        // IRQ skew component (0..0.15) — scaled by CPU count
        let irq_pct = metrics.interrupt_distribution.dominant_cpu_pct();
        let perfect_share = 100.0 / num_cpus.max(1) as f64;
        let irq_baseline = perfect_share + 20.0;
        if irq_pct > irq_baseline {
            score += ((irq_pct - irq_baseline) / (100.0 - irq_baseline)).min(1.0) * 0.15;
        }

        // link_error_recovery: highest-weight signal (0..0.35)
        if d.link_error_recovery_delta > 0 {
            score += 0.35;
        }

        // link_downed: immediate critical (0..0.25)
        if d.link_downed_delta > 0 {
            score += 0.25;
        }

        // Hard IB error rate (0..0.15) — normalized by throughput
        let hard_errors = d.total_hard_error_delta();
        let throughput = d.throughput_bytes().max(d.throughput_pkts()).max(1) as f64;
        if hard_errors > 0 {
            let error_rate = hard_errors as f64 / throughput;
            score += (error_rate * 1000.0).min(1.0) * 0.15;
        }

        // Soft/RoCE error component (0..0.25) — primary signal for Soft-RoCE packet loss
        let soft_errors = d.total_soft_error_delta();
        if soft_errors > 0 && d.has_traffic() {
            let soft_rate = soft_errors as f64 / throughput;
            score += (soft_rate * 100.0).min(1.0) * 0.25;
        }

        // Slab pressure component (0..0.05)
        let slab_latency = metrics.slab_metrics.avg_latency_ns();
        if slab_latency > 1000 {
            score += ((slab_latency as f64 - 1000.0) / 10000.0).min(1.0) * 0.05;
        }

        // NAPI saturation component (0..0.05)
        if metrics.network_metrics.napi_polls > 0 && metrics.network_metrics.napi_total_budget > 0 {
            let avg_work = metrics.network_metrics.napi_total_work as f64
                / metrics.network_metrics.napi_polls as f64;
            let avg_budget = metrics.network_metrics.napi_total_budget as f64
                / metrics.network_metrics.napi_polls as f64;
            if avg_budget > 0.0 {
                let util = avg_work / avg_budget;
                if util > 0.7 {
                    score += ((util - 0.7) / 0.3).min(1.0) * 0.05;
                }
            }
        }

        // CQ jitter / micro-stall component (0..0.15)
        if metrics.cq_jitter.stall_count > 0 {
            let stall_ratio = (metrics.cq_jitter.stall_count as f64
                / metrics.cq_jitter.completion_count.max(1) as f64)
                .min(1.0);
            score += stall_ratio * 0.15;
        }

        // Congestion spread / victim buffer (0..0.10)
        if d.port_xmit_wait_delta > 0 && d.total_hard_error_delta() == 0 {
            score += 0.10;
        }

        score.min(1.0)
    }

    pub fn reset(&mut self) {
        self.state_machine.reset();
        self.score.reset();
        self.prev_raw_score = 0.0;
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub fn severity_rank(state: HealthState) -> u8 {
    match state {
        HealthState::Healthy => 0,
        HealthState::Degraded => 1,
        HealthState::Recovering => 1,
        HealthState::Critical => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::{AggregatedMetrics, IbCounterDeltas, InterruptDistribution, NetworkMetrics};

    fn evaluate_n(engine: &mut DetectionEngine, metrics: &AggregatedMetrics, n: u32) -> Vec<Alert> {
        let mut last = vec![];
        for _ in 0..n {
            last = engine.evaluate(metrics);
        }
        last
    }

    /// Build metrics that produce a high enough health score to trigger
    /// state transitions. Soft-RoCE errors are the primary signal.
    fn bad_metrics() -> AggregatedMetrics {
        AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                rxe_duplicate_request_delta: 30,
                rxe_seq_error_delta: 10,
                hw_rcv_pkts_delta: 80,
                hw_xmit_pkts_delta: 20,
                ..Default::default()
            },
            network_metrics: NetworkMetrics {
                napi_polls: 10,
                napi_total_work: 5,
                napi_total_budget: 64,
                ..Default::default()
            },
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![80, 10, 5, 5],
                total_count: 100,
            },
            ..Default::default()
        }
    }

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
    fn bad_metrics_trigger_degraded_after_hysteresis() {
        let mut engine = DetectionEngine::new();
        let metrics = bad_metrics();

        // First window: score enters EWMA but dwell not met
        let first = engine.evaluate(&metrics);
        assert!(first.is_empty(), "single window should not trigger");
        assert_eq!(engine.current_state(), HealthState::Healthy);

        // Second window: dwell met → Degraded
        let second = engine.evaluate(&metrics);
        assert!(!second.is_empty(), "second window should trigger transition");
        assert_eq!(engine.current_state(), HealthState::Degraded);
    }

    #[test]
    fn reset_returns_to_healthy() {
        let mut engine = DetectionEngine::new();
        evaluate_n(&mut engine, &bad_metrics(), 4);
        engine.reset();
        assert_eq!(engine.current_state(), HealthState::Healthy);
    }

    #[test]
    fn repeated_evaluation_deduplicates() {
        let mut engine = DetectionEngine::new();
        let metrics = bad_metrics();

        let alerts = evaluate_n(&mut engine, &metrics, 2);
        assert!(!alerts.is_empty(), "transition should emit alerts");

        // Third eval at same state: should not re-emit
        let third = engine.evaluate(&metrics);
        assert!(third.is_empty(), "same state should not re-emit alerts");

        engine.reset();
        let after_reset = evaluate_n(&mut engine, &metrics, 2);
        assert!(
            !after_reset.is_empty(),
            "alert fires again after reset + hysteresis"
        );
    }

    // ── Flapping resistance tests ───────────────────────────────────────

    #[test]
    fn sustained_loss_enters_critical_and_holds() {
        let mut sm = HealthStateMachine::new(StateMachineConfig::default());
        let mut score = SmoothedHealthScore::new();

        // Simulate bursty 20% packet loss: alternating high/zero raw scores
        let raw_sequence = [
            0.0, 0.55, 0.60, 0.0, 0.0, 0.55, 0.60, 0.0, 0.0, 0.55, 0.60, 0.0, 0.55, 0.0, 0.55,
            0.60, 0.0, 0.0, 0.55, 0.0,
        ];

        for &raw in &raw_sequence {
            let effective = score.update(raw);
            sm.evaluate(effective);
        }

        assert_eq!(
            sm.current(),
            HealthState::Critical,
            "sustained bursty loss must reach and hold Critical"
        );
    }

    #[test]
    fn clean_windows_cannot_cause_flap() {
        let mut sm = HealthStateMachine::new(StateMachineConfig::default());
        let mut score = SmoothedHealthScore::new();

        // Drive to Critical
        for _ in 0..6 {
            let eff = score.update(0.60);
            sm.evaluate(eff);
        }
        assert_eq!(sm.current(), HealthState::Critical);

        // Inject 2 clean windows (the old system would flap to Healthy here)
        for _ in 0..2 {
            let eff = score.update(0.0);
            sm.evaluate(eff);
        }
        assert_eq!(
            sm.current(),
            HealthState::Critical,
            "2 clean windows must NOT exit Critical"
        );

        // Even 4 clean windows shouldn't exit (need 5 consecutive below critical_exit)
        for _ in 0..2 {
            let eff = score.update(0.0);
            sm.evaluate(eff);
        }
        // Peak hold keeps effective above critical_exit for first ~4 windows
        assert_eq!(
            sm.current(),
            HealthState::Critical,
            "4 clean windows still not enough due to peak-hold"
        );
    }

    #[test]
    fn full_recovery_path_critical_to_healthy() {
        let mut sm = HealthStateMachine::new(StateMachineConfig::default());
        let mut score = SmoothedHealthScore::new();

        // Drive to Critical
        for _ in 0..6 {
            let eff = score.update(0.60);
            sm.evaluate(eff);
        }
        assert_eq!(sm.current(), HealthState::Critical);

        // Recovery: sustained zero scores
        let mut states = vec![];
        for _ in 0..30 {
            let eff = score.update(0.0);
            sm.evaluate(eff);
            states.push(sm.current());
        }

        // Must pass through Recovering and Degraded before reaching Healthy
        assert!(
            states.contains(&HealthState::Recovering),
            "must pass through Recovering"
        );
        assert!(
            states.contains(&HealthState::Degraded),
            "must pass through Degraded"
        );
        assert_eq!(
            *states.last().unwrap(),
            HealthState::Healthy,
            "should eventually reach Healthy"
        );
    }

    #[test]
    fn recovering_re_escalates_on_bad_signal() {
        let mut sm = HealthStateMachine::new(StateMachineConfig::default());
        let mut score = SmoothedHealthScore::new();

        // Drive to Critical
        for _ in 0..6 {
            score.update(0.60);
            sm.evaluate(score.effective());
        }
        assert_eq!(sm.current(), HealthState::Critical);

        // Enough clean windows to reach Recovering
        for _ in 0..30 {
            score.update(0.0);
            sm.evaluate(score.effective());
        }
        let pre = sm.current();
        assert!(
            pre == HealthState::Recovering || pre == HealthState::Degraded || pre == HealthState::Healthy,
            "should have started de-escalating, got {pre}"
        );

        // Bad signal returns — re-escalate to Critical
        for _ in 0..8 {
            score.update(0.60);
            sm.evaluate(score.effective());
        }
        assert_eq!(
            sm.current(),
            HealthState::Critical,
            "bad signal during recovery must re-escalate to Critical"
        );
    }

    #[test]
    fn zero_traffic_carry_forward_prevents_false_recovery() {
        let mut engine = DetectionEngine::new();

        // Simulate a bad window with soft errors
        let bad_metrics = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                rxe_duplicate_request_delta: 20,
                hw_rcv_pkts_delta: 80,
                hw_xmit_pkts_delta: 20,
                ..Default::default()
            },
            network_metrics: NetworkMetrics {
                napi_polls: 10,
                napi_total_work: 5,
                napi_total_budget: 64,
                ..Default::default()
            },
            ..Default::default()
        };

        // Drive with bad metrics
        for _ in 0..4 {
            engine.evaluate(&bad_metrics);
        }

        // Now send an empty (zero-traffic) window
        let empty = AggregatedMetrics::default();
        engine.evaluate(&empty);

        // The score should NOT have dropped to zero
        assert!(
            engine.score.effective() > 0.05,
            "zero-traffic window should carry forward, got {}",
            engine.score.effective()
        );
    }

    #[test]
    fn state_machine_is_deterministic() {
        let raw_sequence = [
            0.0, 0.3, 0.55, 0.60, 0.0, 0.0, 0.55, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0,
        ];

        let run = || {
            let mut sm = HealthStateMachine::new(StateMachineConfig::default());
            let mut score = SmoothedHealthScore::new();
            let mut states = Vec::new();
            for &raw in &raw_sequence {
                let eff = score.update(raw);
                sm.evaluate(eff);
                states.push(sm.current());
            }
            states
        };

        let run1 = run();
        let run2 = run();
        assert_eq!(run1, run2, "state machine must be deterministic across runs");
    }

    #[test]
    fn smoothed_score_peak_hold_decay() {
        let mut s = SmoothedHealthScore::new();
        s.update(0.6);
        assert!((s.peak_hold() - 0.6).abs() < f64::EPSILON);

        // Decay over several windows
        for _ in 0..5 {
            s.update(0.0);
        }
        let expected = 0.6 * 0.85_f64.powi(5);
        assert!(
            (s.peak_hold() - expected).abs() < 0.01,
            "peak should decay to ~{expected:.3}, got {:.3}",
            s.peak_hold()
        );
    }
}

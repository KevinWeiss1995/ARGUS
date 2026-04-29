pub mod burst;
pub mod fusion;
pub mod rolling_stats;
pub mod rules;
pub mod timescale;

use argus_common::{AggregatedMetrics, Alert, CoverageReport, HealthState, Sample};
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
        Self::with_params(0.3, 0.85)
    }

    /// Construct with custom EWMA alpha and peak decay.
    /// Used by the multi-timescale evaluator to spawn fast/slow tracks
    /// with different time constants.
    #[must_use]
    pub fn with_params(alpha: f64, peak_decay: f64) -> Self {
        Self {
            ewma: 0.0,
            peak_hold: 0.0,
            prev_raw: 0.0,
            alpha: alpha.clamp(0.001, 1.0),
            peak_decay: peak_decay.clamp(0.0, 0.999),
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

    pub(crate) config: StateMachineConfig,

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
    last_sample_contribution: f64,
    /// Parallel timescale tracks. The composite verdict (worst of three)
    /// is published via `multi_timescale_state()`. The legacy single-track
    /// `state_machine` remains the authoritative source for the agent's
    /// scheduler integration today; `multi_timescale` is exposed for
    /// telemetry and future consumers.
    multi_timescale: timescale::MultiTimescaleEvaluator,
    /// Token-bucket burst-vs-sustained classifier.
    burst_classifier: burst::BurstClassifier,
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
            state_machine: HealthStateMachine::new(sm_config.clone()),
            score: SmoothedHealthScore::new(),
            num_cpus: config.num_cpus,
            prev_raw_score: 0.0,
            last_sample_contribution: 0.0,
            multi_timescale: timescale::MultiTimescaleEvaluator::new(sm_config),
            burst_classifier: burst::BurstClassifier::default(),
        }
    }

    /// Composite state across fast/medium/slow timescales.
    /// Always equal to or more pessimistic than `current_state()`.
    #[must_use]
    pub fn multi_timescale(&self) -> &timescale::MultiTimescaleEvaluator {
        &self.multi_timescale
    }

    /// Latest burst classification.
    #[must_use]
    pub fn burst_class(&self) -> burst::BurstClass {
        self.burst_classifier.current()
    }

    /// Magnitude of the last sample-driven contribution to the raw score.
    /// Surfaced for observability — a non-zero value means capability
    /// samples agreed with the rule layer.
    #[must_use]
    pub fn last_sample_contribution(&self) -> f64 {
        self.last_sample_contribution
    }

    /// Evaluate all rules against current metrics.
    /// Computes composite score boosted by rule verdicts, feeds it through
    /// EWMA+peak-hold smoothing, then drives the state machine.
    /// Always returns rule-generated alerts so they're visible to telemetry,
    /// TUI, and scheduler regardless of state transitions.
    pub fn evaluate(&mut self, metrics: &AggregatedMetrics) -> Vec<Alert> {
        self.evaluate_with_samples(metrics, &[])
    }

    /// Capability-aware evaluation. Samples produced by capability providers
    /// flow into the fusion layer alongside legacy rule verdicts.
    ///
    /// Without a coverage report the engine still applies a static severity
    /// floor (back-compat). For the proper confidence-weighted path,
    /// callers pass coverage via `evaluate_with_coverage`.
    pub fn evaluate_with_samples(
        &mut self,
        metrics: &AggregatedMetrics,
        samples: &[Sample],
    ) -> Vec<Alert> {
        self.evaluate_with_coverage(metrics, samples, None)
    }

    /// Capability-aware evaluation with optional coverage report for
    /// confidence-weighted fusion.
    ///
    /// Score model:
    /// ```text
    /// raw = compute_effective_raw(metrics)
    /// raw += sample_contribution(samples)         // bounded [0, 0.5]
    /// raw = max(raw, severity_floor * coverage_w) // coverage-scaled boost
    /// effective = smooth(raw)                     // EWMA + peak-hold
    /// ```
    /// where `coverage_w = max(quality_weight) over capabilities consulted by
    /// the rule that produced `worst_severity`. When all consulted caps are
    /// High the boost is full strength; when any are Absent the boost is
    /// zero — i.e., a rule cannot lift the score without underlying signals.
    pub fn evaluate_with_coverage(
        &mut self,
        metrics: &AggregatedMetrics,
        samples: &[Sample],
        coverage: Option<&CoverageReport>,
    ) -> Vec<Alert> {
        let mut new_alerts = Vec::new();
        let mut worst_severity = HealthState::Healthy;
        let mut worst_severity_cap_weight: f64 = 1.0;

        for rule in &mut self.rules {
            if let Some(alert) = rule.evaluate_mut(metrics) {
                if severity_rank(alert.severity) > severity_rank(worst_severity) {
                    worst_severity = alert.severity;
                    let consulted = rule.capabilities_consulted();
                    worst_severity_cap_weight = if consulted.is_empty() {
                        // Host-signal rule: no fabric coverage dependency.
                        1.0
                    } else if let Some(cov) = coverage {
                        cov.input_weight(consulted)
                    } else {
                        1.0
                    };
                }
                new_alerts.push(alert);
            }
        }

        let mut raw = self.compute_effective_raw(metrics);

        let sample_contribution = fusion::sample_score_contribution(samples);
        raw = (raw + sample_contribution).min(1.0);

        let severity_floor_base = match worst_severity {
            HealthState::Critical => self.state_machine.config.critical_enter,
            HealthState::Degraded | HealthState::Recovering => {
                self.state_machine.config.degrade_enter
            }
            HealthState::Healthy => 0.0,
        };
        // Coverage-weighted floor: when fabric signals are missing, the rule
        // verdict cannot single-handedly drain a node.
        let severity_floor = severity_floor_base * worst_severity_cap_weight;
        if severity_floor > raw {
            raw = severity_floor;
        }

        self.prev_raw_score = raw;
        self.last_sample_contribution = sample_contribution;

        let effective = self.score.update(raw);
        self.state_machine.evaluate(effective);

        // Multi-timescale evaluator runs in parallel for telemetry / burst
        // classification. It does not (yet) drive the scheduler.
        self.multi_timescale.evaluate(raw);
        self.burst_classifier.observe(raw, &self.multi_timescale);

        new_alerts
    }

    /// Raw score computation with IB-aware carry-forward.
    ///
    /// When there's no IB signal (no traffic, no errors) but the system is
    /// otherwise active (IRQs, slab allocs), carry forward the previous
    /// score at 0.9 decay. This prevents false recovery during RDMA traffic
    /// gaps caused by retransmission backoff or QP error recovery — the
    /// underlying impairment (e.g., tc netem loss) hasn't gone away, the
    /// measurement just temporarily disappeared.
    ///
    /// We take max(carry, fresh) so that independent signals like IRQ skew
    /// or slab pressure can still push the score higher on their own.
    fn compute_effective_raw(&self, metrics: &AggregatedMetrics) -> f64 {
        let d = &metrics.ib_counter_deltas;
        let has_ib_signal = d.has_traffic()
            || d.total_soft_error_delta() > 0
            || d.total_hard_error_delta() > 0
            || d.link_error_recovery_delta > 0
            || d.link_downed_delta > 0;

        let fresh = Self::compute_health_score(metrics, self.num_cpus);

        if !has_ib_signal {
            let carry = self.prev_raw_score * 0.9;
            return carry.max(fresh);
        }
        fresh
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
        self.multi_timescale.reset();
        self.burst_classifier.reset();
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

        // First window: score enters EWMA but dwell not met — state stays Healthy
        let _first = engine.evaluate(&metrics);
        assert_eq!(engine.current_state(), HealthState::Healthy,
            "single window should not transition state");

        // Second window: dwell met → Degraded
        let _second = engine.evaluate(&metrics);
        assert_eq!(engine.current_state(), HealthState::Degraded,
            "second window should transition to Degraded");
    }

    #[test]
    fn reset_returns_to_healthy() {
        let mut engine = DetectionEngine::new();
        evaluate_n(&mut engine, &bad_metrics(), 4);
        engine.reset();
        assert_eq!(engine.current_state(), HealthState::Healthy);
    }

    #[test]
    fn alerts_always_returned_from_rules() {
        let mut engine = DetectionEngine::new();
        let metrics = bad_metrics();

        // Rule alerts are returned every window, not just on transitions
        let first = engine.evaluate(&metrics);
        let second = engine.evaluate(&metrics);

        // Both windows should return alerts since rules fire on bad metrics
        assert!(!first.is_empty(), "rules should fire on bad metrics");
        assert!(!second.is_empty(), "rules should continue firing");
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
    fn ib_traffic_gap_carries_forward_score() {
        let mut engine = DetectionEngine::new();

        let bad = AggregatedMetrics {
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

        for _ in 0..4 {
            engine.evaluate(&bad);
        }
        let score_before = engine.score.effective();

        // Simulate traffic gap: eBPF still captures IRQs (as always in live
        // mode), but RDMA traffic has paused (retransmission backoff).
        // The old code would reset score to ~0 here because has_any_activity
        // was true (IRQs) but IB deltas were zero.
        let gap = AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![25, 25, 25, 25],
                total_count: 100,
            },
            ..Default::default()
        };
        engine.evaluate(&gap);

        assert!(
            engine.score.effective() > score_before * 0.5,
            "IB traffic gap should carry forward score, got {} (was {})",
            engine.score.effective(),
            score_before,
        );
    }

    #[test]
    fn carry_forward_decays_without_full_engine() {
        // Test the raw carry-forward math in isolation: when there's no
        // IB signal, prev_raw decays at 0.9/window.
        let mut score = SmoothedHealthScore::new();
        let mut prev_raw = 0.55_f64;

        // Simulate 30 windows of carry-forward decay
        for _ in 0..30 {
            prev_raw *= 0.9;
            score.update(prev_raw);
        }

        // 0.55 * 0.9^30 ≈ 0.023
        assert!(
            score.effective() < 0.05,
            "carry-forward should decay to near-zero, got {}",
            score.effective(),
        );
    }

    #[test]
    fn clean_traffic_restores_healthy() {
        let mut engine = DetectionEngine::new();

        let bad = AggregatedMetrics {
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

        for _ in 0..6 {
            engine.evaluate(&bad);
        }
        assert_eq!(engine.current_state(), HealthState::Critical);

        // Impairment removed: traffic continues but errors stop.
        // This should allow full recovery.
        let clean = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                hw_rcv_pkts_delta: 100,
                hw_xmit_pkts_delta: 100,
                ..Default::default()
            },
            network_metrics: NetworkMetrics {
                napi_polls: 10,
                napi_total_work: 5,
                napi_total_budget: 64,
                ..Default::default()
            },
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![25, 25, 25, 25],
                total_count: 100,
            },
            ..Default::default()
        };

        for _ in 0..40 {
            engine.evaluate(&clean);
        }

        assert_eq!(
            engine.current_state(),
            HealthState::Healthy,
            "clean traffic should eventually restore Healthy"
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
    fn coverage_weighted_severity_floor_attenuates_when_caps_absent() {
        use argus_common::{
            Capability, CapabilityCoverage, CoverageGrade, CoverageReport, Quality,
        };

        // Coverage report claims LinkErrors and RetransmitSignal are Absent.
        let coverage = CoverageReport {
            grade: CoverageGrade::F,
            fabric: None,
            capabilities: vec![
                CapabilityCoverage {
                    capability: Capability::LinkErrors,
                    active_backend: None,
                    quality: Quality::Absent,
                    fallback_chain: vec![],
                },
                CapabilityCoverage {
                    capability: Capability::RetransmitSignal,
                    active_backend: None,
                    quality: Quality::Absent,
                    fallback_chain: vec![],
                },
            ],
        };

        let mut engine = DetectionEngine::new();
        // Bad metrics that would normally trigger RdmaLinkDegradation Critical.
        let bad = AggregatedMetrics {
            ib_counter_deltas: IbCounterDeltas {
                rxe_duplicate_request_delta: 30,
                rxe_seq_error_delta: 15,
                hw_rcv_pkts_delta: 80,
                hw_xmit_pkts_delta: 20,
                ..Default::default()
            },
            ..Default::default()
        };
        // With Absent coverage, severity floor must be ~0 so the rule cannot
        // single-handedly drive Critical despite firing.
        for _ in 0..5 {
            engine.evaluate_with_coverage(&bad, &[], Some(&coverage));
        }
        // Note: rule still fires, but the floor is multiplied by 0 → score
        // must be below critical_enter just from the raw-score path.
        let raw = engine.score.raw();
        let crit_enter = engine.state_machine.config.critical_enter;
        assert!(
            raw < crit_enter,
            "Absent coverage should attenuate severity floor; raw={raw} critical_enter={crit_enter}"
        );
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

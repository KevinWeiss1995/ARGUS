//! Multi-timescale evaluation tracks.
//!
//! The same per-window raw score feeds three parallel `SmoothedHealthScore`
//! + `HealthStateMachine` pairs, each tuned for a different time horizon:
//!
//! | Track  | Use-case                                      | Smoothing α | Peak decay | Enter dwell |
//! |--------|-----------------------------------------------|-------------|------------|-------------|
//! | Fast   | Detect transient bursts (microbursts, drops)  | 0.6         | 0.5        | 1           |
//! | Medium | Default; matches the historical engine        | 0.3         | 0.85       | 2           |
//! | Slow   | Sustained, multi-minute degradation           | 0.1         | 0.95       | 4           |
//!
//! The composite verdict is the worst observed state across tracks. This
//! makes ARGUS sensitive to both fast bursts (which the slow track would
//! otherwise smooth away) and slow drift (which the fast track would
//! otherwise have already de-escalated).

use argus_common::HealthState;

use super::{HealthStateMachine, SmoothedHealthScore, StateMachineConfig};

/// One of three named time horizons. Used in metrics labels and logs.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum Timescale {
    Fast,
    Medium,
    Slow,
}

impl Timescale {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Medium => "medium",
            Self::Slow => "slow",
        }
    }

    #[must_use]
    pub fn all() -> [Timescale; 3] {
        [Self::Fast, Self::Medium, Self::Slow]
    }
}

/// One score+state-machine pair plus its declared timescale.
pub struct TimescaleTrack {
    pub timescale: Timescale,
    pub score: SmoothedHealthScore,
    pub state_machine: HealthStateMachine,
}

impl TimescaleTrack {
    #[must_use]
    pub fn fast(base: &StateMachineConfig) -> Self {
        let mut cfg = base.clone();
        cfg.enter_windows = 1;
        cfg.exit_windows = 2.max(base.exit_windows / 2);
        Self {
            timescale: Timescale::Fast,
            score: SmoothedHealthScore::with_params(0.6, 0.5),
            state_machine: HealthStateMachine::new(cfg),
        }
    }

    #[must_use]
    pub fn medium(base: &StateMachineConfig) -> Self {
        Self {
            timescale: Timescale::Medium,
            score: SmoothedHealthScore::with_params(0.3, 0.85),
            state_machine: HealthStateMachine::new(base.clone()),
        }
    }

    #[must_use]
    pub fn slow(base: &StateMachineConfig) -> Self {
        let mut cfg = base.clone();
        cfg.enter_windows = base.enter_windows.saturating_mul(2).max(4);
        cfg.exit_windows = base.exit_windows.saturating_mul(2).max(8);
        Self {
            timescale: Timescale::Slow,
            score: SmoothedHealthScore::with_params(0.1, 0.95),
            state_machine: HealthStateMachine::new(cfg),
        }
    }

    /// Feed one raw score; returns the resulting state.
    pub fn evaluate(&mut self, raw: f64) -> HealthState {
        let eff = self.score.update(raw);
        self.state_machine.evaluate(eff);
        self.state_machine.current()
    }
}

/// Holds all three tracks. The composite state is the worst observed.
pub struct MultiTimescaleEvaluator {
    pub fast: TimescaleTrack,
    pub medium: TimescaleTrack,
    pub slow: TimescaleTrack,
}

impl MultiTimescaleEvaluator {
    #[must_use]
    pub fn new(base: StateMachineConfig) -> Self {
        Self {
            fast: TimescaleTrack::fast(&base),
            medium: TimescaleTrack::medium(&base),
            slow: TimescaleTrack::slow(&base),
        }
    }

    /// Feed the same raw score to all tracks. Returns the composite state.
    pub fn evaluate(&mut self, raw: f64) -> HealthState {
        let f = self.fast.evaluate(raw);
        let m = self.medium.evaluate(raw);
        let s = self.slow.evaluate(raw);
        worst_of([f, m, s])
    }

    /// Per-track current state, for telemetry and the burst classifier.
    #[must_use]
    pub fn states(&self) -> [(Timescale, HealthState); 3] {
        [
            (Timescale::Fast, self.fast.state_machine.current()),
            (Timescale::Medium, self.medium.state_machine.current()),
            (Timescale::Slow, self.slow.state_machine.current()),
        ]
    }

    /// Per-track effective score, for telemetry.
    #[must_use]
    pub fn effective_scores(&self) -> [(Timescale, f64); 3] {
        [
            (Timescale::Fast, self.fast.score.effective()),
            (Timescale::Medium, self.medium.score.effective()),
            (Timescale::Slow, self.slow.score.effective()),
        ]
    }

    pub fn reset(&mut self) {
        self.fast.score.reset();
        self.fast.state_machine.reset();
        self.medium.score.reset();
        self.medium.state_machine.reset();
        self.slow.score.reset();
        self.slow.state_machine.reset();
    }
}

fn worst_of(states: [HealthState; 3]) -> HealthState {
    states
        .into_iter()
        .max_by_key(|s| match s {
            HealthState::Healthy => 0,
            HealthState::Degraded | HealthState::Recovering => 1,
            HealthState::Critical => 2,
        })
        .unwrap_or(HealthState::Healthy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_track_picks_up_bursts_first() {
        let mut e = MultiTimescaleEvaluator::new(StateMachineConfig::default());
        // One big spike — only fast should react quickly.
        e.evaluate(0.7);
        e.evaluate(0.7);
        let states: std::collections::HashMap<Timescale, HealthState> =
            e.states().into_iter().collect();
        assert!(
            states[&Timescale::Fast] != HealthState::Healthy,
            "fast track should escalate quickly: {:?}",
            states
        );
    }

    #[test]
    fn slow_track_resists_short_spikes() {
        let mut e = MultiTimescaleEvaluator::new(StateMachineConfig::default());
        // 2-window spike followed by sustained quiet (~realistic for slow)
        e.evaluate(0.7);
        e.evaluate(0.7);
        for _ in 0..40 {
            e.evaluate(0.0);
        }
        let states: std::collections::HashMap<Timescale, HealthState> =
            e.states().into_iter().collect();
        // Slow track must NOT reach Critical from a 2-window spike.
        // It may briefly Degrade due to peak-hold persistence, then recover.
        assert!(
            states[&Timescale::Slow] != HealthState::Critical,
            "slow track must not reach Critical on a 2-window spike: {:?}",
            states
        );
    }

    #[test]
    fn composite_is_worst_of_tracks() {
        let mut e = MultiTimescaleEvaluator::new(StateMachineConfig::default());
        let composite = e.evaluate(0.7);
        // Composite should match the fast track on first sustained spike.
        let _ = composite;
        let composite2 = e.evaluate(0.7);
        // After 2 windows at 0.7, fast track should be Critical or Degraded.
        assert!(
            composite2 != HealthState::Healthy,
            "composite must escalate at least to Degraded on sustained 0.7"
        );
    }
}

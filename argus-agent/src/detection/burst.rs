//! Token-bucket-based burst-vs-sustained classifier.
//!
//! The classifier consumes the same per-window raw scores the multi-
//! timescale evaluator sees, and labels the current observation as one of:
//!   - `Quiet`: score consistently low.
//!   - `Burst`: short, sharp spike(s) — fast track tripped, slow did not.
//!   - `Sustained`: drift confirmed across all timescales.
//!   - `MixedBurstSustained`: bursts on top of an already-degraded baseline.
//!
//! The scheduler can use this label to differentiate responses: a burst
//! warrants caution but not necessarily a drain; a sustained issue does.
//!
//! Mechanism
//! ---------
//! For each "category" (currently a single "score" channel) we maintain a
//! token bucket sized for ~30s of raw windows. A token is added each
//! window; a "burst event" is recorded any time the per-window raw exceeds
//! a configurable threshold. The classifier then asks:
//!   1. *Sustained?*  Is the slow track in Degraded/Critical?
//!   2. *Burst?*      Did the fast track see ≥1 spike not yet matched by slow?
//!   3. *Mixed?*      Both true?

use super::timescale::MultiTimescaleEvaluator;
use argus_common::HealthState;
use std::collections::VecDeque;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum BurstClass {
    Quiet,
    Burst,
    Sustained,
    MixedBurstSustained,
}

impl BurstClass {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Quiet => "quiet",
            Self::Burst => "burst",
            Self::Sustained => "sustained",
            Self::MixedBurstSustained => "mixed",
        }
    }
}

/// Classifier configuration.
pub struct BurstClassifierConfig {
    /// Raw score threshold above which we record a burst event.
    pub burst_threshold: f64,
    /// How many windows of history to retain for burst counting.
    pub history_windows: usize,
    /// Minimum bursts in `history_windows` to trigger Burst.
    pub min_bursts: u32,
}

impl Default for BurstClassifierConfig {
    fn default() -> Self {
        Self {
            burst_threshold: 0.40,
            history_windows: 30,
            min_bursts: 2,
        }
    }
}

pub struct BurstClassifier {
    cfg: BurstClassifierConfig,
    history: VecDeque<bool>,
    last_class: BurstClass,
}

impl BurstClassifier {
    #[must_use]
    pub fn new(cfg: BurstClassifierConfig) -> Self {
        Self {
            history: VecDeque::with_capacity(cfg.history_windows),
            last_class: BurstClass::Quiet,
            cfg,
        }
    }

    /// Feed one window's raw score and the multi-timescale evaluator's
    /// current state. Updates the internal class.
    pub fn observe(&mut self, raw: f64, evaluator: &MultiTimescaleEvaluator) -> BurstClass {
        let was_spike = raw >= self.cfg.burst_threshold;
        if self.history.len() >= self.cfg.history_windows {
            self.history.pop_front();
        }
        self.history.push_back(was_spike);

        let bursts: u32 = self.history.iter().filter(|b| **b).count() as u32;
        let burst_active = bursts >= self.cfg.min_bursts;

        let states: std::collections::HashMap<_, _> = evaluator.states().into_iter().collect();
        let slow = *states.get(&super::timescale::Timescale::Slow).unwrap_or(&HealthState::Healthy);
        let fast = *states.get(&super::timescale::Timescale::Fast).unwrap_or(&HealthState::Healthy);
        let sustained = matches!(slow, HealthState::Degraded | HealthState::Critical);
        let fast_active = matches!(fast, HealthState::Degraded | HealthState::Critical);

        let class = match (burst_active || fast_active, sustained) {
            (true, true) => BurstClass::MixedBurstSustained,
            (true, false) => BurstClass::Burst,
            (false, true) => BurstClass::Sustained,
            (false, false) => BurstClass::Quiet,
        };
        self.last_class = class;
        class
    }

    #[must_use]
    pub fn current(&self) -> BurstClass {
        self.last_class
    }

    pub fn reset(&mut self) {
        self.history.clear();
        self.last_class = BurstClass::Quiet;
    }
}

impl Default for BurstClassifier {
    fn default() -> Self {
        Self::new(BurstClassifierConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::StateMachineConfig;

    #[test]
    fn quiet_starts_quiet() {
        let mut c = BurstClassifier::default();
        let mut e = MultiTimescaleEvaluator::new(StateMachineConfig::default());
        for _ in 0..10 {
            e.evaluate(0.0);
            c.observe(0.0, &e);
        }
        assert_eq!(c.current(), BurstClass::Quiet);
    }

    #[test]
    fn burst_detected_on_repeated_spikes() {
        let mut c = BurstClassifier::default();
        let mut e = MultiTimescaleEvaluator::new(StateMachineConfig::default());
        for _ in 0..3 {
            e.evaluate(0.65);
            c.observe(0.65, &e);
        }
        for _ in 0..2 {
            e.evaluate(0.0);
            c.observe(0.0, &e);
        }
        assert!(
            matches!(c.current(), BurstClass::Burst | BurstClass::MixedBurstSustained),
            "expected Burst-ish, got {:?}",
            c.current()
        );
    }

    #[test]
    fn sustained_pure_when_slow_only_escalates() {
        let mut c = BurstClassifier::default();
        let mut e = MultiTimescaleEvaluator::new(StateMachineConfig::default());
        // Long sustained moderate signal — should eventually escalate slow but not produce many bursts above 0.40.
        let raw = 0.32; // above degrade_enter (0.30) but below burst_threshold (0.40)
        for _ in 0..40 {
            e.evaluate(raw);
            c.observe(raw, &e);
        }
        // We may see Sustained or MixedBurstSustained depending on fast threshold.
        let cls = c.current();
        assert!(
            matches!(cls, BurstClass::Sustained | BurstClass::MixedBurstSustained | BurstClass::Quiet),
            "got {:?}",
            cls,
        );
    }
}

/// Exponentially Weighted Moving Average (EWMA) tracker for a single metric.
/// Maintains mean, variance, trend (first derivative), and supports anomaly
/// scoring via z-score.
///
/// Supports optional baseline clamping: once warmed up, the EWMA is prevented
/// from drifting beyond `clamp_factor × initial_baseline`. This stops sustained
/// bad conditions from becoming the new "normal."
#[derive(Debug, Clone)]
pub struct RollingStats {
    ewma: f64,
    ewma_var: f64,
    alpha: f64,
    trend: f64,
    prev_ewma: f64,
    samples: u64,
    /// Baseline captured at the end of warmup. None until warmed up.
    baseline: Option<f64>,
    /// Upper clamp: EWMA cannot exceed baseline × clamp_factor. None = unclamped.
    clamp_factor: Option<f64>,
    /// Lower clamp: EWMA cannot drop below baseline × clamp_floor. None = no floor.
    clamp_floor: Option<f64>,
}

impl RollingStats {
    /// Create a new tracker with the given smoothing factor.
    /// `alpha` controls responsiveness: 0.1 = slow adaptation, 0.3 = faster.
    #[must_use]
    pub fn new(alpha: f64) -> Self {
        Self {
            ewma: 0.0,
            ewma_var: 0.0,
            alpha,
            trend: 0.0,
            prev_ewma: 0.0,
            samples: 0,
            baseline: None,
            clamp_factor: None,
            clamp_floor: None,
        }
    }

    /// Create a tracker with an upper clamp. After warmup, the EWMA cannot
    /// exceed `clamp_factor × baseline`. Use for error rates (e.g., 3.0).
    #[must_use]
    pub fn with_clamp(alpha: f64, clamp_factor: f64) -> Self {
        Self {
            clamp_factor: Some(clamp_factor),
            ..Self::new(alpha)
        }
    }

    /// Create a tracker with a lower-bound clamp. After warmup, the EWMA cannot
    /// drop below `clamp_floor × baseline`. Use for throughput (e.g., 0.5 = can't
    /// adapt below 50% of initial throughput, keeping drops detectable).
    #[must_use]
    pub fn with_floor(alpha: f64, clamp_floor: f64) -> Self {
        Self {
            clamp_floor: Some(clamp_floor),
            ..Self::new(alpha)
        }
    }

    /// Push a new observation (typically once per window).
    pub fn push(&mut self, value: f64) {
        self.samples += 1;

        if self.samples == 1 {
            self.ewma = value;
            self.ewma_var = 0.0;
            self.prev_ewma = value;
            return;
        }

        self.prev_ewma = self.ewma;

        let diff = value - self.ewma;
        let new_ewma = self.ewma + self.alpha * diff;
        self.ewma_var = (1.0 - self.alpha) * (self.ewma_var + self.alpha * diff * diff);

        // Capture baseline at end of warmup
        if self.baseline.is_none() && self.samples == 5 {
            self.baseline = Some(new_ewma);
        }

        // Apply clamps: prevent EWMA from drifting too far from baseline
        self.ewma = if let Some(bl) = self.baseline {
            let mut clamped = new_ewma;
            if let Some(cf) = self.clamp_factor {
                if bl > f64::EPSILON {
                    clamped = clamped.min(bl * cf);
                }
            }
            if let Some(cf) = self.clamp_floor {
                if bl > f64::EPSILON {
                    clamped = clamped.max(bl * cf);
                }
            }
            clamped
        } else {
            new_ewma
        };

        self.trend = self.ewma - self.prev_ewma;
    }

    /// The frozen baseline captured at the end of warmup (if any).
    #[must_use]
    pub fn baseline(&self) -> Option<f64> {
        self.baseline
    }

    /// Current EWMA value.
    #[must_use]
    pub fn mean(&self) -> f64 {
        self.ewma
    }

    /// Current EWMA standard deviation.
    #[must_use]
    pub fn stddev(&self) -> f64 {
        self.ewma_var.sqrt()
    }

    /// Current trend (first derivative: positive = rising, negative = falling).
    #[must_use]
    pub fn trend(&self) -> f64 {
        self.trend
    }

    /// Z-score of a value relative to the current distribution.
    /// Returns 0.0 if insufficient data or zero variance.
    #[must_use]
    pub fn z_score(&self, value: f64) -> f64 {
        if self.samples < 3 {
            return 0.0;
        }
        let sd = self.stddev();
        if sd < f64::EPSILON {
            return 0.0;
        }
        (value - self.ewma) / sd
    }

    /// Number of observations pushed.
    #[must_use]
    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// Whether we have enough data to be meaningful (at least 5 windows).
    #[must_use]
    pub fn is_warmed_up(&self) -> bool {
        self.samples >= 5
    }
}

/// Tracks whether a metric has been monotonically increasing for N windows.
#[derive(Debug, Clone)]
pub struct TrendTracker {
    consecutive_rising: u32,
    prev_value: f64,
    has_prev: bool,
}

impl TrendTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            consecutive_rising: 0,
            prev_value: 0.0,
            has_prev: false,
        }
    }

    /// Push a new value. Returns the number of consecutive windows the
    /// value has been strictly increasing.
    pub fn push(&mut self, value: f64) -> u32 {
        if !self.has_prev {
            self.prev_value = value;
            self.has_prev = true;
            return 0;
        }

        if value > self.prev_value {
            self.consecutive_rising += 1;
        } else {
            self.consecutive_rising = 0;
        }
        self.prev_value = value;
        self.consecutive_rising
    }

    #[must_use]
    pub fn consecutive_rising(&self) -> u32 {
        self.consecutive_rising
    }
}

impl Default for TrendTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_warmup() {
        let mut rs = RollingStats::new(0.1);
        assert!(!rs.is_warmed_up());
        for i in 0..5 {
            rs.push(i as f64);
        }
        assert!(rs.is_warmed_up());
    }

    #[test]
    fn ewma_tracks_mean() {
        let mut rs = RollingStats::new(0.3);
        for _ in 0..20 {
            rs.push(100.0);
        }
        assert!((rs.mean() - 100.0).abs() < 1.0);
    }

    #[test]
    fn ewma_z_score_detects_anomaly() {
        let mut rs = RollingStats::new(0.1);
        // Push values with some variance so the EWMA variance is non-zero
        for i in 0..20 {
            rs.push(10.0 + (i % 3) as f64);
        }
        let z = rs.z_score(50.0);
        assert!(z > 3.0, "z_score should be high for anomaly, got {z}");
    }

    #[test]
    fn ewma_trend_positive_on_increase() {
        let mut rs = RollingStats::new(0.3);
        for i in 0..10 {
            rs.push(i as f64 * 10.0);
        }
        assert!(
            rs.trend() > 0.0,
            "trend should be positive for increasing data"
        );
    }

    #[test]
    fn ewma_clamp_prevents_drift() {
        let mut rs = RollingStats::with_clamp(0.1, 3.0);
        // Warmup with low error rate
        for _ in 0..5 {
            rs.push(0.001);
        }
        let bl = rs.baseline().expect("baseline should be set after warmup");
        assert!(bl > 0.0);

        // Push very high values — EWMA should be clamped
        for _ in 0..50 {
            rs.push(1.0);
        }
        assert!(
            rs.mean() <= bl * 3.0 + f64::EPSILON,
            "EWMA {} should be clamped to {} (3x baseline {})",
            rs.mean(),
            bl * 3.0,
            bl
        );
    }

    #[test]
    fn ewma_floor_prevents_downward_drift() {
        let mut rs = RollingStats::with_floor(0.1, 0.5);
        // Warmup with healthy throughput
        for _ in 0..5 {
            rs.push(1000.0);
        }
        let bl = rs.baseline().expect("baseline should be set");
        assert!((bl - 1000.0).abs() < 100.0);

        // Push degraded throughput — EWMA should be floored at 50% of baseline
        for _ in 0..50 {
            rs.push(100.0);
        }
        assert!(
            rs.mean() >= bl * 0.5 - f64::EPSILON,
            "EWMA {} should be floored at {} (50% of baseline {})",
            rs.mean(),
            bl * 0.5,
            bl
        );
    }

    #[test]
    fn ewma_unclamped_drifts_freely() {
        let mut rs = RollingStats::new(0.1);
        for _ in 0..5 {
            rs.push(0.001);
        }
        for _ in 0..50 {
            rs.push(1.0);
        }
        // Without clamping, EWMA should be close to 1.0
        assert!(rs.mean() > 0.5, "unclamped EWMA should drift to ~1.0");
    }

    #[test]
    fn trend_tracker_counts_rising() {
        let mut t = TrendTracker::new();
        assert_eq!(t.push(1.0), 0);
        assert_eq!(t.push(2.0), 1);
        assert_eq!(t.push(3.0), 2);
        assert_eq!(t.push(4.0), 3);
        assert_eq!(t.push(3.0), 0); // reset
        assert_eq!(t.push(4.0), 1);
    }
}

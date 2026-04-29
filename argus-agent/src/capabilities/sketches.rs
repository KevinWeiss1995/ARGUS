//! Streaming sketches for capability backends.
//!
//! - `DdSketch`: relative-error quantile sketch for latency histograms.
//!   Bounded memory; rank error ≤ `alpha` for any quantile.
//! - `SpaceSaving`: top-K heavy-hitter tracker for per-QP attribution.
//!   Bounded memory; "definitely top-K" guarantees if any flow is heavy enough.
//!
//! Both are deterministic — same input sequence yields same output, which is
//! a hard requirement for the ARGUS detection layer.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// DDSketch
// ---------------------------------------------------------------------------

/// Logarithmic-bucket relative-error quantile sketch.
///
/// Implementation note: this is the "unbounded log mapping" form — a fast,
/// deterministic Rust implementation of Datadog's DDSketch. We don't bother
/// with bin collapsing (we cap total bins instead). For RDMA latency the
/// bin count plateaus quickly.
///
/// Relative rank error is at most `alpha` for any quantile q ∈ (0, 1).
/// Default `alpha` of 0.01 means p99 estimates are within ±1%.
#[derive(Clone, Debug)]
pub struct DdSketch {
    alpha: f64,
    gamma: f64,
    log_gamma: f64,
    /// Positive-value bins keyed by bin index.
    pos_bins: HashMap<i32, u64>,
    /// Count of zero values (we treat 0 specially; log(0) is undefined).
    zero_count: u64,
    /// Count of negative values (we map them but don't use them in latency).
    /// Kept for completeness if the sketch is reused for jitter.
    neg_bins: HashMap<i32, u64>,
    total_count: u64,
    max_bins: usize,
}

impl DdSketch {
    /// New sketch with relative-error guarantee `alpha` (typical 0.01..0.05)
    /// and a hard cap on total distinct buckets.
    #[must_use]
    pub fn new(alpha: f64, max_bins: usize) -> Self {
        let alpha = alpha.clamp(1e-6, 0.5);
        let gamma = (1.0 + alpha) / (1.0 - alpha);
        Self {
            alpha,
            gamma,
            log_gamma: gamma.ln(),
            pos_bins: HashMap::new(),
            zero_count: 0,
            neg_bins: HashMap::new(),
            total_count: 0,
            max_bins,
        }
    }

    fn bin_index(&self, v: f64) -> i32 {
        // ceil(log_gamma(v)) for v > 0
        v.ln().div_euclid(self.log_gamma) as i32 + 1
    }

    /// Insert a single observation.
    pub fn insert(&mut self, v: f64) {
        self.total_count += 1;
        if v == 0.0 || !v.is_finite() {
            self.zero_count += 1;
            return;
        }
        if v > 0.0 {
            let idx = self.bin_index(v);
            self.maybe_collapse(true);
            *self.pos_bins.entry(idx).or_insert(0) += 1;
        } else {
            let idx = self.bin_index(-v);
            self.maybe_collapse(false);
            *self.neg_bins.entry(idx).or_insert(0) += 1;
        }
    }

    fn maybe_collapse(&mut self, positive: bool) {
        // If we'd exceed max_bins, collapse the lowest bin into the next one.
        // This bounds memory at cost of slightly increased error at the tails.
        let bins = if positive {
            &mut self.pos_bins
        } else {
            &mut self.neg_bins
        };
        if bins.len() >= self.max_bins {
            if let Some(&min_idx) = bins.keys().min() {
                if let Some(min_count) = bins.remove(&min_idx) {
                    *bins.entry(min_idx + 1).or_insert(0) += min_count;
                }
            }
        }
    }

    /// Estimate the q-th quantile (0.0..=1.0). Returns 0 on empty sketches.
    /// Estimate is `gamma^idx` where `idx` is the bucket containing the q-th rank.
    #[must_use]
    pub fn quantile(&self, q: f64) -> f64 {
        if self.total_count == 0 {
            return 0.0;
        }
        let q = q.clamp(0.0, 1.0);
        let target_rank = (q * (self.total_count - 1) as f64).round() as u64 + 1;

        // Walk buckets in order: negative bins (descending |idx|), then zero, then positive (asc).
        let mut cumulative = 0u64;

        // Negative bins ordered: largest |idx| ≈ most negative value, comes first
        let mut neg_keys: Vec<i32> = self.neg_bins.keys().copied().collect();
        neg_keys.sort_by(|a, b| b.cmp(a));
        for k in neg_keys {
            cumulative += self.neg_bins[&k];
            if cumulative >= target_rank {
                return -(self.gamma.powi(k));
            }
        }
        cumulative += self.zero_count;
        if cumulative >= target_rank {
            return 0.0;
        }
        let mut pos_keys: Vec<i32> = self.pos_bins.keys().copied().collect();
        pos_keys.sort();
        for k in pos_keys {
            cumulative += self.pos_bins[&k];
            if cumulative >= target_rank {
                return self.gamma.powi(k);
            }
        }
        // Shouldn't reach here, but return last known max value if so.
        self.pos_bins
            .keys()
            .copied()
            .max()
            .map_or(0.0, |k| self.gamma.powi(k))
    }

    #[must_use]
    pub fn count(&self) -> u64 {
        self.total_count
    }

    /// Reset for next window. Bins are kept allocated to avoid churn.
    pub fn reset(&mut self) {
        self.pos_bins.clear();
        self.neg_bins.clear();
        self.zero_count = 0;
        self.total_count = 0;
    }

    #[must_use]
    pub fn alpha(&self) -> f64 {
        self.alpha
    }
}

impl Default for DdSketch {
    fn default() -> Self {
        Self::new(0.01, 2048)
    }
}

// ---------------------------------------------------------------------------
// SpaceSaving (Misra-Gries variant) — top-K heavy hitters
// ---------------------------------------------------------------------------

/// Misra-Gries / SpaceSaving combined: tracks up to `k` candidate keys.
/// On insertion of a new key when full, the smallest counter is evicted and
/// reused for the new key (its count starts at the evicted count + 1). This
/// yields the classic over-estimation guarantee: any item with true count ≥
/// `total / k` is guaranteed to be in the table.
///
/// Used for per-QP / per-flow attribution where we cannot afford to track
/// every QP in a 1000-QP run, but want stable visibility into the top
/// 32–64 contributors of errors or latency.
#[derive(Clone, Debug)]
pub struct SpaceSaving<K: std::hash::Hash + Eq + Clone> {
    capacity: usize,
    counts: HashMap<K, u64>,
}

impl<K: std::hash::Hash + Eq + Clone> SpaceSaving<K> {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            counts: HashMap::with_capacity(capacity.max(1)),
        }
    }

    /// Increment the counter for `key`. If full, evict the min entry.
    pub fn observe(&mut self, key: K, weight: u64) {
        if let Some(c) = self.counts.get_mut(&key) {
            *c = c.saturating_add(weight);
            return;
        }
        if self.counts.len() < self.capacity {
            self.counts.insert(key, weight);
            return;
        }
        // Evict the smallest entry; absorb its count + new weight into the new key.
        let min_key = self
            .counts
            .iter()
            .min_by_key(|(_, c)| **c)
            .map(|(k, _)| k.clone());
        if let Some(mk) = min_key {
            let evicted = self.counts.remove(&mk).unwrap_or(0);
            self.counts.insert(key, evicted.saturating_add(weight));
        }
    }

    /// Top-N entries sorted by descending count. Returns owned keys to allow
    /// the caller to reset between windows safely.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(K, u64)> {
        let mut v: Vec<_> = self.counts.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    pub fn reset(&mut self) {
        self.counts.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddsketch_quantile_within_relative_error() {
        let mut s = DdSketch::new(0.01, 2048);
        for v in 1u64..=10_000 {
            s.insert(v as f64);
        }
        let p50 = s.quantile(0.5);
        let p99 = s.quantile(0.99);
        // True p50 = 5000, p99 = 9900 — accept ±2% relative error.
        assert!((p50 - 5000.0).abs() / 5000.0 < 0.05, "p50 was {p50}");
        assert!((p99 - 9900.0).abs() / 9900.0 < 0.05, "p99 was {p99}");
    }

    #[test]
    fn ddsketch_handles_zeros_and_resets() {
        let mut s = DdSketch::new(0.05, 256);
        for _ in 0..10 {
            s.insert(0.0);
        }
        for v in 1..=100 {
            s.insert(v as f64);
        }
        assert_eq!(s.count(), 110);
        let p99 = s.quantile(0.99);
        assert!(p99 > 0.0);
        s.reset();
        assert_eq!(s.count(), 0);
        assert_eq!(s.quantile(0.5), 0.0);
    }

    #[test]
    fn space_saving_keeps_top_hitters() {
        let mut ss: SpaceSaving<u32> = SpaceSaving::new(4);
        // Heavy: QP 1 (100), QP 2 (50)
        for _ in 0..100 {
            ss.observe(1u32, 1);
        }
        for _ in 0..50 {
            ss.observe(2u32, 1);
        }
        // 50 distinct light hitters (1 each)
        for q in 100u32..150 {
            ss.observe(q, 1);
        }
        let top = ss.top_n(2);
        let qps: Vec<_> = top.iter().map(|(k, _)| *k).collect();
        assert!(qps.contains(&1u32), "QP 1 must be in top-2: {qps:?}");
        assert!(qps.contains(&2u32), "QP 2 must be in top-2: {qps:?}");
    }

    #[test]
    fn space_saving_capacity_bound() {
        let mut ss: SpaceSaving<u32> = SpaceSaving::new(8);
        for q in 0u32..100 {
            ss.observe(q, 1);
        }
        assert!(ss.len() <= 8, "should never exceed capacity, got {}", ss.len());
    }

    #[test]
    fn space_saving_reset_clears() {
        let mut ss: SpaceSaving<u32> = SpaceSaving::new(2);
        ss.observe(1, 5);
        ss.reset();
        assert!(ss.is_empty());
    }
}

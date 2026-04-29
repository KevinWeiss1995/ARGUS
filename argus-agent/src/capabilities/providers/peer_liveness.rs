//! PeerLiveness capability — reads probe snapshots written by `argus-probe`.
//!
//! Decoupling the prober from the main agent keeps the agent's hot path
//! short: probing is a side process, the agent just consumes its output.
//!
//! Sample shape: one `Sample` per peer, with `value` = max RTT (us) and
//! `device` = peer name. When the snapshot is missing or stale (older than
//! 3× interval), the provider emits no samples and probes Unavailable.

use crate::capabilities::{
    CapabilityProvider, DetectionContext, FabricEnv, ProbeOutcome,
};
use argus_common::{BackendId, Capability, Quality, Sample};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::SystemTime;

const DEFAULT_PATH: &str = "/var/run/argus/probe.json";
const STALE_FACTOR: u64 = 3;
const FALLBACK_INTERVAL_SECS: u64 = 30;

#[derive(Deserialize)]
struct ProbeResult {
    peer: String,
    rtt_us: Option<u64>,
}

#[derive(Deserialize)]
struct ProbeSnapshot {
    timestamp_unix: u64,
    interval_secs: u64,
    results: Vec<ProbeResult>,
}

pub struct PeerLivenessProvider {
    path: PathBuf,
}

impl PeerLivenessProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_PATH),
        }
    }

    /// Override the probe-snapshot path (useful for tests).
    #[must_use]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Default for PeerLivenessProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityProvider for PeerLivenessProvider {
    fn id(&self) -> BackendId {
        BackendId::ActiveProber
    }
    fn capability(&self) -> Capability {
        Capability::PeerLiveness
    }
    fn declared_quality(&self) -> Quality {
        Quality::Medium
    }
    fn probe(&mut self, _env: &FabricEnv) -> ProbeOutcome {
        // Available if the snapshot file exists and is not too old.
        match std::fs::metadata(&self.path) {
            Ok(meta) => {
                if let Ok(modified) = meta.modified() {
                    let now = SystemTime::now();
                    let age = now.duration_since(modified).map(|d| d.as_secs()).unwrap_or(u64::MAX);
                    if age <= STALE_FACTOR * FALLBACK_INTERVAL_SECS {
                        return ProbeOutcome::Available {
                            quality: Quality::Medium,
                        };
                    }
                }
                ProbeOutcome::Unavailable {
                    reason: format!(
                        "probe snapshot {} is stale or unreadable mtime",
                        self.path.display()
                    ),
                }
            }
            Err(_) => ProbeOutcome::Unavailable {
                reason: format!("probe snapshot {} not present", self.path.display()),
            },
        }
    }

    fn collect(&mut self, ctx: &DetectionContext<'_>) -> Vec<Sample> {
        let Ok(content) = std::fs::read_to_string(&self.path) else {
            return vec![];
        };
        let Ok(snap): Result<ProbeSnapshot, _> = serde_json::from_str(&content) else {
            return vec![];
        };
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let interval = snap.interval_secs.max(1);
        let max_age = STALE_FACTOR * interval;
        if now.saturating_sub(snap.timestamp_unix) > max_age {
            return vec![];
        }

        snap.results
            .into_iter()
            .map(|r| {
                let value = r.rtt_us.map(|v| v as f64).unwrap_or(f64::INFINITY);
                let confidence = if r.rtt_us.is_some() { 0.9 } else { 0.3 };
                Sample {
                    capability: Capability::PeerLiveness,
                    value,
                    confidence,
                    quality: Quality::Medium,
                    origin: BackendId::ActiveProber,
                    timestamp_ns: ctx.timestamp_ns,
                    qp_num: None,
                    port: None,
                    priority: None,
                    device: Some(r.peer),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_reports_unavailable_when_no_snapshot() {
        let mut p = PeerLivenessProvider::with_path("/tmp/argus-probe-doesnotexist.json");
        let env = FabricEnv::synthetic();
        match p.probe(&env) {
            ProbeOutcome::Unavailable { .. } => (),
            _ => panic!("expected Unavailable"),
        }
    }

    #[test]
    fn provider_reads_fresh_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe.json");
        let snap = serde_json::json!({
            "timestamp_unix": SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            "interval_secs": 5,
            "results": [
                {"peer": "node07:9100", "rtt_us": 250, "error": null},
                {"peer": "node08:9100", "rtt_us": 1500, "error": null},
            ]
        });
        std::fs::write(&path, serde_json::to_string(&snap).unwrap()).unwrap();

        let mut p = PeerLivenessProvider::with_path(&path);
        let env = FabricEnv::synthetic();
        assert!(matches!(p.probe(&env), ProbeOutcome::Available { .. }));

        let metrics = argus_common::AggregatedMetrics::default();
        let ctx = DetectionContext {
            metrics: &metrics,
            window_seq: 1,
            timestamp_ns: 0,
            fabric: &env,
            cq_latency_sketch: None,
        };
        let samples = p.collect(&ctx);
        assert_eq!(samples.len(), 2);
        let peers: Vec<_> = samples.iter().map(|s| s.device.clone().unwrap()).collect();
        assert!(peers.contains(&"node07:9100".to_string()));
        assert!(peers.contains(&"node08:9100".to_string()));
    }
}

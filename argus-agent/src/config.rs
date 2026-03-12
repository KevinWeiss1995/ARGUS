use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "argus-agent")]
#[command(about = "ARGUS - Adaptive RDMA Guard & Utilization Sentinel")]
pub struct Cli {
    /// Operating mode
    #[arg(long, default_value = "mock")]
    pub mode: RunMode,

    /// Path to scenario file (for scenario mode)
    #[arg(long)]
    pub scenario: Option<String>,

    /// Path to replay file (for replay mode)
    #[arg(long)]
    pub replay_file: Option<PathBuf>,

    /// Number of CPUs to simulate (for mock mode)
    #[arg(long, default_value = "4")]
    pub num_cpus: u32,

    /// Enable TUI dashboard
    #[arg(long, default_value = "true")]
    pub tui: bool,

    /// Time scale for replay (0 = instant, 1.0 = realtime, 2.0 = 2x speed)
    #[arg(long, default_value = "1.0")]
    pub time_scale: f64,

    /// Maximum events before stopping (0 = unlimited)
    #[arg(long, default_value = "0")]
    pub max_events: u64,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum RunMode {
    /// Live eBPF probes (Linux only)
    Live,
    /// Synthetic event generation
    Mock,
    /// Replay recorded events from file
    Replay,
    /// Run a named test scenario
    Scenario,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub num_cpus: u32,
    pub detection: DetectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub irq_skew_threshold_pct: f64,
    pub rdma_spike_factor: f64,
    pub rdma_baseline_latency_ns: u64,
    pub slab_spike_factor: f64,
    pub slab_baseline_ns: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            num_cpus: 4,
            detection: DetectionConfig::default(),
        }
    }
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            irq_skew_threshold_pct: 70.0,
            rdma_spike_factor: 5.0,
            rdma_baseline_latency_ns: 2_000,
            slab_spike_factor: 5.0,
            slab_baseline_ns: 500,
        }
    }
}

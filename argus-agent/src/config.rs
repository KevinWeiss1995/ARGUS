use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "argus-agent")]
#[command(about = "ARGUS - Adaptive RDMA Guard & Utilization Sentinel")]
pub struct Cli {
    /// Operating mode
    #[arg(long, value_enum, default_value = "mock")]
    pub mode: RunMode,

    /// Event file to replay (for replay mode).
    /// Accepts both raw event arrays and scenario files (with expected_states).
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Mock profile preset
    #[arg(long, value_enum, default_value = "healthy")]
    pub profile: MockProfile,

    /// Path to compiled eBPF object (for live mode)
    #[arg(long)]
    pub ebpf_path: Option<PathBuf>,

    /// Expected SHA-256 hash of the eBPF artifact (hex). Rejects loading if mismatch.
    #[arg(long)]
    pub ebpf_hash: Option<String>,

    /// Number of CPUs to simulate (for mock mode)
    #[arg(long, default_value = "4")]
    pub num_cpus: u32,

    /// Enable TUI dashboard
    #[arg(long)]
    pub tui: bool,

    /// Time scale for replay (0 = instant, 1.0 = realtime, 2.0 = 2x speed)
    #[arg(long, default_value = "0.0")]
    pub time_scale: f64,

    /// Maximum events before stopping (0 = unlimited)
    #[arg(long, default_value = "0")]
    pub max_events: u64,

    /// Aggregation window duration in seconds.
    /// Detection and sparklines reset each window so they reflect recent behavior.
    #[arg(long, default_value = "3")]
    pub window_secs: u64,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Prometheus metrics listen address (e.g. 127.0.0.1:9090). Disabled if not set.
    #[arg(long)]
    pub metrics_addr: Option<String>,

    /// Enable seccomp syscall filtering after initialization (Linux only).
    /// Restricts the process to only the syscalls needed for operation.
    #[arg(long)]
    pub seccomp: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum RunMode {
    /// Live eBPF probes (Linux only, requires --ebpf-path)
    Live,
    /// Synthetic event generation (use --profile to select preset)
    Mock,
    /// Replay events from a file (requires --file)
    Replay,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum MockProfile {
    /// Normal operation — balanced IRQs, low latency
    Healthy,
    /// IRQ affinity skew — 80% interrupts on CPU 0
    Skew,
    /// RDMA completion queue latency spike (8x baseline)
    Spike,
    /// Slab allocator pressure (10x latency)
    Pressure,
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
    pub rdma_link_min_error_delta: u64,
    pub slab_pressure_min_allocs: u64,
    pub slab_pressure_alloc_rate_threshold: u64,
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
            rdma_link_min_error_delta: 1,
            slab_pressure_min_allocs: 100,
            slab_pressure_alloc_rate_threshold: 5_000,
        }
    }
}

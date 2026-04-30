use anyhow::{bail, Context};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// CLI (raw parsed arguments — Options used for mergeable fields)
// ---------------------------------------------------------------------------

fn build_version() -> &'static str {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    const HASH: &str = env!("ARGUS_BUILD_HASH");
    const DATE: &str = env!("ARGUS_BUILD_DATE");

    if HASH.is_empty() {
        VERSION
    } else {
        // Leak is fine — called once at startup, lives for process lifetime
        Box::leak(format!("{VERSION} ({HASH}, built {DATE})").into_boxed_str())
    }
}

#[derive(Parser, Debug)]
#[command(name = "argusd")]
#[command(about = "ARGUS - Adaptive RDMA Guard & Utilization Sentinel")]
#[command(version = build_version())]
pub struct Cli {
    /// Path to TOML config file [default: /etc/argus/argusd.toml if it exists]
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Operating mode [default: mock]
    #[arg(long, value_enum)]
    pub mode: Option<RunMode>,

    /// Event file to replay (for replay mode).
    /// Accepts both raw event arrays and scenario files (with expected_states).
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Mock profile preset [default: healthy]
    #[arg(long, value_enum)]
    pub profile: Option<MockProfile>,

    /// Path to compiled eBPF object (for live mode)
    #[arg(long)]
    pub ebpf_path: Option<PathBuf>,

    /// Expected SHA-256 hash of the eBPF artifact (hex). Rejects loading if mismatch.
    #[arg(long)]
    pub ebpf_hash: Option<String>,

    /// Number of CPUs (auto-detected if not specified)
    #[arg(long)]
    pub num_cpus: Option<u32>,

    /// Enable TUI dashboard
    #[arg(long)]
    pub tui: bool,

    /// Attach TUI to a running ARGUS daemon (read-only, no service interruption).
    /// Connects to the /status endpoint. [default: localhost:9100]
    #[arg(long, num_args = 0..=1, default_missing_value = "localhost:9100")]
    pub attach: Option<String>,

    /// Time scale for replay (0 = instant, 1.0 = realtime, 2.0 = 2x speed)
    #[arg(long)]
    pub time_scale: Option<f64>,

    /// Maximum events before stopping (0 = unlimited)
    #[arg(long)]
    pub max_events: Option<u64>,

    /// Aggregation window duration in seconds [default: 3]
    #[arg(long)]
    pub window_secs: Option<u64>,

    /// Log level (trace, debug, info, warn, error) [default: info]
    #[arg(long)]
    pub log_level: Option<String>,

    /// Prometheus metrics listen address (e.g. 0.0.0.0:9100). Disabled if not set.
    #[arg(long)]
    pub metrics_addr: Option<String>,

    /// TLS certificate file for the metrics endpoint (PEM)
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key file for the metrics endpoint (PEM)
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Bearer token for metrics endpoint authentication
    #[arg(long)]
    pub metrics_token: Option<String>,

    /// File containing bearer token for metrics endpoint authentication
    #[arg(long)]
    pub metrics_token_file: Option<PathBuf>,

    /// Enable seccomp syscall filtering after initialization (Linux only).
    /// Restricts the process to only the syscalls needed for operation.
    #[arg(long)]
    pub seccomp: bool,

    // --- Autonomous action flags ---
    /// Webhook URL for alert notifications (POST JSON).
    #[arg(long)]
    pub action_webhook: Option<String>,

    /// Enable IB port disable on critical link-down events (DANGEROUS).
    #[arg(long)]
    pub action_port_disable: bool,

    /// Dry-run mode: log actions without executing them.
    #[arg(long)]
    pub action_dry_run: bool,

    // --- Scheduler integration flags ---
    /// Scheduler backend to use (slurm, noop). Omit to disable scheduler integration.
    #[arg(long)]
    pub scheduler: Option<String>,

    /// Scheduler dry-run: log drain/resume without executing.
    #[arg(long)]
    pub scheduler_dry_run: bool,

    /// Drain on Degraded health (default: only drain on Critical).
    #[arg(long)]
    pub drain_on_degraded: bool,

    /// Minimum seconds at Healthy before auto-resuming a drained node.
    #[arg(long)]
    pub resume_cooldown: Option<u64>,
}

// ---------------------------------------------------------------------------
// TOML config file structures
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FileConfig {
    pub agent: AgentSection,
    pub metrics: MetricsSection,
    pub tls: TlsSection,
    pub auth: AuthSection,
    pub detection: DetectionSection,
    pub actions: ActionsSection,
    pub scheduler: SchedulerSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AgentSection {
    pub mode: Option<String>,
    pub ebpf_path: Option<PathBuf>,
    pub ebpf_hash: Option<String>,
    pub log_level: Option<String>,
    pub window_secs: Option<u64>,
    pub num_cpus: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MetricsSection {
    pub addr: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct TlsSection {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AuthSection {
    pub bearer_token: Option<String>,
    pub bearer_token_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DetectionSection {
    pub irq_skew_threshold_pct: Option<f64>,
    pub rdma_spike_factor: Option<f64>,
    pub rdma_baseline_latency_ns: Option<u64>,
    pub slab_pressure_min_allocs: Option<u64>,
    pub slab_pressure_alloc_rate_threshold: Option<u64>,
    pub state_machine: Option<StateMachineSection>,
    /// Per-fabric overrides keyed by `FabricKind::name()` —
    /// "infiniband" | "rocev1" | "rocev2" | "softroce" | "iwarp" | "unknown".
    /// Loaded after the base detection section, so a profile match overrides
    /// global thresholds. The chosen profile is determined at startup by
    /// `FabricEnv::detect()` and logged.
    pub profile: std::collections::HashMap<String, FabricProfileSection>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct FabricProfileSection {
    pub irq_skew_threshold_pct: Option<f64>,
    pub rdma_spike_factor: Option<f64>,
    pub rdma_baseline_latency_ns: Option<u64>,
    pub slab_pressure_min_allocs: Option<u64>,
    pub slab_pressure_alloc_rate_threshold: Option<u64>,
    pub state_machine: Option<StateMachineSection>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct StateMachineSection {
    pub degrade_enter: Option<f64>,
    pub degrade_exit: Option<f64>,
    pub critical_enter: Option<f64>,
    pub critical_exit: Option<f64>,
    pub enter_windows: Option<u32>,
    pub exit_windows: Option<u32>,
    pub recover_windows: Option<u32>,
    pub max_hold_windows: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ActionsSection {
    pub webhook_url: Option<String>,
    pub port_disable: Option<bool>,
    pub dry_run: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SchedulerSection {
    pub backend: Option<String>,
    pub dry_run: Option<bool>,
    pub drain_on_degraded: Option<bool>,
    pub resume_cooldown_secs: Option<u64>,
    pub reconcile_interval_secs: Option<u64>,
    pub contested_cooldown_secs: Option<u64>,
    pub max_consecutive_failures: Option<u32>,
    pub state_file: Option<PathBuf>,
    pub lock_file: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Resolved effective configuration (all values determined)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct EffectiveConfig {
    pub mode: RunMode,
    pub file: Option<PathBuf>,
    pub profile: MockProfile,
    pub ebpf_path: Option<PathBuf>,
    pub ebpf_hash: Option<String>,
    pub num_cpus: u32,
    pub tui: bool,
    /// When Some, run in attach mode: connect to a running daemon's /status endpoint.
    pub attach: Option<String>,
    pub time_scale: f64,
    pub max_events: u64,
    pub window_secs: u64,
    pub log_level: String,
    pub metrics_addr: Option<String>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub auth_token: Option<String>,
    pub seccomp: bool,
    pub detection: DetectionConfig,
    pub actions: crate::actions::ActionConfig,
    pub scheduler: Option<crate::scheduler::SchedulerConfig>,
    /// Per-fabric override profiles loaded from the TOML config.
    /// Applied at runtime once `FabricEnv::detect()` reports a fabric kind.
    pub fabric_profiles: std::collections::HashMap<String, FabricProfileSection>,
}

// ---------------------------------------------------------------------------
// Enums shared by CLI and config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq, Eq)]
pub enum RunMode {
    /// Live eBPF probes (Linux only, requires --ebpf-path)
    Live,
    /// Synthetic event generation (use --profile to select preset)
    Mock,
    /// Replay events from a file (requires --file)
    Replay,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
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

// ---------------------------------------------------------------------------
// Detection thresholds
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub num_cpus: u32,
    pub detection: DetectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub num_cpus: u32,
    pub irq_skew_threshold_pct: f64,
    pub rdma_spike_factor: f64,
    pub rdma_baseline_latency_ns: u64,
    pub slab_pressure_min_allocs: u64,
    pub slab_pressure_alloc_rate_threshold: u64,
    pub state_machine: Option<crate::detection::StateMachineConfig>,
}

impl DetectionConfig {
    /// Apply a fabric profile override on top of the current configuration.
    /// Any field that's `Some` in the profile overrides the base value.
    /// Returns a new `DetectionConfig`; the original is left untouched.
    #[must_use]
    pub fn with_profile(&self, profile: &FabricProfileSection) -> Self {
        let mut out = self.clone();
        if let Some(v) = profile.irq_skew_threshold_pct {
            out.irq_skew_threshold_pct = v;
        }
        if let Some(v) = profile.rdma_spike_factor {
            out.rdma_spike_factor = v;
        }
        if let Some(v) = profile.rdma_baseline_latency_ns {
            out.rdma_baseline_latency_ns = v;
        }
        if let Some(v) = profile.slab_pressure_min_allocs {
            out.slab_pressure_min_allocs = v;
        }
        if let Some(v) = profile.slab_pressure_alloc_rate_threshold {
            out.slab_pressure_alloc_rate_threshold = v;
        }
        if let Some(sm) = &profile.state_machine {
            let base_sm = out
                .state_machine
                .clone()
                .unwrap_or_default();
            out.state_machine = Some(crate::detection::StateMachineConfig {
                degrade_enter: sm.degrade_enter.unwrap_or(base_sm.degrade_enter),
                degrade_exit: sm.degrade_exit.unwrap_or(base_sm.degrade_exit),
                critical_enter: sm.critical_enter.unwrap_or(base_sm.critical_enter),
                critical_exit: sm.critical_exit.unwrap_or(base_sm.critical_exit),
                enter_windows: sm.enter_windows.unwrap_or(base_sm.enter_windows),
                exit_windows: sm.exit_windows.unwrap_or(base_sm.exit_windows),
                recover_windows: sm.recover_windows.unwrap_or(base_sm.recover_windows),
                max_hold_windows: sm.max_hold_windows.unwrap_or(base_sm.max_hold_windows),
            });
        }
        out
    }
}

fn detect_cpus() -> u32 {
    // Don't use available_parallelism() — it's cgroup-aware and returns 1
    // when systemd CPUQuota is low (e.g. 5%). We need the actual online CPU
    // count to correctly size per-CPU BPF map reads.
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/sys/devices/system/cpu/online") {
            if let Some(count) = parse_cpu_range(content.trim()) {
                return count;
            }
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4)
}

/// Parse kernel CPU range format like "0-3" or "0-1,4-7" into a count.
#[cfg(any(target_os = "linux", test))]
fn parse_cpu_range(s: &str) -> Option<u32> {
    let mut count = 0u32;
    for part in s.split(',') {
        let part = part.trim();
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u32 = lo.parse().ok()?;
            let hi: u32 = hi.parse().ok()?;
            count += hi - lo + 1;
        } else {
            let _: u32 = part.parse().ok()?;
            count += 1;
        }
    }
    if count > 0 { Some(count) } else { None }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            num_cpus: detect_cpus(),
            detection: DetectionConfig::default(),
        }
    }
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            num_cpus: detect_cpus(),
            irq_skew_threshold_pct: 70.0,
            rdma_spike_factor: 5.0,
            rdma_baseline_latency_ns: 2_000,
            slab_pressure_min_allocs: 100,
            slab_pressure_alloc_rate_threshold: 5_000,
            state_machine: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Config resolution: CLI + TOML → EffectiveConfig
// ---------------------------------------------------------------------------

fn parse_run_mode(s: &str) -> Option<RunMode> {
    match s.to_ascii_lowercase().as_str() {
        "live" => Some(RunMode::Live),
        "mock" => Some(RunMode::Mock),
        "replay" => Some(RunMode::Replay),
        _ => None,
    }
}

impl Cli {
    /// Merge CLI flags with an optional TOML config file to produce the final
    /// effective configuration. Precedence: CLI flag > config file > default.
    pub fn resolve(self) -> anyhow::Result<EffectiveConfig> {
        let fc = self.load_config_file()?;

        let mode = self
            .mode
            .or_else(|| fc.agent.mode.as_deref().and_then(parse_run_mode))
            .unwrap_or(RunMode::Mock);

        let log_level = self
            .log_level
            .or_else(|| fc.agent.log_level.clone())
            .unwrap_or_else(|| "info".into());

        let window_secs = self.window_secs.or(fc.agent.window_secs).unwrap_or(3);

        let num_cpus = self
            .num_cpus
            .or(fc.agent.num_cpus)
            .unwrap_or_else(detect_cpus);

        let metrics_addr = self.metrics_addr.or_else(|| fc.metrics.addr.clone());

        let ebpf_path = self.ebpf_path.or_else(|| fc.agent.ebpf_path.clone());
        let ebpf_hash = self.ebpf_hash.or_else(|| fc.agent.ebpf_hash.clone());

        // TLS — both cert and key must be set together
        let tls_cert = self.tls_cert.or_else(|| fc.tls.cert.clone());
        let tls_key = self.tls_key.or_else(|| fc.tls.key.clone());
        match (&tls_cert, &tls_key) {
            (Some(_), None) => bail!("TLS cert provided without key (need both --tls-cert and --tls-key)"),
            (None, Some(_)) => bail!("TLS key provided without cert (need both --tls-cert and --tls-key)"),
            _ => {}
        }

        // Auth token resolution: CLI > config inline > config file path > CLI file path
        let auth_token = if let Some(t) = self.metrics_token {
            Some(t)
        } else if let Some(ref t) = fc.auth.bearer_token {
            Some(t.clone())
        } else {
            let token_path = self
                .metrics_token_file
                .or_else(|| fc.auth.bearer_token_file.clone());
            match token_path {
                Some(ref p) => {
                    let raw = std::fs::read_to_string(p)
                        .with_context(|| format!("failed to read bearer token file: {}", p.display()))?;
                    let trimmed = raw.trim().to_string();
                    if trimmed.is_empty() {
                        bail!("bearer token file is empty: {}", p.display());
                    }
                    Some(trimmed)
                }
                None => None,
            }
        };

        let defaults = DetectionConfig::default();
        let sm_defaults = crate::detection::StateMachineConfig::default();
        let state_machine = fc.detection.state_machine.as_ref().map(|sm| {
            crate::detection::StateMachineConfig {
                degrade_enter: sm.degrade_enter.unwrap_or(sm_defaults.degrade_enter),
                degrade_exit: sm.degrade_exit.unwrap_or(sm_defaults.degrade_exit),
                critical_enter: sm.critical_enter.unwrap_or(sm_defaults.critical_enter),
                critical_exit: sm.critical_exit.unwrap_or(sm_defaults.critical_exit),
                enter_windows: sm.enter_windows.unwrap_or(sm_defaults.enter_windows),
                exit_windows: sm.exit_windows.unwrap_or(sm_defaults.exit_windows),
                recover_windows: sm.recover_windows.unwrap_or(sm_defaults.recover_windows),
                max_hold_windows: sm.max_hold_windows.unwrap_or(sm_defaults.max_hold_windows),
            }
        });
        let detection = DetectionConfig {
            num_cpus,
            irq_skew_threshold_pct: fc
                .detection
                .irq_skew_threshold_pct
                .unwrap_or(defaults.irq_skew_threshold_pct),
            rdma_spike_factor: fc
                .detection
                .rdma_spike_factor
                .unwrap_or(defaults.rdma_spike_factor),
            rdma_baseline_latency_ns: fc
                .detection
                .rdma_baseline_latency_ns
                .unwrap_or(defaults.rdma_baseline_latency_ns),
            slab_pressure_min_allocs: fc
                .detection
                .slab_pressure_min_allocs
                .unwrap_or(defaults.slab_pressure_min_allocs),
            slab_pressure_alloc_rate_threshold: fc
                .detection
                .slab_pressure_alloc_rate_threshold
                .unwrap_or(defaults.slab_pressure_alloc_rate_threshold),
            state_machine,
        };

        let fabric_profiles = fc.detection.profile.clone();

        let actions = crate::actions::ActionConfig {
            webhook_url: self
                .action_webhook
                .or_else(|| fc.actions.webhook_url.clone()),
            port_disable: self.action_port_disable || fc.actions.port_disable.unwrap_or(false),
            dry_run: self.action_dry_run || fc.actions.dry_run.unwrap_or(false),
        };

        let scheduler_backend = self
            .scheduler
            .or_else(|| fc.scheduler.backend.clone());
        let scheduler = scheduler_backend.map(|backend| {
            use std::time::Duration;
            let defaults = crate::scheduler::SchedulerConfig::default();
            crate::scheduler::SchedulerConfig {
                backend,
                dry_run: self.scheduler_dry_run
                    || fc.scheduler.dry_run.unwrap_or(false),
                drain_on_degraded: self.drain_on_degraded
                    || fc.scheduler.drain_on_degraded.unwrap_or(false),
                resume_cooldown: Duration::from_secs(
                    self.resume_cooldown
                        .or(fc.scheduler.resume_cooldown_secs)
                        .unwrap_or(defaults.resume_cooldown.as_secs()),
                ),
                reconcile_interval: Duration::from_secs(
                    fc.scheduler.reconcile_interval_secs
                        .unwrap_or(defaults.reconcile_interval.as_secs()),
                ),
                contested_cooldown: Duration::from_secs(
                    fc.scheduler.contested_cooldown_secs
                        .unwrap_or(defaults.contested_cooldown.as_secs()),
                ),
                max_consecutive_failures: fc
                    .scheduler
                    .max_consecutive_failures
                    .unwrap_or(defaults.max_consecutive_failures),
                state_file: fc
                    .scheduler
                    .state_file
                    .clone()
                    .unwrap_or(defaults.state_file),
                lock_file: fc
                    .scheduler
                    .lock_file
                    .clone()
                    .unwrap_or(defaults.lock_file),
            }
        });

        Ok(EffectiveConfig {
            mode,
            file: self.file,
            profile: self.profile.unwrap_or(MockProfile::Healthy),
            ebpf_path,
            ebpf_hash,
            num_cpus,
            tui: self.tui,
            attach: self.attach.or_else(|| {
                if std::env::args().next().as_deref().map(std::path::Path::new)
                    .and_then(|p| p.file_name())
                    .map_or(false, |n| n == "argus-tui")
                {
                    Some("localhost:9100".into())
                } else {
                    None
                }
            }),
            time_scale: self.time_scale.unwrap_or(0.0),
            max_events: self.max_events.unwrap_or(0),
            window_secs,
            log_level,
            metrics_addr,
            tls_cert,
            tls_key,
            auth_token,
            seccomp: self.seccomp,
            detection,
            actions,
            scheduler,
            fabric_profiles,
        })
    }

    fn load_config_file(&self) -> anyhow::Result<FileConfig> {
        if let Some(ref path) = self.config {
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read config: {}", path.display()))?;
            toml::from_str(&contents)
                .with_context(|| format!("failed to parse config: {}", path.display()))
        } else {
            let default_path = PathBuf::from("/etc/argus/argusd.toml");
            if default_path.exists() {
                let contents = std::fs::read_to_string(&default_path)
                    .context("failed to read /etc/argus/argusd.toml")?;
                toml::from_str(&contents).context("failed to parse /etc/argus/argusd.toml")
            } else {
                Ok(FileConfig::default())
            }
        }
    }
}

impl EffectiveConfig {
    #[must_use]
    pub fn resolve_num_cpus(&self) -> u32 {
        self.num_cpus
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_range_simple() {
        assert_eq!(parse_cpu_range("0-1"), Some(2));
        assert_eq!(parse_cpu_range("0-3"), Some(4));
        assert_eq!(parse_cpu_range("0-7"), Some(8));
    }

    #[test]
    fn parse_cpu_range_multi_segment() {
        assert_eq!(parse_cpu_range("0-3,8-11"), Some(8));
        assert_eq!(parse_cpu_range("0-1,4-7"), Some(6));
    }

    #[test]
    fn parse_cpu_range_single_cpu() {
        assert_eq!(parse_cpu_range("0"), Some(1));
    }

    #[test]
    fn parse_cpu_range_invalid() {
        assert_eq!(parse_cpu_range(""), None);
        assert_eq!(parse_cpu_range("abc"), None);
    }

    #[test]
    fn detection_with_profile_overrides_only_specified_fields() {
        let base = DetectionConfig::default();
        let profile = FabricProfileSection {
            irq_skew_threshold_pct: Some(85.0),
            rdma_baseline_latency_ns: Some(2000),
            ..Default::default()
        };
        let merged = base.with_profile(&profile);
        assert_eq!(merged.irq_skew_threshold_pct, 85.0);
        assert_eq!(merged.rdma_baseline_latency_ns, 2000);
        // Untouched fields keep their defaults.
        assert_eq!(merged.rdma_spike_factor, base.rdma_spike_factor);
        assert_eq!(merged.slab_pressure_min_allocs, base.slab_pressure_min_allocs);
    }

    #[test]
    fn detection_with_profile_state_machine_partial_override() {
        let base = DetectionConfig::default();
        let profile = FabricProfileSection {
            state_machine: Some(StateMachineSection {
                degrade_enter: Some(0.40),
                ..Default::default()
            }),
            ..Default::default()
        };
        let merged = base.with_profile(&profile);
        let sm = merged.state_machine.expect("state machine should be set");
        assert_eq!(sm.degrade_enter, 0.40);
        // Other fields should match defaults.
        let defaults = crate::detection::StateMachineConfig::default();
        assert_eq!(sm.degrade_exit, defaults.degrade_exit);
        assert_eq!(sm.critical_enter, defaults.critical_enter);
    }

    #[test]
    fn fabric_profiles_parse_from_toml() {
        let toml_str = r#"
[detection]
irq_skew_threshold_pct = 70.0

[detection.profile.softroce]
irq_skew_threshold_pct = 80.0
rdma_spike_factor = 4.0

[detection.profile.softroce.state_machine]
degrade_enter = 0.35

[detection.profile.infiniband]
rdma_baseline_latency_ns = 500
"#;
        let fc: FileConfig = toml::from_str(toml_str).expect("toml parse");
        assert!(fc.detection.profile.contains_key("softroce"));
        assert!(fc.detection.profile.contains_key("infiniband"));
        let s = &fc.detection.profile["softroce"];
        assert_eq!(s.irq_skew_threshold_pct, Some(80.0));
        assert_eq!(s.rdma_spike_factor, Some(4.0));
        let sm = s.state_machine.as_ref().unwrap();
        assert_eq!(sm.degrade_enter, Some(0.35));
    }
}

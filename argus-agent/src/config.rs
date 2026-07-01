use anyhow::{bail, Context};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// CLI (raw parsed arguments — Options used for mergeable fields)
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "argus-agent")]
#[command(about = "ARGUS - Adaptive RDMA Guard & Utilization Sentinel")]
#[allow(clippy::struct_excessive_bools)] // independent CLI flags, not a state machine
pub struct Cli {
    /// Path to TOML config file [default: /etc/argus/argusd.toml if it exists]
    #[arg(long, env = "ARGUS_CONFIG")]
    pub config: Option<PathBuf>,

    /// Operating mode [default: mock]
    #[arg(long, value_enum, env = "ARGUS_MODE")]
    pub mode: Option<RunMode>,

    /// Event file to replay (for replay mode).
    /// Accepts both raw event arrays and scenario files (with `expected_states`).
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Mock profile preset [default: healthy]
    #[arg(long, value_enum)]
    pub profile: Option<MockProfile>,

    /// Path to compiled eBPF object (for live mode)
    #[arg(long, env = "ARGUS_EBPF_PATH")]
    pub ebpf_path: Option<PathBuf>,

    /// Expected SHA-256 hash of the eBPF artifact (hex). Rejects loading if mismatch.
    #[arg(long, env = "ARGUS_EBPF_HASH")]
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
    #[arg(long, env = "ARGUS_WINDOW_SECS")]
    pub window_secs: Option<u64>,

    /// Log level (trace, debug, info, warn, error) [default: info]
    #[arg(long, env = "ARGUS_LOG_LEVEL")]
    pub log_level: Option<String>,

    /// Prometheus metrics listen address (e.g. 127.0.0.1:9100). Disabled if not set.
    #[arg(long, env = "ARGUS_METRICS_ADDR")]
    pub metrics_addr: Option<String>,

    /// TLS certificate file for the metrics endpoint (PEM)
    #[arg(long, env = "ARGUS_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key file for the metrics endpoint (PEM)
    #[arg(long, env = "ARGUS_TLS_KEY")]
    pub tls_key: Option<PathBuf>,

    /// Bearer token for metrics endpoint authentication
    #[arg(long, env = "ARGUS_METRICS_TOKEN")]
    pub metrics_token: Option<String>,

    /// File containing bearer token for metrics endpoint authentication
    #[arg(long, env = "ARGUS_METRICS_TOKEN_FILE")]
    pub metrics_token_file: Option<PathBuf>,

    /// Enable seccomp syscall filtering after initialization (Linux only).
    #[arg(long, env = "ARGUS_SECCOMP")]
    pub seccomp: bool,

    // --- Autonomous action flags ---
    /// Webhook URL for alert notifications (POST JSON).
    #[arg(long, env = "ARGUS_ACTION_WEBHOOK")]
    pub action_webhook: Option<String>,

    /// Enable IB port disable on critical link-down events (DANGEROUS).
    #[arg(long, env = "ARGUS_ACTION_PORT_DISABLE")]
    pub action_port_disable: bool,

    /// Dry-run mode: log actions without executing them.
    #[arg(long, env = "ARGUS_ACTION_DRY_RUN")]
    pub action_dry_run: bool,

    // --- Scheduler integration flags ---
    /// Scheduler backend to use (slurm, noop). Omit to disable scheduler integration.
    #[arg(long, env = "ARGUS_SCHEDULER")]
    pub scheduler: Option<String>,

    /// Scheduler dry-run: log drain/resume without executing.
    #[arg(long, env = "ARGUS_SCHEDULER_DRY_RUN")]
    pub scheduler_dry_run: bool,

    /// Drain on Degraded health (default: only drain on Critical).
    #[arg(long)]
    pub drain_on_degraded: bool,

    /// Minimum seconds at Healthy before auto-resuming a drained node.
    #[arg(long)]
    pub resume_cooldown: Option<u64>,

    /// Read-only mode: disable all scheduler, webhook, and port-disable actions.
    /// ARGUS will monitor and report via metrics/TUI but take no automated action.
    #[arg(long, env = "ARGUS_READ_ONLY")]
    pub read_only: bool,

    /// Skip TLS certificate verification when using --attach (insecure).
    #[arg(long)]
    pub tls_skip_verify: bool,
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
    pub max_drains_per_hour: Option<u32>,
    pub state_file: Option<PathBuf>,
    pub lock_file: Option<PathBuf>,
    pub audit_log_path: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Resolved effective configuration (all values determined)
// ---------------------------------------------------------------------------

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // independent feature toggles resolved from CLI/env/TOML
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
    pub read_only: bool,
    pub tls_skip_verify: bool,
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
            let base_sm = out.state_machine.clone().unwrap_or_default();
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
    if count > 0 {
        Some(count)
    } else {
        None
    }
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

impl DetectionConfig {
    /// Validate all detection thresholds are within sane ranges.
    /// Called during config resolution to catch misconfigurations at startup
    /// rather than producing silent misbehavior at runtime.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.num_cpus == 0 {
            bail!("num_cpus must be >= 1, got 0");
        }
        if !(1.0..=100.0).contains(&self.irq_skew_threshold_pct) {
            bail!(
                "irq_skew_threshold_pct must be in 1.0..=100.0, got {}",
                self.irq_skew_threshold_pct
            );
        }
        if self.rdma_spike_factor < 1.0 {
            bail!(
                "rdma_spike_factor must be >= 1.0, got {}",
                self.rdma_spike_factor
            );
        }
        if self.rdma_baseline_latency_ns == 0 {
            bail!(
                "rdma_baseline_latency_ns must be >= 1, got 0 (would cause division by infinity)"
            );
        }
        if let Some(ref sm) = self.state_machine {
            sm.validate_config()?;
        }
        Ok(())
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
        if window_secs == 0 || window_secs > 300 {
            bail!("window_secs must be in 1..=300, got {window_secs}");
        }

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
            (Some(_), None) => {
                bail!("TLS cert provided without key (need both --tls-cert and --tls-key)")
            }
            (None, Some(_)) => {
                bail!("TLS key provided without cert (need both --tls-cert and --tls-key)")
            }
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
                    let raw = std::fs::read_to_string(p).with_context(|| {
                        format!("failed to read bearer token file: {}", p.display())
                    })?;
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
        let state_machine =
            fc.detection
                .state_machine
                .as_ref()
                .map(|sm| crate::detection::StateMachineConfig {
                    degrade_enter: sm.degrade_enter.unwrap_or(sm_defaults.degrade_enter),
                    degrade_exit: sm.degrade_exit.unwrap_or(sm_defaults.degrade_exit),
                    critical_enter: sm.critical_enter.unwrap_or(sm_defaults.critical_enter),
                    critical_exit: sm.critical_exit.unwrap_or(sm_defaults.critical_exit),
                    enter_windows: sm.enter_windows.unwrap_or(sm_defaults.enter_windows),
                    exit_windows: sm.exit_windows.unwrap_or(sm_defaults.exit_windows),
                    recover_windows: sm.recover_windows.unwrap_or(sm_defaults.recover_windows),
                    max_hold_windows: sm.max_hold_windows.unwrap_or(sm_defaults.max_hold_windows),
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

        detection
            .validate()
            .context("invalid detection configuration")?;

        let fabric_profiles = fc.detection.profile.clone();

        let read_only = self.read_only;

        let actions = crate::actions::ActionConfig {
            webhook_url: if read_only {
                None
            } else {
                self.action_webhook
                    .or_else(|| fc.actions.webhook_url.clone())
            },
            port_disable: !read_only
                && (self.action_port_disable || fc.actions.port_disable.unwrap_or(false)),
            dry_run: read_only || self.action_dry_run || fc.actions.dry_run.unwrap_or(false),
        };

        let scheduler_backend = if read_only {
            None
        } else {
            self.scheduler.or_else(|| fc.scheduler.backend.clone())
        };
        let scheduler = scheduler_backend.map(|backend| {
            use std::time::Duration;
            let defaults = crate::scheduler::SchedulerConfig::default();
            crate::scheduler::SchedulerConfig {
                backend,
                dry_run: self.scheduler_dry_run || fc.scheduler.dry_run.unwrap_or(false),
                drain_on_degraded: self.drain_on_degraded
                    || fc.scheduler.drain_on_degraded.unwrap_or(false),
                resume_cooldown: Duration::from_secs(
                    self.resume_cooldown
                        .or(fc.scheduler.resume_cooldown_secs)
                        .unwrap_or(defaults.resume_cooldown.as_secs()),
                ),
                reconcile_interval: Duration::from_secs(
                    fc.scheduler
                        .reconcile_interval_secs
                        .unwrap_or(defaults.reconcile_interval.as_secs()),
                ),
                contested_cooldown: Duration::from_secs(
                    fc.scheduler
                        .contested_cooldown_secs
                        .unwrap_or(defaults.contested_cooldown.as_secs()),
                ),
                max_consecutive_failures: fc
                    .scheduler
                    .max_consecutive_failures
                    .unwrap_or(defaults.max_consecutive_failures),
                max_drains_per_hour: fc
                    .scheduler
                    .max_drains_per_hour
                    .unwrap_or(defaults.max_drains_per_hour),
                state_file: fc
                    .scheduler
                    .state_file
                    .clone()
                    .unwrap_or(defaults.state_file),
                lock_file: fc.scheduler.lock_file.clone().unwrap_or(defaults.lock_file),
                audit_log_path: fc
                    .scheduler
                    .audit_log_path
                    .clone()
                    .unwrap_or(defaults.audit_log_path),
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
                if std::env::args()
                    .next()
                    .as_deref()
                    .map(std::path::Path::new)
                    .and_then(|p| p.file_name())
                    .is_some_and(|n| n == "argus-tui")
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
            read_only,
            tls_skip_verify: self.tls_skip_verify,
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
    pub const fn resolve_num_cpus(&self) -> u32 {
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
        assert_eq!(
            merged.slab_pressure_min_allocs,
            base.slab_pressure_min_allocs
        );
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
    fn detection_config_validate_rejects_zero_window_secs() {
        // window_secs validated in resolve(); test DetectionConfig::validate() fields here
        let mut dc = DetectionConfig::default();
        dc.num_cpus = 0;
        assert!(dc.validate().is_err());
    }

    #[test]
    fn detection_config_validate_rejects_zero_baseline_latency() {
        let mut dc = DetectionConfig::default();
        dc.rdma_baseline_latency_ns = 0;
        let err = dc.validate().unwrap_err();
        assert!(err.to_string().contains("rdma_baseline_latency_ns"));
    }

    #[test]
    fn detection_config_validate_rejects_low_spike_factor() {
        let mut dc = DetectionConfig::default();
        dc.rdma_spike_factor = 0.5;
        let err = dc.validate().unwrap_err();
        assert!(err.to_string().contains("rdma_spike_factor"));
    }

    #[test]
    fn detection_config_validate_rejects_bad_irq_threshold() {
        let mut dc = DetectionConfig::default();
        dc.irq_skew_threshold_pct = -1.0;
        assert!(dc.validate().is_err());
        dc.irq_skew_threshold_pct = 101.0;
        assert!(dc.validate().is_err());
    }

    #[test]
    fn detection_config_validate_accepts_defaults() {
        let dc = DetectionConfig::default();
        dc.validate().expect("defaults should be valid");
    }

    #[test]
    fn state_machine_validate_rejects_inverted_thresholds() {
        let sm = crate::detection::StateMachineConfig {
            degrade_enter: 0.05,
            degrade_exit: 0.10,
            ..Default::default()
        };
        let err = sm.validate_config().unwrap_err();
        assert!(err.to_string().contains("degrade_enter"));
    }

    #[test]
    fn state_machine_validate_rejects_zero_windows() {
        let sm = crate::detection::StateMachineConfig {
            enter_windows: 0,
            ..Default::default()
        };
        assert!(sm.validate_config().is_err());
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

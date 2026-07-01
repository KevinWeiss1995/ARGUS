#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// See lib.rs for rationale on these allows.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
#![allow(clippy::option_if_let_else)]

use anyhow::{bail, Context, Result};
use argus_agent::config::{Cli, EffectiveConfig, MockProfile, RunMode};
use argus_agent::pipeline::Pipeline;
use argus_agent::sources::mock::{MockConfig, MockEventSource};
use argus_agent::sources::replay::ReplayEventSource;
use argus_agent::sources::AnyEventSource;
use argus_agent::telemetry::TelemetryCollector;
use argus_agent::tui::{Dashboard, DashboardState};
use clap::Parser;
use tokio::sync::watch;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Cli::parse().resolve()?;

    // Pin umask before any file I/O to prevent world-readable runtime files.
    #[cfg(target_os = "linux")]
    {
        #[allow(unsafe_code)]
        unsafe {
            libc::umask(0o077);
        }
    }

    if let Some(ref addr) = config.attach {
        return run_attach_tui(addr, config.tls_skip_verify, config.auth_token.as_deref()).await;
    }

    if !config.tui {
        let log_level: tracing::Level = config.log_level.parse().unwrap_or(tracing::Level::INFO);
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env().add_directive(log_level.into()),
            )
            .json()
            .init();
    }

    install_panic_hook();

    if let Some(ref path) = config.tls_cert {
        tracing::info!(?path, "TLS enabled for metrics endpoint");
    }
    if config.auth_token.is_some() {
        tracing::info!("bearer token auth enabled for metrics endpoint");
    }

    // Singleton enforcement: advisory flock on PID file.
    // Only meaningful in live mode (daemon). Mock/replay are dev tools — no PID lock needed.
    // The _pid_guard must live for the duration of main(); dropping it releases the lock.
    let _pid_guard = if config.mode == RunMode::Live {
        Some(acquire_pid_lock()?)
    } else {
        None
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    if config.read_only {
        tracing::info!("read-only mode: all scheduler and action operations disabled");
    }

    let num_cpus = config.num_cpus;
    tracing::info!(num_cpus, "CPU count resolved");

    // Detect fabric first so we can apply the right detection profile.
    let fabric_env = argus_agent::capabilities::FabricEnv::detect();
    let fabric_name = fabric_env
        .fabric
        .map_or_else(|| "none".into(), |f| f.name().to_string());

    // Apply per-fabric profile overrides if one matches the detected fabric.
    let detection_config = if let Some(profile) = config.fabric_profiles.get(&fabric_name) {
        tracing::info!(fabric = %fabric_name, "applying fabric-specific detection profile");
        config.detection.with_profile(profile)
    } else {
        config.detection.clone()
    };

    let pipeline = Pipeline::with_fabric(num_cpus, fabric_env, &detection_config);
    let telemetry = TelemetryCollector::default();
    let dash_state = DashboardState::default();
    let start = std::time::Instant::now();

    // Surface capability coverage at startup so operators see what fabric was
    // detected and which backends are active.
    {
        let coverage = pipeline.coverage();
        tracing::info!(
            grade = %coverage.grade.as_char(),
            fabric = coverage.fabric.as_deref().unwrap_or("none"),
            "capability coverage"
        );
        for cap in &coverage.capabilities {
            let backend = cap
                .active_backend
                .map_or("none", argus_common::BackendId::name);
            tracing::info!(
                capability = %cap.capability,
                backend = backend,
                quality = %cap.quality,
                "capability tier"
            );
        }
    }

    let prom_exporter = std::sync::Arc::new(std::sync::Mutex::new(
        argus_agent::telemetry::prometheus::PrometheusExporter::new(),
    ));
    let coverage_snapshot: std::sync::Arc<std::sync::Mutex<argus_common::CoverageReport>> =
        std::sync::Arc::new(std::sync::Mutex::new(pipeline.coverage().clone()));
    if let Ok(exp) = prom_exporter.lock() {
        exp.update_capability_coverage(pipeline.coverage());
    }
    let health_snapshot = std::sync::Arc::new(std::sync::Mutex::new(
        argus_agent::telemetry::prometheus::HealthSnapshot::default(),
    ));
    let status_snapshot = std::sync::Arc::new(std::sync::Mutex::new(
        argus_agent::telemetry::prometheus::StatusSnapshot::default(),
    ));
    // Construct scheduler reconciler if configured
    let shared_reconciler: Option<
        std::sync::Arc<std::sync::Mutex<argus_agent::scheduler::Reconciler>>,
    > = if let Some(ref sched_cfg) = config.scheduler {
        let hostname =
            hostname::get().map_or_else(|_| "unknown".into(), |h| h.to_string_lossy().to_string());
        let backend = argus_agent::scheduler::build_backend(sched_cfg);
        tracing::info!(
            backend = backend.name(),
            node = %hostname,
            dry_run = sched_cfg.dry_run,
            "scheduler integration enabled"
        );
        match argus_agent::scheduler::Reconciler::new(backend, sched_cfg.clone(), hostname) {
            Ok(r) => Some(std::sync::Arc::new(std::sync::Mutex::new(r))),
            Err(e) => {
                tracing::error!("failed to initialize scheduler reconciler: {e}");
                None
            }
        }
    } else {
        None
    };

    if let Some(ref addr_str) = config.metrics_addr {
        let addr: std::net::SocketAddr = addr_str
            .parse()
            .with_context(|| format!("invalid metrics addr: {addr_str}"))?;
        let exp = prom_exporter.clone();
        let hs = health_snapshot.clone();
        let ss = status_snapshot.clone();
        let rc = shared_reconciler.clone();
        let cov = Some(coverage_snapshot.clone());
        let tls_cfg = match (&config.tls_cert, &config.tls_key) {
            (Some(cert), Some(key)) => Some(argus_agent::telemetry::prometheus::TlsConfig {
                cert_path: cert.clone(),
                key_path: key.clone(),
            }),
            _ => None,
        };
        let auth_token = config.auth_token.clone();
        let metrics_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = argus_agent::telemetry::prometheus::serve_metrics(
                exp,
                hs,
                ss,
                rc,
                cov,
                addr,
                tls_cfg,
                auth_token,
                metrics_shutdown,
            )
            .await
            {
                tracing::error!("metrics server failed: {e}");
            }
        });
    }

    let dashboard = if config.tui {
        Some(Dashboard::new()?)
    } else {
        None
    };

    if config.mode == RunMode::Live {
        #[cfg(target_os = "linux")]
        {
            run_live_mode(
                &config,
                pipeline,
                telemetry,
                dash_state,
                dashboard,
                start,
                prom_exporter,
                health_snapshot,
                status_snapshot,
                shared_reconciler,
                shutdown_rx,
            )?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            bail!(
                "live eBPF mode requires Linux — use --mode mock or --mode replay on this platform"
            );
        }
    }

    let (source, source_name) = build_event_source(&config)?;
    run_event_mode(
        source,
        source_name,
        &config,
        pipeline,
        telemetry,
        dash_state,
        dashboard,
        start,
        prom_exporter,
        health_snapshot,
        status_snapshot,
        shared_reconciler,
        shutdown_rx,
    )
    .await?;

    Ok(())
}

/// Live eBPF mode: timer-based map reading, no per-event overhead.
/// The agent sleeps most of the time and wakes only at window boundaries
/// to read aggregated BPF maps and sysfs hardware counters.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn run_live_mode(
    config: &EffectiveConfig,
    mut pipeline: Pipeline,
    mut telemetry: TelemetryCollector,
    mut dash_state: DashboardState,
    mut dashboard: Option<Dashboard>,
    start: std::time::Instant,
    prom_exporter: std::sync::Arc<
        std::sync::Mutex<argus_agent::telemetry::prometheus::PrometheusExporter>,
    >,
    health_snapshot: std::sync::Arc<
        std::sync::Mutex<argus_agent::telemetry::prometheus::HealthSnapshot>,
    >,
    status_snapshot: std::sync::Arc<
        std::sync::Mutex<argus_agent::telemetry::prometheus::StatusSnapshot>,
    >,
    shared_reconciler: Option<std::sync::Arc<std::sync::Mutex<argus_agent::scheduler::Reconciler>>>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let ebpf_path = config
        .ebpf_path
        .as_ref()
        .context("--ebpf-path <path> is required in live mode")?;

    if !ebpf_path.exists() {
        bail!(
            "eBPF artifact not found: {}\nBuild it with: just build-ebpf",
            ebpf_path.display()
        );
    }

    let ebpf_hash = config.ebpf_hash.clone().or_else(|| load_ebpf_hash_file());
    if let Some(ref expected_hash) = ebpf_hash {
        verify_ebpf_hash(ebpf_path, expected_hash)?;
    } else {
        tracing::warn!(
            "no eBPF hash configured — integrity verification skipped. \
             Set ARGUS_EBPF_HASH or install /etc/argus/ebpf.sha256 for production use."
        );
    }

    let mut ebpf_source = argus_agent::sources::ebpf::EbpfEventSource::new(ebpf_path)
        .map_err(|e| anyhow::anyhow!("failed to load eBPF probes: {e}"))?;

    // Publish the kprobe attachment outcomes as Prometheus gauges so
    // operators can SEE whether CQ latency / slab latency data paths
    // are alive, instead of having to grep startup logs after the fact.
    if let Ok(exp) = prom_exporter.lock() {
        exp.set_ebpf_attachment_status(
            ebpf_source.cq_kprobes_attached,
            ebpf_source.slab_latency_attached,
        );
    }
    if !ebpf_source.cq_kprobes_attached {
        tracing::warn!(
            "CQ latency monitoring is OFFLINE on this host (kprobes failed \
             to attach). argus_ebpf_cq_kprobes_attached=0. CQ panel will \
             show zero. See startup log for the grep command to inspect \
             /proc/kallsyms."
        );
    }

    dash_state.source_name = "ebpf/live".into();

    argus_agent::security::drop_privileges();
    if config.seccomp {
        argus_agent::security::apply_seccomp();
    }

    let hw_reader = {
        let reader = argus_agent::sources::hwcounters::HwCounterReader::discover();
        if reader.port_count() > 0 {
            tracing::info!(
                ports = reader.port_count(),
                "discovered IB ports for hw counters"
            );
        }
        reader
    };

    // Host-side NIC health (PCIe lanes + thermal). Independent of IB
    // protocol — catches NIC hardware degradation that doesn't move
    // any IB counter.
    let nic_health = argus_agent::sources::nic_health::NicHealthReader::discover();
    if nic_health.device_count() > 0 {
        let thermal_coverage = nic_health.thermal_coverage();
        let with_thermal: Vec<&String> = thermal_coverage
            .iter()
            .filter(|(_, has)| *has)
            .map(|(d, _)| d)
            .collect();
        tracing::info!(
            ib_devices = nic_health.device_count(),
            with_thermal = with_thermal.len(),
            "NIC health reader online"
        );
    }

    let mut process_resolver = argus_agent::sources::process_resolver::ProcessResolver::new();
    let mut action_engine = argus_agent::actions::ActionEngine::from_config(&config.actions);

    let window_duration = std::time::Duration::from_secs(config.window_secs);
    let tick_interval = std::time::Duration::from_millis(200);
    let mut window_start = std::time::Instant::now();
    let mut event_count = 0u64;

    // Take an initial BPF snapshot to establish baselines (deltas will be zero).
    let _ = ebpf_source.read_bpf_snapshot();

    loop {
        if *shutdown_rx.borrow() {
            tracing::info!("received shutdown signal, exiting gracefully");
            break;
        }

        if let Some(ref dash) = dashboard {
            if dash.poll_quit()? {
                break;
            }
        }

        if window_start.elapsed() >= window_duration {
            let snap = ebpf_source.read_bpf_snapshot();
            event_count += snap.total_irq_count
                + snap.slab_alloc_count
                + snap.slab_free_count
                + snap.napi_poll_count;
            pipeline.ingest_bpf_snapshot(&snap);

            for hw_event in hw_reader.read_all() {
                pipeline.ingest(&hw_event);
            }

            let alerts = pipeline.evaluate();

            // Stamp per-port idle state onto current_metrics so the snapshot
            // emits argus_ib_port_idle_seconds. Hardware counters keep
            // firing regardless — this is visibility, not gating.
            let discovered_ports: Vec<(String, u32)> = hw_reader
                .discovered_ports()
                .into_iter()
                .map(|(d, p, _)| (d, p))
                .collect();
            pipeline.finalize_idle_window(&discovered_ports, config.window_secs);

            if !alerts.is_empty() {
                let qp_owners = ebpf_source.read_qp_owners();
                let blast = process_resolver.resolve_blast_radius(&qp_owners);
                if !blast.is_empty() {
                    tracing::info!(affected = blast.summary(), "blast radius resolved");
                }
                for mut alert in alerts {
                    action_engine.dispatch(&alert, &blast);

                    if let Ok(exp) = prom_exporter.lock() {
                        exp.record_alert(alert.kind_name(), &alert.severity.to_string());
                    }

                    if !blast.is_empty() {
                        alert.message =
                            format!("{} | Affected: {}", alert.message, blast.summary());
                    }
                    telemetry.record_alert(alert.clone());
                    dash_state.recent_alerts.push(alert);
                    if dash_state.recent_alerts.len() > 100 {
                        dash_state.recent_alerts.remove(0);
                    }
                }
            }
            process_resolver.gc();

            dash_state.health = pipeline.detection_engine().current_state();
            dash_state.metrics = pipeline.current_metrics().clone();
            dash_state.push_metrics_snapshot();
            dash_state.event_count = event_count;
            dash_state.uptime_secs = start.elapsed().as_secs_f64();

            if let Ok(mut exp) = prom_exporter.lock() {
                exp.update(pipeline.current_metrics(), dash_state.health, event_count);
                exp.update_score_components(pipeline.detection_engine().smoothed_score());
                exp.update_sample_contribution(
                    pipeline.detection_engine().last_sample_contribution(),
                );
                exp.update_cq_latency_quantiles(pipeline.last_samples());
                exp.update_timescales(pipeline.detection_engine().multi_timescale());
                let class = pipeline.detection_engine().burst_class();
                exp.update_burst_classification(&[
                    (
                        "quiet",
                        class == argus_agent::detection::burst::BurstClass::Quiet,
                    ),
                    (
                        "burst",
                        class == argus_agent::detection::burst::BurstClass::Burst,
                    ),
                    (
                        "sustained",
                        class == argus_agent::detection::burst::BurstClass::Sustained,
                    ),
                    (
                        "mixed",
                        class == argus_agent::detection::burst::BurstClass::MixedBurstSustained,
                    ),
                ]);
                for (device, port, dev_type) in hw_reader.discovered_ports() {
                    let port_str = port.to_string();
                    // Heartbeat first — guarantees operators can see polling
                    // is alive even when every error counter is legitimately 0.
                    exp.record_hw_counter_poll(&device, &port_str);
                    exp.update_ib_counters(
                        &device,
                        &port_str,
                        &pipeline.current_metrics().ib_counter_deltas,
                        dev_type,
                    );
                }
                // Publish absolute counter values for long-window slope
                // analysis (the El-Sayed & Schroeder DSN-2013 / Mellanox
                // UFM Health-Score pattern for slow IB degradation).
                exp.update_absolute_counters(&hw_reader.absolute_counters());
                // Host-side NIC health: PCIe lane state + thermal.
                // These read /sys/bus/pci/.../current_link_* and
                // /sys/class/hwmon — independent of IB protocol.
                exp.update_nic_pcie(&nic_health.read_pcie());
                exp.update_nic_thermal(&nic_health.read_thermal());
                exp.update_lru_evictions(snap.cq_lru_misses, snap.slab_lru_misses);
            }
            if let Ok(mut hs) = health_snapshot.lock() {
                hs.state = dash_state.health;
                hs.uptime_secs = start.elapsed().as_secs_f64();
                hs.events_processed = event_count;
                hs.last_window_ts = pipeline.current_metrics().window_end_ns;
            }
            if let Ok(mut ss) = status_snapshot.lock() {
                ss.state = dash_state.health;
                ss.health_score = dash_state.metrics.composite_health_score;
                ss.uptime_secs = start.elapsed().as_secs_f64();
                ss.events_processed = event_count;
                ss.metrics = dash_state.metrics.clone();
                ss.recent_alerts.clone_from(&dash_state.recent_alerts);
                ss.source_name.clone_from(&dash_state.source_name);
            }

            // Scheduler reconciliation — uses current_state(), not alerts (M5 fix)
            if let Some(ref rc) = shared_reconciler {
                let health = pipeline.detection_engine().current_state();
                if let Ok(mut reconciler) = rc.lock() {
                    let sched_events = reconciler.maybe_reconcile(health);
                    if !sched_events.is_empty() {
                        if let Ok(exp) = prom_exporter.lock() {
                            let drain_dur = reconciler
                                .last_drain_time()
                                .map(|t| t.elapsed().as_secs_f64())
                                .unwrap_or(0.0);
                            exp.update_scheduler(
                                &reconciler.desired_state(),
                                &reconciler.last_observed_state(),
                                &sched_events,
                                drain_dur,
                                reconciler.is_dry_run(),
                                reconciler.drain_rejections(),
                            );
                        }
                        reconciler.push_events(&sched_events);
                    }
                }
            }

            pipeline.reset_window();
            window_start = std::time::Instant::now();
        }

        if let Some(ref mut dash) = dashboard {
            dash_state.uptime_secs = start.elapsed().as_secs_f64();
            dash.draw(&dash_state)?;
        }

        std::thread::sleep(tick_interval);
    }

    if let Some(ref mut dash) = dashboard {
        dash.shutdown()?;
    }

    println!(
        "ARGUS finished: {event_count} events processed, final state: {}",
        pipeline.detection_engine().current_state()
    );

    Ok(())
}

/// Mock/Replay mode: event-driven processing with batch draining.
#[allow(clippy::too_many_arguments)]
async fn run_event_mode(
    mut source: AnyEventSource,
    source_name: String,
    config: &EffectiveConfig,
    mut pipeline: Pipeline,
    mut telemetry: TelemetryCollector,
    mut dash_state: DashboardState,
    mut dashboard: Option<Dashboard>,
    start: std::time::Instant,
    prom_exporter: std::sync::Arc<
        std::sync::Mutex<argus_agent::telemetry::prometheus::PrometheusExporter>,
    >,
    health_snapshot: std::sync::Arc<
        std::sync::Mutex<argus_agent::telemetry::prometheus::HealthSnapshot>,
    >,
    status_snapshot: std::sync::Arc<
        std::sync::Mutex<argus_agent::telemetry::prometheus::StatusSnapshot>,
    >,
    shared_reconciler: Option<std::sync::Arc<std::sync::Mutex<argus_agent::scheduler::Reconciler>>>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    dash_state.source_name = source_name;

    #[cfg(target_os = "linux")]
    let hw_reader = if matches!(config.mode, RunMode::Live) {
        let reader = argus_agent::sources::hwcounters::HwCounterReader::discover();
        if reader.port_count() > 0 {
            tracing::info!(
                ports = reader.port_count(),
                "discovered IB ports for hw counters"
            );
        }
        Some(reader)
    } else {
        None
    };

    let mut event_count = 0u64;
    let window_duration = std::time::Duration::from_secs(config.window_secs);
    let display_interval = std::time::Duration::from_millis(200);
    let mut window_start = std::time::Instant::now();
    let mut last_display = std::time::Instant::now();

    loop {
        if *shutdown_rx.borrow() {
            tracing::info!("received shutdown signal, exiting gracefully");
            break;
        }

        if let Some(ref dash) = dashboard {
            if dash.poll_quit()? {
                break;
            }
        }

        if window_start.elapsed() >= window_duration {
            #[cfg(target_os = "linux")]
            if let Some(ref reader) = hw_reader {
                for hw_event in reader.read_all() {
                    pipeline.ingest(&hw_event);
                }
            }

            let alerts = pipeline.evaluate();

            // Stamp per-port idle state. Mock/replay won't usually have IB
            // ports discovered, so this list is normally empty — but if the
            // host *does* have IB and we're scraping its counters in mock
            // mode, the visibility carries through.
            #[cfg(target_os = "linux")]
            let discovered_ports: Vec<(String, u32)> = hw_reader
                .as_ref()
                .map(|r| {
                    r.discovered_ports()
                        .into_iter()
                        .map(|(d, p, _)| (d, p))
                        .collect()
                })
                .unwrap_or_default();
            #[cfg(not(target_os = "linux"))]
            let discovered_ports: Vec<(String, u32)> = Vec::new();
            pipeline.finalize_idle_window(&discovered_ports, config.window_secs);

            for alert in alerts {
                if let Ok(exp) = prom_exporter.lock() {
                    exp.record_alert(alert.kind_name(), &alert.severity.to_string());
                }
                telemetry.record_alert(alert.clone());
                dash_state.recent_alerts.push(alert);
                if dash_state.recent_alerts.len() > 100 {
                    dash_state.recent_alerts.remove(0);
                }
            }
            dash_state.health = pipeline.detection_engine().current_state();
            dash_state.metrics = pipeline.current_metrics().clone();
            dash_state.push_metrics_snapshot();

            if let Ok(mut exp) = prom_exporter.lock() {
                exp.update(pipeline.current_metrics(), dash_state.health, event_count);
                exp.update_score_components(pipeline.detection_engine().smoothed_score());
                exp.update_sample_contribution(
                    pipeline.detection_engine().last_sample_contribution(),
                );
                exp.update_cq_latency_quantiles(pipeline.last_samples());
                exp.update_timescales(pipeline.detection_engine().multi_timescale());
                let class = pipeline.detection_engine().burst_class();
                exp.update_burst_classification(&[
                    (
                        "quiet",
                        class == argus_agent::detection::burst::BurstClass::Quiet,
                    ),
                    (
                        "burst",
                        class == argus_agent::detection::burst::BurstClass::Burst,
                    ),
                    (
                        "sustained",
                        class == argus_agent::detection::burst::BurstClass::Sustained,
                    ),
                    (
                        "mixed",
                        class == argus_agent::detection::burst::BurstClass::MixedBurstSustained,
                    ),
                ]);
            }
            if let Ok(mut hs) = health_snapshot.lock() {
                hs.state = dash_state.health;
                hs.uptime_secs = start.elapsed().as_secs_f64();
                hs.events_processed = event_count;
                hs.last_window_ts = pipeline.current_metrics().window_end_ns;
            }
            if let Ok(mut ss) = status_snapshot.lock() {
                ss.state = dash_state.health;
                ss.health_score = dash_state.metrics.composite_health_score;
                ss.uptime_secs = start.elapsed().as_secs_f64();
                ss.events_processed = event_count;
                ss.metrics = dash_state.metrics.clone();
                ss.recent_alerts.clone_from(&dash_state.recent_alerts);
                ss.source_name.clone_from(&dash_state.source_name);
            }

            // Scheduler reconciliation (event mode)
            if let Some(ref rc) = shared_reconciler {
                let health = pipeline.detection_engine().current_state();
                if let Ok(mut reconciler) = rc.lock() {
                    let sched_events = reconciler.maybe_reconcile(health);
                    if !sched_events.is_empty() {
                        if let Ok(exp) = prom_exporter.lock() {
                            let drain_dur = reconciler
                                .last_drain_time()
                                .map_or(0.0, |t| t.elapsed().as_secs_f64());
                            exp.update_scheduler(
                                &reconciler.desired_state(),
                                &reconciler.last_observed_state(),
                                &sched_events,
                                drain_dur,
                                reconciler.is_dry_run(),
                                reconciler.drain_rejections(),
                            );
                        }
                        reconciler.push_events(&sched_events);
                    }
                }
            }

            pipeline.reset_window();
            window_start = std::time::Instant::now();
        }

        match source.next_batch(512).await {
            Ok(events) => {
                event_count += events.len() as u64;
                for event in &events {
                    pipeline.ingest(event);
                }

                if last_display.elapsed() >= display_interval {
                    dash_state.metrics = pipeline.current_metrics().clone();
                    dash_state.event_count = event_count;
                    dash_state.uptime_secs = start.elapsed().as_secs_f64();

                    if let Some(ref mut dash) = dashboard {
                        dash.draw(&dash_state)?;
                    }
                    last_display = std::time::Instant::now();
                }
            }
            Err(argus_agent::sources::EventSourceError::Exhausted) => {
                let alerts = pipeline.evaluate();
                for alert in alerts {
                    telemetry.record_alert(alert.clone());
                    dash_state.recent_alerts.push(alert);
                }
                dash_state.health = pipeline.detection_engine().current_state();
                dash_state.metrics = pipeline.current_metrics().clone();
                dash_state.push_metrics_snapshot();

                if let Some(ref mut dash) = dashboard {
                    dash_state.uptime_secs = start.elapsed().as_secs_f64();
                    dash.draw(&dash_state)?;

                    loop {
                        if *shutdown_rx.borrow() || dash.poll_quit()? {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
                break;
            }
            Err(e) => {
                if let Some(ref mut dash) = dashboard {
                    let _ = dash.shutdown();
                }
                return Err(anyhow::anyhow!("event source error: {e}"));
            }
        }
    }

    if let Some(ref mut dash) = dashboard {
        dash.shutdown()?;
    }

    println!(
        "ARGUS finished: {} events processed, final state: {}",
        event_count,
        pipeline.detection_engine().current_state()
    );

    Ok(())
}

/// Attach-mode TUI: read-only viewer that connects to a running daemon's /status endpoint.
/// Does not load eBPF, does not start a pipeline — purely a display client.
async fn run_attach_tui(addr: &str, tls_skip_verify: bool, auth_token: Option<&str>) -> Result<()> {
    use argus_agent::telemetry::prometheus::StatusSnapshot;

    // Normalize the attach target into scheme://host:port. The scheme is
    // split off first so `https://node` still gets the default port appended.
    // IPv6 literals must be bracketed (`[::1]` or `[::1]:9100`).
    let (scheme, host_part) = addr
        .split_once("://")
        .map_or(("http", addr), |(s, h)| (s, h));
    let has_port = if let Some(v6) = host_part.strip_prefix('[') {
        v6.contains("]:")
    } else {
        host_part
            .split_once(':')
            .is_some_and(|(_, p)| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    };
    let host_with_port = if has_port {
        host_part.to_string()
    } else {
        format!("{host_part}:9100")
    };
    let addr = format!("{scheme}://{host_with_port}");
    let status_url = format!("{addr}/status");

    // Honor the same bearer token the daemon side accepts. The token is
    // surfaced through --auth-token / ARGUS_METRICS_TOKEN — exactly what the
    // 401 hint below tells the operator to set.
    let mut default_headers = reqwest::header::HeaderMap::new();
    if let Some(token) = auth_token {
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .context("auth token contains characters not permitted in an HTTP header")?;
        value.set_sensitive(true);
        default_headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .danger_accept_invalid_certs(tls_skip_verify)
        .default_headers(default_headers)
        .build()?;

    // Probe once up front. Most operator-facing failures (daemon not
    // running, wrong port, missing auth token, TLS mismatch) are
    // instantly diagnosable from the first failure — don't make the
    // operator stare at "waiting..." for 30 seconds before getting
    // anything useful.
    //
    // The short retry burst that follows handles the genuinely-transient
    // case: argus-tui invoked while systemd is mid-restart. Three
    // attempts at 1s each is enough for that — if the daemon isn't back
    // by then, it's not coming.
    let max_attempts = 3;
    let retry_interval = std::time::Duration::from_secs(1);
    let mut last_error: Option<String> = None;

    for attempt in 1..=max_attempts {
        match client.get(&status_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                last_error = None;
                break;
            }
            Ok(resp) => {
                let code = resp.status();
                last_error = Some(match code.as_u16() {
                    401 => format!(
                        "{status_url} returned 401 Unauthorized — the daemon requires a bearer token. \
                         Pass it via env: ARGUS_METRICS_TOKEN=$(sudo cat /etc/argus/token) argus-tui"
                    ),
                    503 => format!(
                        "{status_url} returned 503 Service Unavailable — the daemon is up but not \
                         ready to serve. Check `journalctl -u argusd -e` for startup errors."
                    ),
                    _ => format!("{status_url} returned HTTP {code}"),
                });
                // Auth/client errors are deterministic — retrying the same
                // request can't succeed, so fail fast with the guidance.
                if code.is_client_error() {
                    break;
                }
                if attempt < max_attempts {
                    eprintln!(
                        "retry {attempt}/{max_attempts}: {}",
                        last_error.as_ref().unwrap()
                    );
                }
            }
            Err(e) => {
                last_error = Some(diagnose_connect_error(&status_url, &e));
                if attempt < max_attempts {
                    eprintln!(
                        "retry {attempt}/{max_attempts}: {}",
                        last_error.as_ref().unwrap()
                    );
                }
            }
        }
        if attempt < max_attempts {
            tokio::time::sleep(retry_interval).await;
        }
    }

    if let Some(err) = last_error {
        bail!("{err}");
    }

    let mut dashboard = Dashboard::new()?;
    let mut dash_state = DashboardState {
        source_name: format!("attach/{addr}"),
        ..Default::default()
    };

    let poll_interval = std::time::Duration::from_millis(1000);
    let draw_interval = std::time::Duration::from_millis(200);
    // None = no poll yet; forces an immediate first poll without doing
    // Instant arithmetic that can underflow shortly after boot.
    let mut last_poll: Option<std::time::Instant> = None;

    loop {
        if dashboard.poll_quit()? {
            break;
        }

        if last_poll.is_none_or(|t| t.elapsed() >= poll_interval) {
            match client.get(&status_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(snap) = resp.json::<StatusSnapshot>().await {
                        // De-dup: only push to the history Vecs when the
                        // remote actually advanced to a new window. The
                        // /status poll interval (1s) is faster than the
                        // agent's window_secs (default 3s), so without this
                        // check the sparklines would repeat the same value
                        // 2-3 times before changing.
                        let advanced =
                            snap.metrics.window_end_ns != dash_state.metrics.window_end_ns;

                        dash_state.health = snap.state;
                        dash_state.metrics = snap.metrics;
                        dash_state.recent_alerts = snap.recent_alerts;
                        dash_state.event_count = snap.events_processed;
                        dash_state.uptime_secs = snap.uptime_secs;
                        dash_state.source_name = if snap.source_name.is_empty() {
                            format!("attach/{addr}")
                        } else {
                            format!("attach/{} ({})", addr, snap.source_name)
                        };

                        // Append the freshly-arrived window to the sparkline
                        // history. Without this every panel renders the
                        // "Waiting for data..." placeholder forever because
                        // *_history stays empty.
                        if advanced {
                            dash_state.push_metrics_snapshot();
                        }
                    }
                }
                _ => {
                    dash_state.source_name = format!("attach/{addr} [disconnected]");
                }
            }
            last_poll = Some(std::time::Instant::now());
        }

        dash_state.uptime_secs += 0.2;
        dashboard.draw(&dash_state)?;
        tokio::time::sleep(draw_interval).await;
    }

    dashboard.shutdown()?;
    Ok(())
}

/// Translate a reqwest connect error into an actionable diagnostic that
/// names the specific operator action to take. Avoids the
/// "waiting for argusd..." goose chase by saying exactly what's wrong
/// the first time the request fails.
fn diagnose_connect_error(url: &str, err: &reqwest::Error) -> String {
    let msg = err.to_string();
    let is_local = url.contains("localhost") || url.contains("127.0.0.1");

    // Connection refused → port not listening → daemon is down or bound elsewhere.
    if msg.contains("Connection refused") || msg.contains("connection refused") {
        if is_local {
            return format!(
                "{url}: connection refused. The daemon isn't listening here.\n  \
                 Check:  systemctl status argusd\n  \
                 Logs:   journalctl -u argusd -e --no-pager | tail -30\n  \
                 If it's running, confirm the port: ss -tlnp | grep 9100"
            );
        }
        return format!(
            "{url}: connection refused. Either argusd isn't running on that host, \
             or its ARGUS_METRICS_ADDR doesn't include this interface. \
             Check the conf on the target: grep ARGUS_METRICS_ADDR /etc/argus/argusd.conf"
        );
    }

    // Timeout → daemon may be running but stuck, or network unreachable.
    if msg.contains("timed out") || msg.contains("operation timed out") {
        return format!(
            "{url}: request timed out. The daemon may be running but unresponsive \
             (deadlocked main loop), or firewalld is dropping packets silently. \
             Check:  journalctl -u argusd -e | tail -30  AND  firewall-cmd --list-all"
        );
    }

    // DNS / name resolution.
    if msg.contains("dns") || msg.contains("failed to lookup") {
        return format!("{url}: DNS resolution failed. Use an IP address or fix /etc/hosts.");
    }

    // TLS handshake errors.
    if msg.contains("certificate") || msg.contains("handshake") {
        return format!(
            "{url}: TLS handshake failed. The daemon may be using HTTP not HTTPS, \
             or the certificate is rejected by your trust store. \
             Try: argus-tui --tls-skip-verify --attach <host>"
        );
    }

    // Fall-through: report the raw error verbatim.
    format!("{url}: {msg}")
}

/// Install a panic hook that restores the terminal (if in raw mode) and
/// emits structured logging before the process aborts.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Attempt terminal restoration so the user's shell isn't left in raw mode.
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stderr(), crossterm::terminal::LeaveAlternateScreen);

        let location = info.location().map_or_else(
            || "<unknown>".into(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic>".into()
        };

        tracing::error!(
            component = "agent",
            panic.location = %location,
            panic.payload = %payload,
            "ARGUS agent panicked — aborting"
        );

        default_hook(info);
    }));
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => {},
                    _ = sigterm.recv() => {},
                }
            }
            Err(e) => {
                tracing::warn!(
                    component = "agent",
                    error = %e,
                    "SIGTERM handler unavailable, falling back to ctrl-c only"
                );
                ctrl_c.await.ok();
            }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}

/// Acquire an advisory lock on a PID file to prevent multiple agent instances.
/// Returns a guard that holds the lock file open; dropping it releases the lock.
///
/// Only called in live mode (daemon). Requires root, which live mode needs
/// anyway for eBPF. The directory is normally created by systemd
/// (`RuntimeDirectory=argus`) or the install script.
fn acquire_pid_lock() -> Result<std::fs::File> {
    use std::io::Write;

    let pid_dir = std::path::Path::new("/var/run/argus");
    if !pid_dir.exists() {
        std::fs::create_dir_all(pid_dir).context("failed to create /var/run/argus for PID file")?;
    }
    let pid_path = pid_dir.join("argusd.pid");
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts
        .open(&pid_path)
        .with_context(|| format!("failed to open PID file: {}", pid_path.display()))?;

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: flock is a POSIX advisory lock on a valid fd we own.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            bail!(
                "another argusd instance is already running (could not lock {})",
                pid_path.display()
            );
        }
    }

    write!(file, "{}", std::process::id())
        .with_context(|| format!("failed to write PID to {}", pid_path.display()))?;
    file.sync_all()?;

    tracing::info!(
        pid = std::process::id(),
        path = %pid_path.display(),
        component = "agent",
        "PID file lock acquired"
    );
    Ok(file)
}

/// Load expected eBPF hash from the well-known path written by RPM %post.
/// Returns None if the file doesn't exist (dev workflow: no hash = no check).
#[cfg(target_os = "linux")]
fn load_ebpf_hash_file() -> Option<String> {
    let hash_path = std::path::Path::new("/etc/argus/ebpf.sha256");
    match std::fs::read_to_string(hash_path) {
        Ok(contents) => {
            let hash = contents.split_whitespace().next()?.trim().to_string();
            if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                tracing::info!("loaded eBPF hash from {}", hash_path.display());
                Some(hash)
            } else {
                tracing::warn!("malformed eBPF hash file: {}", hash_path.display());
                None
            }
        }
        Err(_) => None,
    }
}

#[cfg(target_os = "linux")]
fn verify_ebpf_hash(path: &std::path::Path, expected: &str) -> Result<()> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read eBPF artifact: {}", path.display()))?;
    let hash = hex::encode(Sha256::digest(&data));
    if hash != expected.to_lowercase() {
        bail!(
            "eBPF artifact hash mismatch!\n  expected: {expected}\n  actual:   {hash}\n  \
             path: {}\n  \
             Refusing to load — this may indicate a tampered or mismatched binary.",
            path.display()
        );
    }
    tracing::info!("eBPF artifact hash verified: {hash}");
    Ok(())
}

fn build_event_source(config: &EffectiveConfig) -> Result<(AnyEventSource, String)> {
    match config.mode {
        RunMode::Mock => {
            let base = match config.profile {
                MockProfile::Healthy => MockConfig::healthy(),
                MockProfile::Skew => MockConfig::interrupt_skew(),
                MockProfile::Spike => MockConfig::rdma_latency_spike(),
                MockProfile::Pressure => MockConfig::slab_pressure(),
            };
            let mc = MockConfig {
                num_cpus: config.num_cpus,
                max_events: if config.max_events > 0 {
                    Some(config.max_events)
                } else {
                    None
                },
                ..base
            };
            let name = format!("mock/{:?} (simulated)", config.profile).to_lowercase();
            Ok((AnyEventSource::Mock(MockEventSource::new(mc)), name))
        }
        RunMode::Replay => {
            const MAX_REPLAY_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB
            const MAX_REPLAY_EVENTS: usize = 10_000_000;

            let path = config
                .file
                .as_ref()
                .context("--file <path> is required in replay mode")?;

            if !path.exists() {
                bail!("file not found: {}", path.display());
            }

            let file_size = std::fs::metadata(path)
                .with_context(|| format!("failed to stat {}", path.display()))?
                .len();
            if file_size > MAX_REPLAY_FILE_SIZE {
                bail!(
                    "replay file too large: {file_size} bytes (max {MAX_REPLAY_FILE_SIZE}). \
                     This limit prevents OOM from malformed inputs."
                );
            }

            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;

            let source = if let Ok(scenario) =
                serde_json::from_str::<argus_common::TestScenario>(&contents)
            {
                if scenario.events.len() > MAX_REPLAY_EVENTS {
                    bail!(
                        "scenario has {} events (max {MAX_REPLAY_EVENTS})",
                        scenario.events.len()
                    );
                }
                tracing::info!(
                    name = scenario.name,
                    events = scenario.events.len(),
                    "loaded scenario"
                );
                ReplayEventSource::from_events(scenario.events)
            } else {
                let events: Vec<argus_common::ArgusEvent> = serde_json::from_str(&contents)
                    .with_context(|| {
                        format!("failed to parse {} as events or scenario", path.display())
                    })?;
                if events.len() > MAX_REPLAY_EVENTS {
                    bail!(
                        "replay file has {} events (max {MAX_REPLAY_EVENTS})",
                        events.len()
                    );
                }
                ReplayEventSource::from_events(events)
            };

            let source = source.with_time_scale(config.time_scale);
            let name = format!(
                "replay/{}",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            Ok((AnyEventSource::Replay(source), name))
        }
        RunMode::Live => {
            bail!("live mode handled separately — this path should not be reached");
        }
    }
}

#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

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

    if let Some(ref addr) = config.attach {
        return run_attach_tui(addr).await;
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

    if let Some(ref path) = config.tls_cert {
        tracing::info!(?path, "TLS enabled for metrics endpoint");
    }
    if config.auth_token.is_some() {
        tracing::info!("bearer token auth enabled for metrics endpoint");
    }

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
        .map(|f| f.name().to_string())
        .unwrap_or_else(|| "none".into());

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
                .map(|b| b.name())
                .unwrap_or("none");
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
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".into());
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
        tokio::spawn(async move {
            if let Err(e) =
                argus_agent::telemetry::prometheus::serve_metrics(
                    exp, hs, ss, rc, cov, addr, tls_cfg, auth_token,
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

    match config.mode {
        RunMode::Live => {
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
            }
            #[cfg(not(target_os = "linux"))]
            {
                bail!("live eBPF mode requires Linux — use --mode mock or --mode replay on this platform");
            }
        }
        _ => {
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
        }
    }

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
    shared_reconciler: Option<
        std::sync::Arc<std::sync::Mutex<argus_agent::scheduler::Reconciler>>,
    >,
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

    let ebpf_hash = config
        .ebpf_hash
        .clone()
        .or_else(|| load_ebpf_hash_file());
    if let Some(ref expected_hash) = ebpf_hash {
        verify_ebpf_hash(ebpf_path, expected_hash)?;
    } else {
        tracing::info!("no eBPF hash file or --ebpf-hash; skipping integrity check");
    }

    let mut ebpf_source = argus_agent::sources::ebpf::EbpfEventSource::new(ebpf_path)
        .map_err(|e| anyhow::anyhow!("failed to load eBPF probes: {e}"))?;

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
                    ("quiet", class == argus_agent::detection::burst::BurstClass::Quiet),
                    ("burst", class == argus_agent::detection::burst::BurstClass::Burst),
                    ("sustained", class == argus_agent::detection::burst::BurstClass::Sustained),
                    ("mixed", class == argus_agent::detection::burst::BurstClass::MixedBurstSustained),
                ]);
                for (device, port, dev_type) in hw_reader.discovered_ports() {
                    exp.update_ib_counters(
                        &device,
                        &port.to_string(),
                        &pipeline.current_metrics().ib_counter_deltas,
                        dev_type,
                    );
                }
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
                ss.recent_alerts = dash_state.recent_alerts.clone();
                ss.source_name = dash_state.source_name.clone();
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
    shared_reconciler: Option<
        std::sync::Arc<std::sync::Mutex<argus_agent::scheduler::Reconciler>>,
    >,
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
                    ("quiet", class == argus_agent::detection::burst::BurstClass::Quiet),
                    ("burst", class == argus_agent::detection::burst::BurstClass::Burst),
                    ("sustained", class == argus_agent::detection::burst::BurstClass::Sustained),
                    ("mixed", class == argus_agent::detection::burst::BurstClass::MixedBurstSustained),
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
                ss.recent_alerts = dash_state.recent_alerts.clone();
                ss.source_name = dash_state.source_name.clone();
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
                    dash.shutdown()?;
                }
                eprintln!("Event source error: {e}");
                break;
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
async fn run_attach_tui(addr: &str) -> Result<()> {
    use argus_agent::telemetry::prometheus::StatusSnapshot;

    let addr_with_port = if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{addr}:9100")
    };
    let addr = if addr_with_port.contains("://") {
        addr_with_port
    } else {
        format!("http://{addr_with_port}")
    };
    let status_url = format!("{addr}/status");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()?;

    // Verify connectivity before entering raw mode
    let resp = client
        .get(&status_url)
        .send()
        .await
        .with_context(|| format!("cannot reach {status_url}"))?;
    if !resp.status().is_success() {
        bail!(
            "{} returned {} — is argusd running?",
            status_url,
            resp.status()
        );
    }

    let mut dashboard = Dashboard::new()?;
    let mut dash_state = DashboardState::default();
    dash_state.source_name = format!("attach/{addr}");

    let poll_interval = std::time::Duration::from_millis(1000);
    let draw_interval = std::time::Duration::from_millis(200);
    let mut last_poll = std::time::Instant::now() - poll_interval;

    loop {
        if dashboard.poll_quit()? {
            break;
        }

        if last_poll.elapsed() >= poll_interval {
            if let Ok(resp) = client.get(&status_url).send().await {
                if let Ok(snap) = resp.json::<StatusSnapshot>().await {
                    dash_state.health = snap.state;
                    dash_state.metrics = snap.metrics;
                    dash_state.recent_alerts = snap.recent_alerts;
                    dash_state.event_count = snap.events_processed;
                    dash_state.uptime_secs = snap.uptime_secs;
                    if !snap.source_name.is_empty() {
                        dash_state.source_name =
                            format!("attach/{} ({})", addr, snap.source_name);
                    }
                    dash_state.push_metrics_snapshot();
                }
            }
            last_poll = std::time::Instant::now();
        }

        dash_state.uptime_secs += 0.2;
        dashboard.draw(&dash_state)?;
        tokio::time::sleep(draw_interval).await;
    }

    dashboard.shutdown()?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
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
                    "replay file too large: {} bytes (max {}). \
                     This limit prevents OOM from malformed inputs.",
                    file_size,
                    MAX_REPLAY_FILE_SIZE
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

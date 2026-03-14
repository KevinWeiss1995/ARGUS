#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use anyhow::{bail, Context, Result};
use argus_agent::config::{Cli, MockProfile, RunMode};
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
    let cli = Cli::parse();

    if !cli.tui {
        let log_level: tracing::Level = cli.log_level.parse().unwrap_or(tracing::Level::INFO);
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env().add_directive(log_level.into()),
            )
            .json()
            .init();
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let (mut source, source_name) = build_event_source(&cli)?;

    // After eBPF programs are loaded and attached, drop privileges
    if matches!(cli.mode, RunMode::Live) {
        argus_agent::security::drop_privileges();
        if cli.seccomp {
            argus_agent::security::apply_seccomp();
        }
    }

    #[cfg(target_os = "linux")]
    let hw_reader = if matches!(cli.mode, RunMode::Live) {
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

    let detection_config = argus_agent::config::DetectionConfig::default();
    let mut pipeline = Pipeline::with_config(cli.num_cpus, &detection_config);
    let mut telemetry = TelemetryCollector::default();
    let mut dash_state = DashboardState {
        source_name,
        ..Default::default()
    };
    let start = std::time::Instant::now();

    // Metrics server (prometheus + health endpoint)
    let prom_exporter = std::sync::Arc::new(std::sync::Mutex::new(
        argus_agent::telemetry::prometheus::PrometheusExporter::new(),
    ));
    let health_snapshot = std::sync::Arc::new(std::sync::Mutex::new(
        argus_agent::telemetry::prometheus::HealthSnapshot::default(),
    ));
    if let Some(ref addr_str) = cli.metrics_addr {
        let addr: std::net::SocketAddr = addr_str
            .parse()
            .with_context(|| format!("invalid --metrics-addr: {addr_str}"))?;
        let exp = prom_exporter.clone();
        let hs = health_snapshot.clone();
        tokio::spawn(async move {
            if let Err(e) = argus_agent::telemetry::prometheus::serve_metrics(exp, hs, addr).await {
                tracing::error!("metrics server failed: {e}");
            }
        });
    }

    let mut dashboard = if cli.tui {
        Some(Dashboard::new()?)
    } else {
        None
    };

    let mut event_count = 0u64;
    let window_duration = std::time::Duration::from_secs(cli.window_secs);
    let mut window_start = std::time::Instant::now();

    let shutdown_rx = shutdown_rx;

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
            // Poll hardware counters at window boundary (live mode only)
            #[cfg(target_os = "linux")]
            if let Some(ref reader) = hw_reader {
                for hw_event in reader.read_all() {
                    pipeline.ingest(&hw_event);
                }
            }

            // Run detection once per window, so alerts and sparklines appear together
            let alerts = pipeline.evaluate();
            for alert in alerts {
                telemetry.record_alert(alert.clone());
                dash_state.recent_alerts.push(alert);
                if dash_state.recent_alerts.len() > 100 {
                    dash_state.recent_alerts.remove(0);
                }
            }
            dash_state.health = pipeline.detection_engine().current_state();
            dash_state.metrics = pipeline.current_metrics().clone();
            dash_state.push_metrics_snapshot();

            // Update prometheus and health snapshot
            if let Ok(exp) = prom_exporter.lock() {
                exp.update(pipeline.current_metrics(), dash_state.health, event_count);
            }
            if let Ok(mut hs) = health_snapshot.lock() {
                hs.state = dash_state.health;
                hs.uptime_secs = start.elapsed().as_secs_f64();
                hs.events_processed = event_count;
                hs.last_window_ts = pipeline.current_metrics().window_end_ns;
            }

            pipeline.reset_window();
            window_start = std::time::Instant::now();
        }

        match source.next_event().await {
            Ok(event) => {
                event_count += 1;
                pipeline.ingest(&event);

                dash_state.metrics = pipeline.current_metrics().clone();
                dash_state.event_count = event_count;
                dash_state.uptime_secs = start.elapsed().as_secs_f64();

                if let Some(ref mut dash) = dashboard {
                    dash.draw(&dash_state)?;
                }
            }
            Err(argus_agent::sources::EventSourceError::Exhausted) => {
                // Final window evaluation before exiting
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

fn build_event_source(cli: &Cli) -> Result<(AnyEventSource, String)> {
    match cli.mode {
        RunMode::Mock => {
            let base = match cli.profile {
                MockProfile::Healthy => MockConfig::healthy(),
                MockProfile::Skew => MockConfig::interrupt_skew(),
                MockProfile::Spike => MockConfig::rdma_latency_spike(),
                MockProfile::Pressure => MockConfig::slab_pressure(),
            };
            let config = MockConfig {
                num_cpus: cli.num_cpus,
                max_events: if cli.max_events > 0 {
                    Some(cli.max_events)
                } else {
                    None
                },
                ..base
            };
            let name = format!("mock/{:?} (simulated)", cli.profile).to_lowercase();
            Ok((AnyEventSource::Mock(MockEventSource::new(config)), name))
        }
        RunMode::Replay => {
            const MAX_REPLAY_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB
            const MAX_REPLAY_EVENTS: usize = 10_000_000;

            let path = cli
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

            // Try scenario format first (has "events" + "expected_states" fields),
            // fall back to raw event array.
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

            let source = source.with_time_scale(cli.time_scale);
            let name = format!(
                "replay/{}",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            Ok((AnyEventSource::Replay(source), name))
        }
        RunMode::Live => {
            #[cfg(target_os = "linux")]
            {
                let ebpf_path = cli
                    .ebpf_path
                    .as_ref()
                    .context("--ebpf-path <path> is required in live mode")?;

                if !ebpf_path.exists() {
                    bail!(
                        "eBPF artifact not found: {}\nBuild it with: just build-ebpf",
                        ebpf_path.display()
                    );
                }

                if let Some(ref expected_hash) = cli.ebpf_hash {
                    verify_ebpf_hash(ebpf_path, expected_hash)?;
                }

                let source = argus_agent::sources::ebpf::EbpfEventSource::new(ebpf_path)
                    .map_err(|e| anyhow::anyhow!("failed to load eBPF probes: {e}"))?;
                Ok((AnyEventSource::Ebpf(source), "ebpf/live".into()))
            }
            #[cfg(not(target_os = "linux"))]
            {
                bail!("live eBPF mode requires Linux — use --mode mock or --mode replay on this platform");
            }
        }
    }
}

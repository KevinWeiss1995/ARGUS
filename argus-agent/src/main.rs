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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.tui {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .json()
            .init();
    }

    let (mut source, source_name) = build_event_source(&cli)?;

    let mut pipeline = Pipeline::new(cli.num_cpus);
    let mut telemetry = TelemetryCollector::default();
    let mut dash_state = DashboardState {
        source_name,
        ..Default::default()
    };
    let start = std::time::Instant::now();

    let mut dashboard = if cli.tui {
        Some(Dashboard::new()?)
    } else {
        None
    };

    let mut event_count = 0u64;
    let window_duration = std::time::Duration::from_secs(cli.window_secs);
    let mut window_start = std::time::Instant::now();

    loop {
        if let Some(ref dash) = dashboard {
            if dash.poll_quit()? {
                break;
            }
        }

        if window_start.elapsed() >= window_duration {
            dash_state.push_metrics_snapshot();
            pipeline.reset_window();
            window_start = std::time::Instant::now();
        }

        match source.next_event().await {
            Ok(event) => {
                event_count += 1;
                let alerts = pipeline.process_event(&event);

                for alert in alerts {
                    telemetry.record_alert(alert.clone());
                    dash_state.recent_alerts.push(alert);
                    if dash_state.recent_alerts.len() > 100 {
                        dash_state.recent_alerts.remove(0);
                    }
                }

                dash_state.health = pipeline.detection_engine().current_state();
                dash_state.metrics = pipeline.current_metrics().clone();
                dash_state.event_count = event_count;
                dash_state.uptime_secs = start.elapsed().as_secs_f64();

                if let Some(ref mut dash) = dashboard {
                    dash.draw(&dash_state)?;
                }
            }
            Err(argus_agent::sources::EventSourceError::Exhausted) => {
                if let Some(ref mut dash) = dashboard {
                    dash_state.health = pipeline.detection_engine().current_state();
                    dash_state.uptime_secs = start.elapsed().as_secs_f64();
                    dash.draw(&dash_state)?;

                    loop {
                        if dash.poll_quit()? {
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
            let path = cli
                .file
                .as_ref()
                .context("--file <path> is required in replay mode")?;

            if !path.exists() {
                bail!("file not found: {}", path.display());
            }

            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;

            // Try scenario format first (has "events" + "expected_states" fields),
            // fall back to raw event array.
            let source = if let Ok(scenario) = serde_json::from_str::<argus_common::TestScenario>(&contents) {
                tracing::info!(
                    name = scenario.name,
                    events = scenario.events.len(),
                    "loaded scenario"
                );
                ReplayEventSource::from_events(scenario.events)
            } else {
                let events: Vec<argus_common::ArgusEvent> = serde_json::from_str(&contents)
                    .with_context(|| format!("failed to parse {} as events or scenario", path.display()))?;
                ReplayEventSource::from_events(events)
            };

            let source = source.with_time_scale(cli.time_scale);
            let name = format!("replay/{}", path.file_name().unwrap_or_default().to_string_lossy());
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

#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use anyhow::Result;
use argus_agent::config::{Cli, RunMode};
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

    let source_name = format!("{:?}", cli.mode).to_lowercase();

    let mut source: AnyEventSource = match cli.mode {
        RunMode::Mock => {
            let config = MockConfig {
                num_cpus: cli.num_cpus,
                max_events: if cli.max_events > 0 {
                    Some(cli.max_events)
                } else {
                    None
                },
                ..MockConfig::healthy()
            };
            AnyEventSource::Mock(MockEventSource::new(config))
        }
        RunMode::Replay => {
            let path = cli
                .replay_file
                .as_ref()
                .expect("--replay-file required in replay mode");
            let source = ReplayEventSource::from_file(path)?.with_time_scale(cli.time_scale);
            AnyEventSource::Replay(source)
        }
        RunMode::Scenario => {
            let scenario_name = cli
                .scenario
                .as_ref()
                .expect("--scenario required in scenario mode");
            let path = std::path::PathBuf::from(format!(
                "argus-test-scenarios/scenarios/{scenario_name}.json"
            ));
            let (source, _expected) = ReplayEventSource::from_scenario_file(&path)?;
            AnyEventSource::Replay(source.with_time_scale(cli.time_scale))
        }
        RunMode::Live => {
            #[cfg(target_os = "linux")]
            {
                eprintln!("Live eBPF mode not yet implemented (Phase 3)");
                return Ok(());
            }
            #[cfg(not(target_os = "linux"))]
            {
                eprintln!("Live eBPF mode requires Linux");
                return Ok(());
            }
        }
    };

    let mut pipeline = Pipeline::new(cli.num_cpus);
    let mut telemetry = TelemetryCollector::default();
    let mut dash_state = DashboardState {
        source_name: source_name.clone(),
        ..Default::default()
    };
    let start = std::time::Instant::now();

    let mut dashboard = if cli.tui {
        Some(Dashboard::new()?)
    } else {
        None
    };

    let mut event_count = 0u64;

    loop {
        if let Some(ref dash) = dashboard {
            if dash.poll_quit()? {
                break;
            }
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
                dash_state.push_metrics_snapshot();

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

use argus_agent::capabilities::FabricEnv;
use argus_agent::config::DetectionConfig;
use argus_agent::pipeline::Pipeline;
use argus_common::TestScenario;
use std::path::PathBuf;

fn run_scenario(scenario_path: &str) {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join(scenario_path);
    let path = path.as_path();
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read scenario {scenario_path}: {e}"));
    let scenario: TestScenario = serde_json::from_str(&contents)
        .unwrap_or_else(|e| panic!("Failed to parse scenario {scenario_path}: {e}"));

    // Use synthetic env so capability providers report Available at full
    // quality (otherwise the coverage-weighted severity floor would scale
    // rule verdicts to ~0 on hosts that lack RDMA hardware, e.g., CI).
    let mut pipeline =
        Pipeline::with_fabric(4, FabricEnv::synthetic(), &DetectionConfig::default());

    for (i, event) in scenario.events.iter().enumerate() {
        pipeline.ingest(event);

        for expected in &scenario.expected_states {
            if expected.after_event_index == i {
                // Evaluate multiple windows to let the score build through
                // EWMA + peak-hold and satisfy dwell timers. Each iteration
                // re-ingests the same event set into a fresh window, then
                // evaluates. This simulates sustained signal.
                for _ in 0..6 {
                    let _ = pipeline.evaluate();
                    pipeline.reset_window();
                    for ev in &scenario.events[..=i] {
                        pipeline.ingest(ev);
                    }
                }
                let _ = pipeline.evaluate();
                let actual_state = pipeline.detection_engine().current_state();
                assert_eq!(
                    actual_state, expected.expected_state,
                    "Scenario '{}': after event {i}, expected {:?} but got {:?}",
                    scenario.name, expected.expected_state, actual_state
                );
            }
        }
    }
}

#[test]
fn scenario_healthy_baseline() {
    run_scenario("argus-test-scenarios/scenarios/healthy_baseline.json");
}

#[test]
fn scenario_interrupt_skew_ramp() {
    run_scenario("argus-test-scenarios/scenarios/interrupt_skew_ramp.json");
}

#[test]
fn scenario_rdma_latency_spike() {
    run_scenario("argus-test-scenarios/scenarios/rdma_latency_spike.json");
}

#[test]
fn scenario_slab_pressure_cascade() {
    run_scenario("argus-test-scenarios/scenarios/slab_pressure_cascade.json");
}

#[test]
fn scenario_link_flap_critical() {
    run_scenario("argus-test-scenarios/scenarios/link_flap_critical.json");
}

#[test]
fn scenario_cable_degradation_slow() {
    run_scenario("argus-test-scenarios/scenarios/cable_degradation_slow.json");
}

#[test]
fn scenario_cable_fault_fast() {
    run_scenario("argus-test-scenarios/scenarios/cable_fault_fast.json");
}

#[test]
fn scenario_noisy_but_healthy() {
    run_scenario("argus-test-scenarios/scenarios/noisy_but_healthy.json");
}

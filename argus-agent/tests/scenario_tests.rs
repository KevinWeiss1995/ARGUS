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

    let mut pipeline = Pipeline::new(4);

    for (i, event) in scenario.events.iter().enumerate() {
        pipeline.ingest(event);

        for expected in &scenario.expected_states {
            if expected.after_event_index == i {
                // Evaluate multiple times to satisfy hysteresis (2 windows).
                // Since all events are in the same window, we evaluate twice.
                let _ = pipeline.evaluate();
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

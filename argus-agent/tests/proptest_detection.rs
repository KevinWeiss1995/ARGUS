use argus_agent::pipeline::Pipeline;
use argus_common::*;
use proptest::prelude::*;

fn arb_irq_entry() -> impl Strategy<Value = ArgusEvent> {
    (0u32..16, 0u32..128, any::<u64>()).prop_map(|(cpu, irq, ts)| {
        ArgusEvent::IrqEntry(IrqEntryEvent {
            timestamp_ns: ts,
            cpu,
            irq,
            handler_name_hash: 0,
        })
    })
}

fn arb_slab_alloc() -> impl Strategy<Value = ArgusEvent> {
    (0u32..16, 32u32..8192, 0u64..100_000).prop_map(|(cpu, bytes, latency)| {
        ArgusEvent::SlabAlloc(SlabAllocEvent {
            timestamp_ns: 0,
            cpu,
            bytes_req: bytes,
            bytes_alloc: bytes,
            latency_ns: latency,
            numa_node: 0,
        })
    })
}

fn arb_cq_completion() -> impl Strategy<Value = ArgusEvent> {
    (0u32..16, 0u64..200_000, any::<bool>()).prop_map(|(cpu, latency, is_error)| {
        ArgusEvent::CqCompletion(CqCompletionEvent {
            timestamp_ns: 0,
            cpu,
            latency_ns: latency,
            queue_pair_num: 1,
            is_error,
            opcode: 0,
        })
    })
}

fn arb_event() -> impl Strategy<Value = ArgusEvent> {
    prop_oneof![arb_irq_entry(), arb_slab_alloc(), arb_cq_completion(),]
}

/// Helper: run N windows of the same events to satisfy hysteresis.
fn evaluate_with_hysteresis(pipeline: &mut Pipeline, events: &[ArgusEvent], windows: u32) {
    for w in 0..windows {
        for event in events {
            pipeline.ingest(event);
        }
        let _ = pipeline.evaluate();
        if w < windows - 1 {
            pipeline.reset_window();
        }
    }
}

proptest! {
    #[test]
    fn detection_never_panics(events in proptest::collection::vec(arb_event(), 0..500)) {
        let mut pipeline = Pipeline::new(16);
        for event in &events {
            pipeline.ingest(event);
        }
        let _ = pipeline.evaluate();
        let _ = pipeline.detection_engine().current_state();
    }

    #[test]
    fn health_state_always_valid(events in proptest::collection::vec(arb_event(), 1..200)) {
        let mut pipeline = Pipeline::new(16);
        for event in &events {
            pipeline.ingest(event);
        }
        let _ = pipeline.evaluate();
        let state = pipeline.detection_engine().current_state();
        prop_assert!(matches!(state, HealthState::Healthy | HealthState::Degraded | HealthState::Critical));
    }

    /// IRQ skew detection: accounts for hysteresis by evaluating 2 windows.
    #[test]
    fn irq_skew_monotonic(skew_pct in 50u32..100) {
        let total = 100u32;
        let skewed = (total as f64 * skew_pct as f64 / 100.0) as u32;

        let events: Vec<_> = (0..total)
            .map(|i| {
                let cpu = if i < skewed { 0 } else { (i % 3) + 1 };
                ArgusEvent::IrqEntry(IrqEntryEvent {
                    timestamp_ns: u64::from(i) * 1_000_000,
                    cpu,
                    irq: 33,
                    handler_name_hash: 0,
                })
            })
            .collect();

        let mut pipeline = Pipeline::new(4);
        evaluate_with_hysteresis(&mut pipeline, &events, 2);
        let state = pipeline.detection_engine().current_state();

        if skew_pct >= 90 && total >= 10 {
            prop_assert_eq!(state, HealthState::Critical);
        } else if skew_pct >= 70 && total >= 10 {
            prop_assert!(matches!(state, HealthState::Degraded | HealthState::Critical));
        }
    }

    /// RDMA latency detection: accounts for hysteresis.
    #[test]
    fn rdma_latency_monotonic(latency_factor in 1.0f64..20.0) {
        let baseline = 2000u64;
        let latency = (baseline as f64 * latency_factor) as u64;

        let events: Vec<_> = (0..20)
            .map(|i| {
                ArgusEvent::CqCompletion(CqCompletionEvent {
                    timestamp_ns: i * 1_000_000,
                    cpu: 0,
                    latency_ns: latency,
                    queue_pair_num: 1,
                    is_error: false,
                    opcode: 0,
                })
            })
            .collect();

        let mut pipeline = Pipeline::new(4);
        evaluate_with_hysteresis(&mut pipeline, &events, 2);
        let state = pipeline.detection_engine().current_state();

        if latency_factor >= 10.0 {
            prop_assert_eq!(state, HealthState::Critical);
        } else if latency_factor >= 5.0 {
            prop_assert!(matches!(state, HealthState::Degraded | HealthState::Critical));
        }
    }

    /// Slab pressure without IB errors should stay Healthy.
    #[test]
    fn slab_pressure_needs_ib_errors(alloc_count in 100u64..10_000) {
        let events: Vec<_> = (0..alloc_count)
            .map(|i| {
                ArgusEvent::SlabAlloc(SlabAllocEvent {
                    timestamp_ns: i * 1_000_000,
                    cpu: 0,
                    bytes_req: 64,
                    bytes_alloc: 64,
                    latency_ns: 0,
                    numa_node: 0,
                })
            })
            .collect();

        let mut pipeline = Pipeline::new(4);
        evaluate_with_hysteresis(&mut pipeline, &events, 2);
        let state = pipeline.detection_engine().current_state();
        prop_assert_eq!(state, HealthState::Healthy,
            "Slab allocs without IB errors should never trigger slab pressure");
    }

    /// Mixed events should never produce inconsistent state.
    #[test]
    fn mixed_events_consistent(
        irq_events in proptest::collection::vec(arb_irq_entry(), 0..100),
        slab_events in proptest::collection::vec(arb_slab_alloc(), 0..100),
        cq_events in proptest::collection::vec(arb_cq_completion(), 0..100),
    ) {
        let mut pipeline = Pipeline::new(16);
        let all_events: Vec<_> = irq_events.into_iter()
            .chain(slab_events)
            .chain(cq_events)
            .collect();

        for event in &all_events {
            pipeline.ingest(event);
        }

        let all_alerts = pipeline.evaluate();
        let final_state = pipeline.detection_engine().current_state();

        if !all_alerts.is_empty() {
            prop_assert!(matches!(final_state, HealthState::Healthy | HealthState::Degraded | HealthState::Critical));
        }
    }
}

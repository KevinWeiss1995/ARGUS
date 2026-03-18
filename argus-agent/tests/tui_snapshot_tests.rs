use argus_agent::tui::{render_to_string, DashboardState};
use argus_common::*;

fn healthy_state() -> DashboardState {
    DashboardState {
        health: HealthState::Healthy,
        source_name: "test".to_string(),
        event_count: 500,
        uptime_secs: 12.3,
        metrics: AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![130, 120, 125, 125],
                total_count: 500,
            },
            slab_metrics: SlabMetrics {
                alloc_count: 200,
                total_latency_ns: 100_000,
                max_latency_ns: 800,
                ..Default::default()
            },
            rdma_metrics: RdmaMetrics {
                completion_count: 150,
                total_latency_ns: 300_000,
                max_latency_ns: 3000,
                ..Default::default()
            },
            ..Default::default()
        },
        ib_error_history: vec![0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        slab_rate_history: vec![200.0, 198.0, 205.0, 200.0, 195.0, 210.0, 200.0, 198.0],
        irq_rate_history: vec![100.0, 120.0, 110.0, 115.0, 105.0, 125.0, 130.0, 120.0],
        rdma_throughput_history: vec![
            1024.0, 1100.0, 1050.0, 1080.0, 1024.0, 1150.0, 1090.0, 1060.0,
        ],
        cq_latency_history: vec![2.0, 2.1, 1.9, 2.0, 2.2, 2.0, 1.8, 2.1],
        rdma_has_byte_counters: true,
        recent_alerts: Vec::new(),
    }
}

fn degraded_state() -> DashboardState {
    DashboardState {
        health: HealthState::Degraded,
        source_name: "scenario".to_string(),
        event_count: 1000,
        uptime_secs: 25.7,
        metrics: AggregatedMetrics {
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![750, 100, 80, 70],
                total_count: 1000,
            },
            slab_metrics: SlabMetrics {
                alloc_count: 400,
                total_latency_ns: 200_000,
                max_latency_ns: 1200,
                ..Default::default()
            },
            rdma_metrics: RdmaMetrics {
                completion_count: 300,
                total_latency_ns: 3_600_000,
                max_latency_ns: 16000,
                error_count: 3,
                ..Default::default()
            },
            ..Default::default()
        },
        ib_error_history: vec![0.0, 0.0, 0.0, 2.0, 5.0, 8.0, 4.0, 3.0],
        slab_rate_history: vec![400.0, 410.0, 400.0, 600.0, 800.0, 900.0, 850.0, 800.0],
        irq_rate_history: vec![250.0, 260.0, 280.0, 500.0, 700.0, 750.0, 740.0, 720.0],
        rdma_throughput_history: vec![512.0, 480.0, 520.0, 300.0, 150.0, 80.0, 100.0, 90.0],
        cq_latency_history: vec![2.0, 2.5, 3.0, 50.0, 120.0, 80.0, 60.0, 45.0],
        rdma_has_byte_counters: false,
        recent_alerts: vec![Alert {
            timestamp_ns: 20_000_000_000,
            kind: AlertKind::InterruptAffinitySkew {
                dominant_cpu: 0,
                dominant_pct: 75.0,
            },
            severity: HealthState::Degraded,
            message: "Interrupt affinity skew: CPU 0 handling 75.0% of interrupts".to_string(),
        }],
    }
}

#[test]
fn snapshot_healthy_dashboard() {
    let state = healthy_state();
    let rendered = render_to_string(&state, 80, 30);
    insta::assert_snapshot!("healthy_dashboard", rendered);
}

#[test]
fn snapshot_degraded_dashboard() {
    let state = degraded_state();
    let rendered = render_to_string(&state, 80, 30);
    insta::assert_snapshot!("degraded_dashboard", rendered);
}

#[test]
fn snapshot_empty_dashboard() {
    let state = DashboardState::default();
    let rendered = render_to_string(&state, 80, 30);
    insta::assert_snapshot!("empty_dashboard", rendered);
}

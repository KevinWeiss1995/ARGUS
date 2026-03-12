use argus_common::{AggregatedMetrics, HealthState};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};

/// Prometheus metrics exporter for ARGUS telemetry.
pub struct PrometheusExporter {
    registry: Registry,
    metrics: ArgusPrometheusMetrics,
}

#[derive(Clone)]
#[allow(dead_code)] // Fields are held to keep prometheus registry handles alive for scraping
struct ArgusPrometheusMetrics {
    health_state: Gauge,
    event_count: Counter,
    alert_count: Family<Vec<(String, String)>, Counter>,
    irq_total: Family<Vec<(String, String)>, Counter>,
    slab_alloc_count: Counter,
    slab_avg_latency_ns: Gauge,
    slab_max_latency_ns: Gauge,
    cq_completion_count: Counter,
    cq_avg_latency_ns: Gauge,
    cq_max_latency_ns: Gauge,
    cq_error_count: Counter,
}

impl PrometheusExporter {
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let health_state = Gauge::default();
        registry.register(
            "argus_health_state",
            "Node health state (0=healthy, 1=degraded, 2=critical)",
            health_state.clone(),
        );

        let event_count = Counter::default();
        registry.register(
            "argus_events_total",
            "Total events processed",
            event_count.clone(),
        );

        let alert_count = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_alerts_total",
            "Total alerts by kind and severity",
            alert_count.clone(),
        );

        let irq_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_irq_total",
            "Total interrupts by CPU",
            irq_total.clone(),
        );

        let slab_alloc_count = Counter::default();
        registry.register(
            "argus_slab_alloc_total",
            "Total slab allocations",
            slab_alloc_count.clone(),
        );

        let slab_avg_latency_ns = Gauge::default();
        registry.register(
            "argus_slab_avg_latency_ns",
            "Average slab allocation latency in nanoseconds",
            slab_avg_latency_ns.clone(),
        );

        let slab_max_latency_ns = Gauge::default();
        registry.register(
            "argus_slab_max_latency_ns",
            "Maximum slab allocation latency in nanoseconds",
            slab_max_latency_ns.clone(),
        );

        let cq_completion_count = Counter::default();
        registry.register(
            "argus_cq_completions_total",
            "Total CQ completions",
            cq_completion_count.clone(),
        );

        let cq_avg_latency_ns = Gauge::default();
        registry.register(
            "argus_cq_avg_latency_ns",
            "Average CQ completion latency in nanoseconds",
            cq_avg_latency_ns.clone(),
        );

        let cq_max_latency_ns = Gauge::default();
        registry.register(
            "argus_cq_max_latency_ns",
            "Maximum CQ completion latency in nanoseconds",
            cq_max_latency_ns.clone(),
        );

        let cq_error_count = Counter::default();
        registry.register(
            "argus_cq_errors_total",
            "Total CQ completion errors",
            cq_error_count.clone(),
        );

        let metrics = ArgusPrometheusMetrics {
            health_state,
            event_count,
            alert_count,
            irq_total,
            slab_alloc_count,
            slab_avg_latency_ns,
            slab_max_latency_ns,
            cq_completion_count,
            cq_avg_latency_ns,
            cq_max_latency_ns,
            cq_error_count,
        };

        Self { registry, metrics }
    }

    /// Update all gauges from aggregated metrics.
    pub fn update(&self, metrics: &AggregatedMetrics, health: HealthState, _event_count: u64) {
        let state_val: i64 = match health {
            HealthState::Healthy => 0,
            HealthState::Degraded => 1,
            HealthState::Critical => 2,
        };
        self.metrics.health_state.set(state_val);

        self.metrics
            .slab_avg_latency_ns
            .set(metrics.slab_metrics.avg_latency_ns() as i64);
        self.metrics
            .slab_max_latency_ns
            .set(metrics.slab_metrics.max_latency_ns as i64);

        self.metrics
            .cq_avg_latency_ns
            .set(metrics.rdma_metrics.avg_latency_ns() as i64);
        self.metrics
            .cq_max_latency_ns
            .set(metrics.rdma_metrics.max_latency_ns as i64);
    }

    /// Record an alert in Prometheus counters.
    pub fn record_alert(&self, kind: &str, severity: &str) {
        self.metrics
            .alert_count
            .get_or_create(&vec![
                ("kind".to_string(), kind.to_string()),
                ("severity".to_string(), severity.to_string()),
            ])
            .inc();
    }

    /// Encode all metrics as Prometheus text format.
    pub fn encode(&self) -> String {
        let mut buf = String::new();
        encode(&mut buf, &self.registry).expect("encoding should not fail");
        buf
    }
}

impl Default for PrometheusExporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared state for the metrics HTTP server.
pub type SharedExporter = Arc<Mutex<PrometheusExporter>>;

/// Start an HTTP server on `addr` that serves `/metrics`.
pub async fn serve_metrics(
    exporter: SharedExporter,
    addr: std::net::SocketAddr,
) -> anyhow::Result<()> {
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "Prometheus metrics server listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let exporter = exporter.clone();

        tokio::spawn(async move {
            let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
                let exporter = exporter.clone();
                async move {
                    let body = {
                        let exp = exporter.lock().unwrap();
                        exp.encode()
                    };
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .header("content-type", "text/plain; version=0.0.4")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                }
            });

            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            )
            .serve_connection(io, service)
            .await
            {
                tracing::warn!("metrics server connection error: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::*;

    #[test]
    fn prometheus_encoding_works() {
        let exporter = PrometheusExporter::new();

        let metrics = AggregatedMetrics {
            slab_metrics: SlabMetrics {
                alloc_count: 100,
                total_latency_ns: 50_000,
                max_latency_ns: 800,
                ..Default::default()
            },
            rdma_metrics: RdmaMetrics {
                completion_count: 50,
                total_latency_ns: 100_000,
                max_latency_ns: 3000,
                ..Default::default()
            },
            ..Default::default()
        };

        exporter.update(&metrics, HealthState::Healthy, 150);
        exporter.record_alert("interrupt_affinity_skew", "DEGRADED");

        let output = exporter.encode();
        assert!(output.contains("argus_health_state"));
        assert!(output.contains("argus_slab_avg_latency_ns"));
        assert!(output.contains("argus_alerts_total"));
    }

    #[test]
    fn health_state_encoding() {
        let exporter = PrometheusExporter::new();
        let metrics = AggregatedMetrics::default();

        exporter.update(&metrics, HealthState::Critical, 0);
        let output = exporter.encode();
        assert!(output.contains("argus_health_state 2"));
    }
}

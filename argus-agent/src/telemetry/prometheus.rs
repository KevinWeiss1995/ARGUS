use argus_common::{AggregatedMetrics, HealthState};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};

pub struct PrometheusExporter {
    registry: Registry,
    metrics: ArgusPrometheusMetrics,
    prev_health: HealthState,
}

#[derive(Clone)]
struct ArgusPrometheusMetrics {
    health_state: Gauge,
    health_score: Gauge,
    event_count: Counter,
    alert_count: Family<Vec<(String, String)>, Counter>,
    state_transitions: Family<Vec<(String, String)>, Counter>,
    irq_total: Family<Vec<(String, String)>, Counter>,
    irq_skew_pct: Gauge,
    irq_dominant_cpu: Gauge,
    irq_total_rate: Gauge,
    slab_alloc_count: Counter,
    slab_avg_latency_ns: Gauge,
    slab_max_latency_ns: Gauge,
    cq_completion_count: Counter,
    cq_avg_latency_ns: Gauge,
    cq_max_latency_ns: Gauge,
    cq_stall_count: Counter,
    cq_p99_latency_ns: Gauge,
    ib_error_delta_total: Gauge,
    ib_symbol_errors: Family<Vec<(String, String)>, Gauge>,
    ib_link_downed: Family<Vec<(String, String)>, Gauge>,
    ib_link_error_recovery: Family<Vec<(String, String)>, Gauge>,
    ib_port_rcv_errors: Family<Vec<(String, String)>, Gauge>,
    ib_port_xmit_discards: Family<Vec<(String, String)>, Gauge>,
    ib_port_xmit_wait: Family<Vec<(String, String)>, Gauge>,
    ib_throughput_rcv_bytes: Family<Vec<(String, String)>, Gauge>,
    ib_throughput_xmit_bytes: Family<Vec<(String, String)>, Gauge>,
    ib_throughput_rcv_pkts: Family<Vec<(String, String)>, Gauge>,
    ib_throughput_xmit_pkts: Family<Vec<(String, String)>, Gauge>,
    napi_utilization_pct: Gauge,
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

        let health_score = Gauge::default();
        registry.register(
            "argus_health_score_millis",
            "Composite health score in milliunits (0=healthy, 1000=worst)",
            health_score.clone(),
        );

        let event_count = Counter::default();
        registry.register(
            "argus_events",
            "Total events processed",
            event_count.clone(),
        );

        let alert_count = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_alerts",
            "Total alerts by kind and severity",
            alert_count.clone(),
        );

        let state_transitions = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_state_transitions",
            "Health state transitions",
            state_transitions.clone(),
        );

        let irq_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "argus_irq",
            "Total interrupts by CPU",
            irq_total.clone(),
        );

        let irq_skew_pct = Gauge::default();
        registry.register(
            "argus_irq_imbalance_pct",
            "Normalized IRQ imbalance (0=balanced, 100=all on one CPU)",
            irq_skew_pct.clone(),
        );

        let irq_dominant_cpu = Gauge::default();
        registry.register(
            "argus_irq_dominant_cpu",
            "CPU ID handling the most IRQs in the current window",
            irq_dominant_cpu.clone(),
        );

        let irq_total_rate = Gauge::default();
        registry.register(
            "argus_irq_total_rate",
            "Total IRQ count across all CPUs in the current window",
            irq_total_rate.clone(),
        );

        let slab_alloc_count = Counter::default();
        registry.register(
            "argus_slab_alloc",
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
            "argus_cq_completions",
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

        let cq_stall_count = Counter::default();
        registry.register(
            "argus_cq_stalls",
            "CQ completions exceeding stall threshold (>50us)",
            cq_stall_count.clone(),
        );

        let cq_p99_latency_ns = Gauge::default();
        registry.register(
            "argus_cq_p99_latency_ns",
            "Estimated p99 CQ completion latency in nanoseconds",
            cq_p99_latency_ns.clone(),
        );

        let ib_error_delta_total = Gauge::default();
        registry.register(
            "argus_ib_error_delta_total",
            "Total IB hardware counter error deltas in current window",
            ib_error_delta_total.clone(),
        );

        let ib_symbol_errors = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_symbol_errors_delta",
            "IB symbol error count delta per window",
            ib_symbol_errors.clone(),
        );

        let ib_link_downed = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_link_downed_delta",
            "IB link downed event delta per window",
            ib_link_downed.clone(),
        );

        let ib_link_error_recovery = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_link_error_recovery_delta",
            "IB link error recovery delta per window (early cable fault warning)",
            ib_link_error_recovery.clone(),
        );

        let ib_port_rcv_errors = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_port_rcv_errors_delta",
            "IB port receive errors delta per window",
            ib_port_rcv_errors.clone(),
        );

        let ib_port_xmit_discards = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_port_xmit_discards_delta",
            "IB port transmit discards delta per window",
            ib_port_xmit_discards.clone(),
        );

        let ib_port_xmit_wait = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_port_xmit_wait_delta",
            "IB port transmit wait delta per window (congestion indicator)",
            ib_port_xmit_wait.clone(),
        );

        let ib_throughput_rcv_bytes = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_throughput_rcv_bytes",
            "IB receive throughput in bytes per window",
            ib_throughput_rcv_bytes.clone(),
        );

        let ib_throughput_xmit_bytes = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_throughput_xmit_bytes",
            "IB transmit throughput in bytes per window",
            ib_throughput_xmit_bytes.clone(),
        );

        let ib_throughput_rcv_pkts = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_throughput_rcv_pkts",
            "IB receive throughput in packets per window",
            ib_throughput_rcv_pkts.clone(),
        );

        let ib_throughput_xmit_pkts = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "argus_ib_throughput_xmit_pkts",
            "IB transmit throughput in packets per window",
            ib_throughput_xmit_pkts.clone(),
        );

        let napi_utilization_pct = Gauge::default();
        registry.register(
            "argus_napi_utilization_pct",
            "NAPI budget utilization percentage (0-100 integer)",
            napi_utilization_pct.clone(),
        );

        let metrics = ArgusPrometheusMetrics {
            health_state,
            health_score,
            event_count,
            alert_count,
            state_transitions,
            irq_total,
            irq_skew_pct,
            irq_dominant_cpu,
            irq_total_rate,
            slab_alloc_count,
            slab_avg_latency_ns,
            slab_max_latency_ns,
            cq_completion_count,
            cq_avg_latency_ns,
            cq_max_latency_ns,
            cq_stall_count,
            cq_p99_latency_ns,
            ib_error_delta_total,
            ib_symbol_errors,
            ib_link_downed,
            ib_link_error_recovery,
            ib_port_rcv_errors,
            ib_port_xmit_discards,
            ib_port_xmit_wait,
            ib_throughput_rcv_bytes,
            ib_throughput_xmit_bytes,
            ib_throughput_rcv_pkts,
            ib_throughput_xmit_pkts,
            napi_utilization_pct,
        };

        Self {
            registry,
            metrics,
            prev_health: HealthState::Healthy,
        }
    }

    /// Update all gauges and counters from aggregated metrics.
    pub fn update(&mut self, metrics: &AggregatedMetrics, health: HealthState, event_count: u64) {
        let state_val: i64 = match health {
            HealthState::Healthy => 0,
            HealthState::Degraded => 1,
            HealthState::Critical => 2,
        };
        self.metrics.health_state.set(state_val);
        self.metrics
            .health_score
            .set((metrics.composite_health_score * 1000.0) as i64);

        // State transitions
        if health != self.prev_health {
            self.metrics
                .state_transitions
                .get_or_create(&vec![
                    ("from".to_string(), self.prev_health.to_string()),
                    ("to".to_string(), health.to_string()),
                ])
                .inc();
            self.prev_health = health;
        }

        // Events
        if event_count > 0 {
            self.metrics.event_count.inc_by(event_count);
        }

        // Slab
        if metrics.slab_metrics.alloc_count > 0 {
            self.metrics
                .slab_alloc_count
                .inc_by(metrics.slab_metrics.alloc_count);
        }
        self.metrics
            .slab_avg_latency_ns
            .set(metrics.slab_metrics.avg_latency_ns() as i64);
        self.metrics
            .slab_max_latency_ns
            .set(metrics.slab_metrics.max_latency_ns as i64);

        // CQ jitter (from cq_jitter, not rdma_metrics)
        if metrics.cq_jitter.completion_count > 0 {
            self.metrics
                .cq_completion_count
                .inc_by(metrics.cq_jitter.completion_count);
        }
        self.metrics
            .cq_avg_latency_ns
            .set(metrics.cq_jitter.avg_latency_ns() as i64);
        self.metrics
            .cq_max_latency_ns
            .set(metrics.cq_jitter.max_latency_ns as i64);
        if metrics.cq_jitter.stall_count > 0 {
            self.metrics
                .cq_stall_count
                .inc_by(metrics.cq_jitter.stall_count);
        }
        self.metrics
            .cq_p99_latency_ns
            .set(metrics.cq_jitter.estimated_p99_ns() as i64);

        // IRQ per-CPU (detail) + aggregate skew metrics
        let dist = &metrics.interrupt_distribution;
        for (i, &count) in dist.per_cpu_counts.iter().enumerate() {
            let counter = self
                .metrics
                .irq_total
                .get_or_create(&vec![("cpu".to_string(), i.to_string())]);
            if count > 0 {
                counter.inc_by(count);
            }
        }
        let n = dist.per_cpu_counts.len() as f64;
        let imbalance = if n > 1.0 {
            let ideal_pct = 100.0 / n;
            let max_pct = dist.dominant_cpu_pct();
            ((max_pct - ideal_pct) / (100.0 - ideal_pct) * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };
        self.metrics.irq_skew_pct.set(imbalance as i64);
        // #region agent log
        eprintln!("[debug-58f965] irq imbalance_pct={:.1} n_cpus={} total={} per_cpu_len={}", imbalance, n, dist.total_count, dist.per_cpu_counts.len());
        // #endregion
        let dominant_cpu = dist
            .per_cpu_counts
            .iter()
            .enumerate()
            .max_by_key(|(_, &c)| c)
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.metrics.irq_dominant_cpu.set(dominant_cpu as i64);
        self.metrics
            .irq_total_rate
            .set(dist.total_count as i64);

        // NAPI utilization
        let napi_util = if metrics.network_metrics.napi_total_budget > 0 {
            metrics.network_metrics.napi_total_work as f64
                / metrics.network_metrics.napi_total_budget as f64
                * 100.0
        } else {
            0.0
        };
        self.metrics.napi_utilization_pct.set(napi_util as i64);

        // IB counters (aggregate — per-device breakdown via update_ib_counters)
        self.metrics
            .ib_error_delta_total
            .set(metrics.ib_counter_deltas.total_error_delta() as i64);
    }

    /// Update per-device/port IB counter gauges.
    /// Call once per device per window with the device name and port.
    pub fn update_ib_counters(
        &self,
        device: &str,
        port: &str,
        deltas: &argus_common::IbCounterDeltas,
    ) {
        let labels = vec![
            ("device".to_string(), device.to_string()),
            ("port".to_string(), port.to_string()),
        ];

        self.metrics
            .ib_symbol_errors
            .get_or_create(&labels)
            .set(deltas.symbol_error_delta as i64);
        self.metrics
            .ib_link_downed
            .get_or_create(&labels)
            .set(deltas.link_downed_delta as i64);
        self.metrics
            .ib_link_error_recovery
            .get_or_create(&labels)
            .set(deltas.link_error_recovery_delta as i64);
        self.metrics
            .ib_port_rcv_errors
            .get_or_create(&labels)
            .set(deltas.port_rcv_errors_delta as i64);
        self.metrics
            .ib_port_xmit_discards
            .get_or_create(&labels)
            .set(deltas.port_xmit_discards_delta as i64);
        self.metrics
            .ib_port_xmit_wait
            .get_or_create(&labels)
            .set(deltas.port_xmit_wait_delta as i64);
        self.metrics
            .ib_throughput_rcv_bytes
            .get_or_create(&labels)
            .set((deltas.port_rcv_data_delta * 4) as i64);
        self.metrics
            .ib_throughput_xmit_bytes
            .get_or_create(&labels)
            .set((deltas.port_xmit_data_delta * 4) as i64);
        self.metrics
            .ib_throughput_rcv_pkts
            .get_or_create(&labels)
            .set(deltas.hw_rcv_pkts_delta as i64);
        self.metrics
            .ib_throughput_xmit_pkts
            .get_or_create(&labels)
            .set(deltas.hw_xmit_pkts_delta as i64);
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
    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut buf = String::new();
        encode(&mut buf, &self.registry)?;
        Ok(buf)
    }
}

impl Default for PrometheusExporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared state for the metrics HTTP server.
pub type SharedExporter = Arc<Mutex<PrometheusExporter>>;

/// Shared health state for the /health endpoint.
pub type SharedHealthState = Arc<Mutex<HealthSnapshot>>;

#[derive(Clone)]
pub struct HealthSnapshot {
    pub state: HealthState,
    pub uptime_secs: f64,
    pub events_processed: u64,
    pub last_window_ts: u64,
}

impl Default for HealthSnapshot {
    fn default() -> Self {
        Self {
            state: HealthState::Healthy,
            uptime_secs: 0.0,
            events_processed: 0,
            last_window_ts: 0,
        }
    }
}

/// TLS configuration for the metrics endpoint.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
}

/// Start an HTTP(S) server on `addr` that serves `/metrics` and `/health`.
///
/// When `tls` is `Some`, the server uses TLS (HTTPS). When `auth_token` is
/// `Some`, every request must include a matching `Authorization: Bearer <token>`
/// header or receive a 401.
pub async fn serve_metrics(
    exporter: SharedExporter,
    health: SharedHealthState,
    addr: std::net::SocketAddr,
    tls: Option<TlsConfig>,
    auth_token: Option<String>,
) -> anyhow::Result<()> {
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let tls_acceptor = if let Some(ref tls_cfg) = tls {
        Some(build_tls_acceptor(tls_cfg)?)
    } else {
        None
    };

    let listener = TcpListener::bind(addr).await?;
    let scheme = if tls.is_some() { "https" } else { "http" };
    tracing::info!(%addr, %scheme, "metrics/health server listening");

    let auth_token: Option<Arc<str>> = auth_token.map(|t| Arc::from(t.as_str()));

    loop {
        let (stream, _) = listener.accept().await?;
        let exporter = exporter.clone();
        let health = health.clone();
        let auth = auth_token.clone();

        if let Some(ref acceptor) = tls_acceptor {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!("TLS handshake failed: {e}");
                        return;
                    }
                };
                let io = TokioIo::new(tls_stream);
                serve_connection(io, exporter, health, auth).await;
            });
        } else {
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                serve_connection(io, exporter, health, auth).await;
            });
        }
    }
}

async fn serve_connection<I>(
    io: I,
    exporter: SharedExporter,
    health: SharedHealthState,
    auth_token: Option<Arc<str>>,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};

    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let exporter = exporter.clone();
        let health = health.clone();
        let auth = auth_token.clone();
        async move {
            if let Some(ref expected) = auth {
                let authorized = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .map_or(false, |t| t == expected.as_ref());
                if !authorized {
                    return Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .body(Full::new(Bytes::from("unauthorized\n")))
                            .unwrap_or_else(|_| {
                                Response::new(Full::new(Bytes::from("unauthorized\n")))
                            }),
                    );
                }
            }

            match req.uri().path() {
                "/metrics" => {
                    let body = match exporter.lock() {
                        Ok(exp) => exp.encode().unwrap_or_default(),
                        Err(_) => String::from("# error: lock poisoned\n"),
                    };
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/plain; version=0.0.4")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap_or_else(|_| {
                                Response::new(Full::new(Bytes::from("internal error")))
                            }),
                    )
                }
                "/health" => {
                    let snap = health.lock().map(|h| h.clone()).unwrap_or_default();
                    let body = format!(
                        r#"{{"state":"{}","uptime_secs":{:.1},"events_processed":{},"last_window_ts":{}}}"#,
                        snap.state,
                        snap.uptime_secs,
                        snap.events_processed,
                        snap.last_window_ts,
                    );
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(body)))
                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
                }
                _ => Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from("not found")))
                    .unwrap_or_else(|_| {
                        Response::new(Full::new(Bytes::from("not found")))
                    })),
            }
        }
    });

    if let Err(e) =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(io, service)
            .await
    {
        tracing::warn!("metrics server connection error: {e}");
    }
}

fn build_tls_acceptor(cfg: &TlsConfig) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;
    use tokio_rustls::rustls::ServerConfig;

    let cert_file = std::fs::File::open(&cfg.cert_path)
        .map_err(|e| anyhow::anyhow!("failed to open TLS cert {}: {e}", cfg.cert_path.display()))?;
    let key_file = std::fs::File::open(&cfg.key_path)
        .map_err(|e| anyhow::anyhow!("failed to open TLS key {}: {e}", cfg.key_path.display()))?;

    let cert_chain: Vec<_> = certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse TLS cert chain: {e}"))?;

    let key = private_key(&mut BufReader::new(key_file))
        .map_err(|e| anyhow::anyhow!("failed to parse TLS private key: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", cfg.key_path.display()))?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| anyhow::anyhow!("TLS server config error: {e}"))?;

    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
        server_config,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::*;

    #[test]
    fn prometheus_encoding_works() {
        let mut exporter = PrometheusExporter::new();

        let metrics = AggregatedMetrics {
            slab_metrics: SlabMetrics {
                alloc_count: 100,
                total_latency_ns: 50_000,
                max_latency_ns: 800,
                ..Default::default()
            },
            cq_jitter: CqJitterMetrics {
                completion_count: 50,
                total_latency_ns: 100_000,
                max_latency_ns: 3000,
                stall_count: 2,
            },
            ..Default::default()
        };

        exporter.update(&metrics, HealthState::Healthy, 150);
        exporter.record_alert("interrupt_affinity_skew", "DEGRADED");

        let output = exporter.encode().expect("encoding should not fail");
        assert!(output.contains("argus_health_state"));
        assert!(output.contains("argus_slab_avg_latency_ns"));
        assert!(output.contains("argus_alerts_total"));
        assert!(output.contains("argus_cq_stalls_total"));
        assert!(output.contains("argus_health_score"));
    }

    #[test]
    fn health_state_encoding() {
        let mut exporter = PrometheusExporter::new();
        let metrics = AggregatedMetrics::default();

        exporter.update(&metrics, HealthState::Critical, 0);
        let output = exporter.encode().expect("encoding should not fail");
        assert!(output.contains("argus_health_state 2"));
    }

    #[test]
    fn state_transitions_counted() {
        let mut exporter = PrometheusExporter::new();
        let metrics = AggregatedMetrics::default();

        exporter.update(&metrics, HealthState::Degraded, 0);
        exporter.update(&metrics, HealthState::Critical, 0);

        let output = exporter.encode().expect("encoding should not fail");
        assert!(output.contains("argus_state_transitions_total"));
    }

    #[test]
    fn ib_counter_labels() {
        let exporter = PrometheusExporter::new();
        let deltas = IbCounterDeltas {
            symbol_error_delta: 5,
            link_downed_delta: 1,
            ..Default::default()
        };

        exporter.update_ib_counters("mlx5_0", "1", &deltas);
        let output = exporter.encode().expect("encoding should not fail");
        assert!(output.contains("argus_ib_symbol_errors_delta"));
        assert!(output.contains("mlx5_0"));
    }

    #[test]
    fn counters_increment_correctly() {
        let mut exporter = PrometheusExporter::new();

        let metrics = AggregatedMetrics {
            slab_metrics: SlabMetrics {
                alloc_count: 100,
                ..Default::default()
            },
            interrupt_distribution: InterruptDistribution {
                per_cpu_counts: vec![60, 40],
                total_count: 100,
            },
            cq_jitter: CqJitterMetrics {
                completion_count: 25,
                stall_count: 3,
                ..Default::default()
            },
            ..Default::default()
        };

        exporter.update(&metrics, HealthState::Healthy, 200);

        let output = exporter.encode().expect("encoding should not fail");
        assert!(output.contains("argus_events_total"));
        assert!(output.contains("argus_slab_alloc_total"));
        assert!(output.contains("argus_irq_total"));
        assert!(output.contains("argus_cq_completions_total"));
    }
}

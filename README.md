# ARGUS

**Adaptive RDMA Guard & Utilization Sentinel**

*Note: ARGUS is under active development. We'd love your help building, testing, and improving it. Email: kjweiss1995@gmail.com if this project seems of interest to you.* 

ARGUS is a lightweight, node-local telemetry agent that uses eBPF to monitor kernel behavior related to RDMA networking, interrupt handling, and memory allocation. It's designed to catch the early warning signs of InfiniBand link degradation and system imbalance before your applications notice.

We built this to fill a gap we saw in other fabric monitors. In most cases, by the time a job hangs the link has usually been degraded for awhile. At the kernel level, the warning signs are there, but with nothing listening degradation goes unnoticed until jobs are affected. The ARGUS project intends to fix that.

## What it does

ARGUS attaches eBPF tracepoints to the running kernel and reads InfiniBand hardware counters from sysfs. It feeds everything through a detection engine that combines threshold-based rules with predictive trend analysis (EWMA, z-scores, consecutive-window hysteresis) to classify node health as **Healthy**, **Degraded**, or **Critical**.

**Kernel probes** (via eBPF):
- `kmem/kmem_cache_alloc` and `kmem_cache_free` — slab allocator pressure
- `irq/irq_handler_entry` — interrupt affinity distribution across CPUs
- `napi/napi_poll` — NIC polling saturation

**Hardware counters** (via sysfs):
- Symbol errors, link downed, port receive errors, transmit discards
- Receive/transmit data throughput deltas
- Remote physical errors, link integrity errors, buffer overruns

**Detection rules** (8 total — 4 reactive, 4 predictive):
- Interrupt affinity skew (single CPU handling >70% of IRQs)
- RDMA latency spikes (mock/replay modes)
- IB link degradation (hardware counter deltas)
- Slab pressure correlated with IB errors
- Rising error trend (monotonically increasing IB errors over N windows)
- Latency drift (z-score deviation from EWMA baseline)
- Throughput drop (>50% below rolling average)
- NAPI saturation (work/budget approaching 100%)

State transitions use hysteresis (consecutive-window confirmation) to avoid flapping on noisy metrics.

## Quick start

```bash
# Clone and build
git clone https://github.com/KevinWeiss1995/ARGUS.git
cd ARGUS
cargo build --release

# Run with mock data and the TUI dashboard
cargo run --release -- --mode mock --profile skew --tui

# Try different failure profiles
cargo run --release -- --mode mock --profile pressure --tui
cargo run --release -- --mode mock --profile spike --tui
```

You don't need root, eBPF, or InfiniBand hardware to try it out. Mock mode generates synthetic events that exercise the full pipeline.

## Deployment

ARGUS supports two deployment modes. The agent binary is identical in both -- what changes is who runs Prometheus and Grafana.

| | Standalone | Production Integration |
|---|---|---|
| Who runs Prometheus/Grafana | ARGUS (bundled Docker stack) | Your existing infrastructure |
| TLS on metrics endpoint | Optional | Recommended |
| Bearer token auth | Optional | Recommended |
| Best for | Single-node, demos, dev | Multi-node clusters, HPC |
| Config format | Env file or TOML | TOML (recommended) |

### Prerequisites

- Linux with eBPF support (kernel 5.4+)
- Root or `CAP_BPF` permissions
- Rust toolchain (the install script will install it if missing)
- Docker + Docker Compose (only for the standalone observability stack)

---

### Option A: Standalone mode (ARGUS manages its own Grafana + Prometheus)

Use this when you want a complete, self-contained setup. ARGUS deploys its own Prometheus + Grafana + Alertmanager stack via Docker Compose and pre-provisions dashboards automatically.

**Step 1: Clone and install the agent**

```bash
git clone https://github.com/KevinWeiss1995/ARGUS.git
cd ARGUS
sudo ./scripts/install.sh
```

The install script builds the agent and eBPF probes, then installs:
- `/usr/local/bin/argusd` -- the agent binary
- `/usr/local/lib/argus/argus-ebpf` -- the eBPF object
- `/etc/argus/argusd.conf` -- environment-based config
- `/etc/argus/argusd.toml` -- TOML config (example, not active by default)
- `/etc/systemd/system/argusd.service` -- systemd unit

If you already have pre-built binaries, use `sudo ./scripts/install.sh --no-build` to skip compilation.

**Important**: On upgrade (re-running `install.sh`), existing config files in `/etc/argus/` are **never overwritten**. If you need the latest defaults, manually copy them:
```bash
sudo cp deploy/argusd.conf /etc/argus/argusd.conf
sudo cp deploy/examples/standalone.toml /etc/argus/argusd.toml
```

**Step 2: Start the agent**

```bash
sudo systemctl enable argusd    # start on boot
sudo systemctl start argusd     # start now
```

**Step 3: Verify the agent is running**

```bash
sudo systemctl status argusd
journalctl -u argusd --no-pager -n 20

# Prometheus metrics endpoint (should return metric text)
curl localhost:9100/metrics | head -5

# Health check (should return JSON)
curl localhost:9100/health
```

**Step 4: Start the observability stack**

Requires Docker and Docker Compose on the same host (or a host that can reach the agent's port 9100).

```bash
cd ARGUS
deploy/observability/scripts/start-observability.sh
```

This starts:
- **Prometheus** on port `9091` -- scrapes the agent at `host.docker.internal:9100`
- **Grafana** on port `3000` -- pre-provisioned with ARGUS dashboards
- **Alertmanager** on port `9093` -- alert routing (webhook receiver not configured by default)

**Step 5: Open Grafana**

Open `http://<host-ip>:3000` in your browser. Login: `admin` / `admin`.

Three dashboards are pre-loaded under the ARGUS folder:
- **Fleet Overview** -- health state summary across all monitored nodes
- **Node Detail** -- kernel probe metrics, CQ jitter, IB counters for a single node
- **Link Drill-Down** -- per-device, per-port InfiniBand error and throughput analysis

If the node has no InfiniBand hardware, the IB and CQ sections will show "No IB hardware detected" / "No CQ data" -- this is expected. The kernel probe panels (IRQ, slab, NAPI) will be active on any Linux node.

---

### Option B: Production integration (plug into your existing Prometheus + Grafana)

Use this when you already have a Prometheus/Grafana stack and want ARGUS to feed metrics into it. The agent exposes a standard `/metrics` endpoint that any Prometheus can scrape. No Docker or ARGUS-managed stack required.

**Step 1: Install the agent**

```bash
git clone https://github.com/KevinWeiss1995/ARGUS.git
cd ARGUS
sudo ./scripts/install.sh
```

**Step 2: Configure with the production TOML template**

```bash
# Copy the production config template
sudo cp deploy/examples/production.toml /etc/argus/argusd.toml

# Enable the TOML config file in the systemd env file
sudo sed -i 's|# ARGUS_CONFIG=.*|ARGUS_CONFIG=/etc/argus/argusd.toml|' /etc/argus/argusd.conf

# Verify it took effect
grep ARGUS_CONFIG /etc/argus/argusd.conf
# Should print:  ARGUS_CONFIG=/etc/argus/argusd.toml
```

**Step 3: Set up TLS and bearer token auth**

This secures the metrics endpoint so only your Prometheus can scrape it. Skip this step if you're on a trusted network.

```bash
# Create the TLS directory
sudo mkdir -p /etc/argus/tls

# Generate a self-signed certificate (for testing; use real certs in production)
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /etc/argus/tls/server.key -out /etc/argus/tls/server.crt \
  -days 365 -nodes -subj "/CN=argusd"

# Generate a shared bearer token
sudo sh -c 'openssl rand -hex 32 > /etc/argus/token'
sudo chmod 600 /etc/argus/token

# Note the token -- you'll need it for Prometheus config
sudo cat /etc/argus/token
```

The production TOML template already points to these paths:
```toml
[tls]
cert = "/etc/argus/tls/server.crt"
key  = "/etc/argus/tls/server.key"

[auth]
bearer_token_file = "/etc/argus/token"
```

If you skip TLS, comment out or remove the `[tls]` and `[auth]` sections from `/etc/argus/argusd.toml`.

**Step 4: Edit the TOML config**

Review `/etc/argus/argusd.toml` and remove or adjust anything that doesn't apply. In particular, remove the `webhook_url` line if you don't have a webhook endpoint:

```bash
sudo nano /etc/argus/argusd.toml
# or:
sudo sed -i '/webhook_url/d' /etc/argus/argusd.toml
```

**Step 5: Start the agent**

```bash
sudo systemctl enable argusd
sudo systemctl start argusd
```

**Step 6: Verify**

```bash
sudo systemctl status argusd
journalctl -u argusd --no-pager -n 20
```

In the logs you should see:
- `TLS enabled for metrics endpoint` (if TLS is configured)
- `bearer token auth enabled for metrics endpoint` (if auth is configured)
- `metrics/health server listening` with the bind address

Test the endpoint:

```bash
# Read the token into a variable
TOKEN=$(sudo cat /etc/argus/token)

# With TLS + auth (production):
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:9100/metrics | head -5
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:9100/health

# Without TLS (if you skipped Step 3):
curl localhost:9100/metrics | head -5
curl localhost:9100/health
```

**Step 7: Configure your Prometheus to scrape ARGUS**

Add an ARGUS scrape job to your existing `prometheus.yml`. A full example is at `deploy/examples/prometheus-scrape-argus.yml`.

With TLS + bearer auth:
```yaml
scrape_configs:
  - job_name: argus
    scrape_interval: 5s
    scheme: https
    tls_config:
      # Copy the cert from the ARGUS node, or use your own CA
      ca_file: /etc/prometheus/argus-ca.crt
      # If using self-signed certs without proper SANs:
      insecure_skip_verify: true
    bearer_token_file: /etc/prometheus/argus-token
    static_configs:
      - targets:
          - "node01:9100"
          - "node02:9100"
        labels:
          cluster: production
```

Without TLS (plain HTTP):
```yaml
scrape_configs:
  - job_name: argus
    scrape_interval: 5s
    static_configs:
      - targets:
          - "node01:9100"
          - "node02:9100"
        labels:
          cluster: production
```

Copy the bearer token to your Prometheus host:
```bash
# On the ARGUS node:
sudo cat /etc/argus/token
# Copy the output

# On the Prometheus host:
echo "THE_TOKEN" > /etc/prometheus/argus-token
chmod 600 /etc/prometheus/argus-token
```

Reload Prometheus to pick up the new scrape config:
```bash
curl -X POST http://localhost:9090/-/reload
# or: sudo systemctl reload prometheus
```

**Step 8: Import ARGUS dashboards into your Grafana**

The ARGUS dashboards are designed to be portable -- they use `${DS_PROMETHEUS}` datasource variables so they work with any Prometheus datasource name.

**Method 1 -- Grafana UI (recommended for first-time setup)**:

1. Open your Grafana instance
2. Go to **Dashboards** > **New** > **Import**
3. Click **Upload dashboard JSON file**
4. Upload each file from `deploy/observability/grafana/dashboards/`:
   - `argus-fleet-overview.json`
   - `argus-node-detail.json`
   - `argus-link-drilldown.json`
5. Grafana will prompt you to select a Prometheus datasource -- choose the one that scrapes your ARGUS nodes
6. Click **Import**

**Method 2 -- API import (for automation)**:

```bash
# From the ARGUS repo on any machine with network access to Grafana
./scripts/export-dashboards.sh --import http://your-grafana:3000 --api-key YOUR_GRAFANA_API_KEY
```

If you don't have an API key, the script falls back to `admin:admin` basic auth.

**Method 3 -- Copy JSON files for manual distribution**:

```bash
./scripts/export-dashboards.sh
# Outputs to dist/grafana-dashboards/
ls dist/grafana-dashboards/
```

**Step 9 (optional): Push-based delivery for firewalled nodes**

If your ARGUS nodes can't be scraped directly (firewalls, NAT), deploy a Prometheus agent sidecar that scrapes the local agent and `remote_write`s to your central store:

```bash
# See deploy/examples/prometheus-agent-sidecar.yml for a Docker Compose template
```

This uses Prometheus in `--agent` mode -- it scrapes `localhost:9100` and pushes to your central Prometheus, Thanos, or Mimir instance.

---

### Configuration reference

ARGUS supports two configuration layers. They can be used independently or together.

**Environment file** (`/etc/argus/argusd.conf`):

Sourced by the systemd unit. Simple key=value pairs for basic settings:
```bash
ARGUS_MODE=live
ARGUS_EBPF_PATH=/usr/local/lib/argus/argus-ebpf
ARGUS_METRICS_ADDR=0.0.0.0:9100
ARGUS_LOG_LEVEL=info
ARGUS_WINDOW_SECS=3
ARGUS_EXTRA_ARGS=

# To enable the TOML config file, uncomment:
# ARGUS_CONFIG=/etc/argus/argusd.toml
```

**TOML config file** (`/etc/argus/argusd.toml`):

Must be enabled by setting `ARGUS_CONFIG=/etc/argus/argusd.toml` in the env file. Supports all settings including TLS, auth, and detection tuning:

```toml
[agent]
mode = "live"                                    # live, mock, or replay
ebpf_path = "/usr/local/lib/argus/argus-ebpf"
log_level = "info"                               # trace, debug, info, warn, error
window_secs = 3                                  # aggregation window

[metrics]
addr = "0.0.0.0:9100"                           # bind address for /metrics and /health

[tls]                                            # omit this section to disable TLS
cert = "/etc/argus/tls/server.crt"
key  = "/etc/argus/tls/server.key"

[auth]                                           # omit this section to disable auth
bearer_token_file = "/etc/argus/token"

[detection]
irq_skew_threshold_pct = 70.0
rdma_spike_factor = 5.0
rdma_baseline_latency_ns = 2000
slab_pressure_min_allocs = 100
slab_pressure_alloc_rate_threshold = 5000

[actions]
dry_run = false
# webhook_url = "https://alerting.internal/hooks/argus"
# slurm_drain = false
# port_disable = false
```

**Precedence**: CLI flags > env file values > TOML config values > built-in defaults.

Example config files are in `deploy/examples/`:
- `standalone.toml` -- no TLS, no auth, local use
- `production.toml` -- TLS + auth + detection tuning

### Kubernetes deployment

A DaemonSet manifest with headless Service and ServiceMonitor (for Prometheus Operator) is provided at `deploy/examples/k8s-daemonset.yaml`. It runs `argusd` as a privileged DaemonSet on every node with host PID/network, mounts `/sys` and `/proc`, and exposes port 9100 for Prometheus scraping.

## Running with live eBPF (manual)

If you prefer to run ARGUS directly without systemd:

```bash
# One-time setup: install nightly toolchain and bpf-linker
just setup-ebpf

# Build the eBPF probes
just build-ebpf

# Run (needs root)
sudo ./target/release/argus-agent \
  --mode live \
  --ebpf-path argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf \
  --tui
```

After eBPF programs are loaded, ARGUS drops all capabilities and sets `PR_SET_NO_NEW_PRIVS`. It doesn't stay root.

### Artifact integrity

If you're deploying to production, you can pin the expected eBPF binary hash:

```bash
sha256sum argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf
# pass the hash at runtime:
sudo ./target/release/argus-agent \
  --mode live \
  --ebpf-path argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf \
  --ebpf-hash <sha256hex> \
  --tui
```

The agent will refuse to load a binary that doesn't match.

## Replay mode

ARGUS can replay recorded event files and test scenarios:

```bash
cargo run --release -- --mode replay --file argus-test-scenarios/scenarios/link_flap_critical.json --tui
```

Scenarios include expected state transitions so they double as regression tests. See `argus-test-scenarios/scenarios/` for examples.

## Prometheus and health endpoints

The agent exposes two HTTP(S) endpoints when `--metrics-addr` is set (always set in systemd mode):

| Endpoint | Content | Use |
|---|---|---|
| `/metrics` | Prometheus text format | Scrape target for Prometheus |
| `/health` | JSON | Kubernetes liveness/readiness, SLURM health checks |

```bash
# Plain HTTP (standalone / trusted network)
curl http://localhost:9100/metrics
curl http://localhost:9100/health

# With TLS + bearer auth (production)
TOKEN=$(sudo cat /etc/argus/token)
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:9100/metrics
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:9100/health
```

Health response format:
```json
{"state":"HEALTHY","uptime_secs":42.3,"events_processed":14200,"last_window_ts":1710000000}
```

For manual runs (without systemd), enable the endpoint with:
```bash
./target/release/argus-agent --mode mock --metrics-addr 127.0.0.1:9100
```

## Don't have an HPC cluster but want to test ARGUS?
No problem. Detailed instructions for setting up Lima VMs with soft-roce and running ARGUS can be found here: (WIP)

## Architecture

```
┌──────────────────────────────────────────────┐
│                  Linux Kernel                │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ kmem     │ │ irq      │ │ napi         │  │
│  │ probes   │ │ probes   │ │ probes       │  │
│  └────┬─────┘ └────┬─────┘ └──────┬───────┘  │
│       │  counter++  │  counter++   │          │
│  ┌────▼─────┐ ┌────▼─────┐ ┌──────▼───────┐  │
│  │SLAB_STATS│ │IRQ_COUNTS│ │ NAPI_STATS   │  │
│  │PerCpuMap │ │PerCpuMap │ │ PerCpuMap    │  │
│  └──────────┘ └──────────┘ └──────────────┘  │
└──────────────────────────────────────────────┘
              │ read maps (once per window)
     ┌────────▼────────┐    ┌─────────────────┐
     │  BPF Map Reader │    │  HW Counter     │
     │  (eBPF source)  │    │  Reader (sysfs) │
     └────────┬────────┘    └────────┬────────┘
              │                      │
     ┌────────▼──────────────────────▼────────┐
     │              Aggregator                │
     │  (per-window metrics: IRQ dist, slab,  │
     │   RDMA, NAPI, IB counter deltas)       │
     └────────────────┬───────────────────────┘
                      │
     ┌────────────────▼───────────────────────┐
     │          Detection Engine              │
     │  8 rules · EWMA rolling stats ·        │
     │  hysteresis · composite health score   │
     └──────┬──────────────┬──────────────────┘
            │              │
     ┌──────▼──────┐  ┌───▼──────────────┐
     │  TUI        │  │  Prometheus      │
     │  Dashboard  │  │  /metrics /health│
     └─────────────┘  └──────────────────┘
```

High-frequency tracepoints (IRQ, slab, NAPI) increment per-CPU BPF map counters in-kernel — a nanosecond-scale operation with no ring buffer overhead. Userspace reads these maps once per aggregation window (default 3 seconds), keeping CPU usage under 1%.

ARGUS is scheduler-agnostic. It doesn't talk to Kubernetes, SLURM, or any orchestrator directly. External systems consume its health signals through Prometheus, the health endpoint, or structured logs.

## Project layout

```
argus-agent/          Userspace daemon (Rust, tokio)
argus-ebpf/           eBPF kernel probes (Rust, aya-ebpf, compiled with nightly)
argus-common/         Shared types between agent and tests
argus-test-scenarios/ JSON scenario files for replay and regression testing
xtask/                Build tooling (eBPF compilation)
scripts/              Install, export-dashboards, E2E tests, fault injection, Soft-RoCE
deploy/
  argusd.service      Systemd unit
  argusd.conf         Environment file (simple config)
  examples/           TOML configs, Prometheus scrape snippets, K8s manifests
  observability/      Bundled Prometheus + Grafana + Alertmanager stack
    grafana/dashboards/  Portable Grafana dashboards (importable into any Grafana)
```

## Testing

```bash
# Unit + integration + proptest + scenario + snapshot tests
cargo test --workspace

# Extended property-based testing (1000 cases)
PROPTEST_CASES=1000 cargo test --workspace --test proptest_detection

# E2E tests (tiered by available capabilities)
sudo scripts/e2e-test.sh
```

Current test counts: 50 unit tests, 6 property-based tests, 5 scenario tests, 3 TUI snapshot tests, plus 8 tests in `argus-common`.

## Testing without InfiniBand

You can test RDMA-related detection using Soft-RoCE:

```bash
sudo scripts/setup-soft-roce.sh
```

This creates an RDMA device over a regular Ethernet interface. Combined with `tc netem` for fault injection, you can exercise the full detection pipeline without real InfiniBand hardware.

## Platform support

ARGUS builds and runs the detection pipeline on any platform Rust supports. The eBPF probes and live hardware counter collection are Linux-only.

| Feature | Linux | macOS | Windows |
|---|---|---|---|
| Mock/replay modes | yes | yes | yes |
| TUI dashboard | yes | yes | yes |
| Prometheus endpoint | yes | yes | yes |
| eBPF kernel probes | yes | — | — |
| IB hardware counters | yes | — | — |

CI runs on both `ubuntu-latest` and `macos-latest`. ARM64 cross-compilation is checked on every PR.

## Security

ARGUS loads eBPF programs into the kernel. We take that seriously:

- **Privilege dropping**: All capabilities are dropped after eBPF load. `PR_SET_NO_NEW_PRIVS` is enforced.
- **Artifact verification**: `--ebpf-hash` validates SHA-256 of the eBPF binary before loading.
- **Seccomp**: `--seccomp` restricts syscalls after initialization.
- **Input validation**: Replay files are capped at 100MB / 10M events.
- **Dependency auditing**: `cargo deny` and `cargo audit` run in CI.
- **Unsafe minimized**: `argus-common` uses `#![forbid(unsafe_code)]`. The agent uses `#![deny(unsafe_code)]`. The only `unsafe` is in the eBPF kernel probes (required by BPF) and the privilege-dropping prctl call, both documented with `SAFETY` comments.

If you find a security issue, please open an issue or reach out directly before disclosing publicly.

## Resource overhead

ARGUS is designed to be invisible to workloads. In live mode, the agent:

- Sleeps between aggregation windows (default 3s)
- Wakes to read 3 BPF maps + sysfs counters (milliseconds of work)
- Runs detection rules and redraws the TUI
- Goes back to sleep

**Expected CPU usage**: <1% in steady state. eBPF probes add nanoseconds per tracepoint hit since they only increment per-CPU map counters (no ring buffer, no userspace wakeup).

### CPU scheduling controls

The systemd unit (`deploy/argusd.service`) ships with resource limits pre-configured:

```ini
CPUQuota=5%
Nice=19
IOSchedulingClass=idle
MemoryMax=256M
```

For manual runs, use `nice`:

```bash
nice +19 sudo ./target/release/argus-agent --mode live ...
```

### Tuning `--window-secs`

Longer windows = less frequent work = lower CPU. Shorter windows = faster detection.

| Window | CPU overhead | Detection latency |
|--------|-------------|-------------------|
| 1s     | ~2-3%       | ~2s (hysteresis)  |
| 3s     | <1%         | ~6s               |
| 10s    | <0.1%       | ~20s              |
| 30s    | negligible  | ~60s              |

For most HPC clusters, 3-10 seconds is a good balance. Link degradation develops over seconds to minutes, not milliseconds.

## Detection thresholds

All detection thresholds are configurable via CLI, TOML config (`[detection]` section), or the `DetectionConfig` struct. Defaults are tuned for typical HPC InfiniBand clusters:

| Parameter | Default | Description |
|---|---|---|
| `--window-secs` | 3 | Aggregation window duration |
| `irq_skew_threshold_pct` | 70.0 | % of IRQs on one CPU to trigger skew alert |
| `rdma_spike_factor` | 5.0 | Latency multiplier over baseline to trigger spike |
| `slab_pressure_min_allocs` | 100 | Minimum slab allocations per window to evaluate |
| `slab_pressure_alloc_rate_threshold` | 5000 | Alloc rate above which pressure is suspected |

## Contributing

Contributions are welcome. This project is still young and there's a lot of ground to cover, particularly around:

- Additional eBPF probes (scheduler latency, page faults, cgroup pressure)
- Smarter detection rules (ML-based anomaly detection, correlation between signals)
- Better scenario coverage and fuzz testing
- Packaging and distribution (RPM/DEB, container images)
- Documentation and operational guides

If you're running InfiniBand clusters and have opinions about what "link degradation" looks like in practice, we especially want to hear from you.

To get started:

```bash
just setup          # install dev tools
cargo test          # make sure everything passes
```

Open a PR against `main`. Tests must pass. We use `cargo fmt`, `cargo clippy` with pedantic lints, and `cargo deny` for dependency auditing.

## License

Apache-2.0. See [LICENSE](LICENSE) for details.

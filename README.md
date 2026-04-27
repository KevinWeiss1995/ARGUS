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
- Soft-RoCE (rxe) errors: duplicate requests, sequence errors, retries, send errors

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

| | Standalone | External Integration |
|---|---|---|
| Who runs Prometheus/Grafana | ARGUS (bundled Docker stack) | Your infrastructure |
| TLS on metrics endpoint | Optional | Recommended |
| Bearer token auth | Optional | Recommended |
| Best for | Single-node, demos, dev | Multi-node clusters, HPC |
| Config format | Env file or TOML | TOML |

### Prerequisites

- Linux with eBPF support (kernel 5.4+)
- Root or `CAP_BPF` permissions
- Rust toolchain (the install script will install it if missing)
- Docker + Docker Compose (only for the standalone observability stack)

---

### Option A: Standalone (ARGUS manages Grafana + Prometheus)

**Install and start the agent:**

```bash
git clone https://github.com/KevinWeiss1995/ARGUS.git
cd ARGUS
sudo ./scripts/install.sh
sudo systemctl enable --now argusd
```

The install script builds and installs:

| Path | Description |
|---|---|
| `/usr/local/bin/argusd` | Agent binary |
| `/usr/local/bin/argus-tui` | Attach a live TUI to any running agent |
| `/usr/local/bin/argus-status` | CLI health check (local or remote) |
| `/usr/local/bin/argus-discover` | Subnet scanner for node discovery |
| `/usr/local/bin/argus-manage-targets` | Manage Prometheus scrape targets |
| `/usr/local/bin/argus-scheduler` | Scheduler integration (enable, disable, hold, release, validate) |
| `/usr/local/lib/argus/argus-ebpf` | eBPF object |
| `/etc/argus/argusd.conf` | Environment-based config |
| `/etc/systemd/system/argusd.service` | Systemd unit |

If you already have pre-built binaries, use `sudo ./scripts/install.sh --no-build` to skip compilation. On upgrade, existing config files in `/etc/argus/` are **never overwritten**.

**Verify:**

```bash
argus-status                  # quick health check
argus-status --watch          # live refresh every 3s
curl localhost:9100/health    # raw JSON
```

**Start the observability stack:**

```bash
# Discover nodes on a subnet and launch Grafana + Prometheus + Alertmanager:
sudo argus-discover --subnet 10.0.0.0/24 --start

# Or start with just the local node:
cd ARGUS && deploy/observability/scripts/start-observability.sh
```

Open `http://<host-ip>:3000` (login: `admin` / `admin`). Three dashboards are pre-loaded:
- **Fleet Overview** — health summary across all monitored nodes
- **Node Detail** — kernel probe metrics, CQ jitter, IB counters
- **Link Drill-Down** — per-device, per-port error and throughput analysis

If the node has no InfiniBand hardware, IB/CQ panels will show "No IB hardware detected" — the kernel probe panels (IRQ, slab, NAPI) work on any Linux node.

**Managing monitored nodes:**

ARGUS uses Prometheus [file-based service discovery](https://prometheus.io/docs/guides/file-sd/). Targets are stored in `deploy/observability/argus-targets.json` and Prometheus picks up changes within 30 seconds — no restart required.

```bash
argus-manage-targets add 10.0.0.5          # add a node
argus-manage-targets add 10.0.0.7:9200     # non-default port
argus-manage-targets remove 10.0.0.5       # remove a node
argus-manage-targets list                   # show configured nodes
argus-manage-targets verify                 # probe each node, report status
argus-discover --subnet 10.0.0.0/24 \
  --output deploy/observability/argus-targets.json   # scan and write targets
```

Each target node needs `argusd` installed and port 9100 reachable from the Prometheus host.

---

### Option B: Integrate with existing Prometheus + Grafana

The agent exposes a standard `/metrics` endpoint. No Docker or ARGUS-managed stack required.

#### 1. Install the agent (on each node you want to monitor)

```bash
git clone https://github.com/KevinWeiss1995/ARGUS.git
cd ARGUS
sudo ./scripts/install.sh
```

#### 2. Enable the integration config

The default install uses an env-file config (`/etc/argus/argusd.conf`). For integration with an existing stack, switch to the TOML config which supports TLS and auth:

```bash
sudo cp deploy/examples/integration.toml /etc/argus/argusd.toml
```

Then edit `/etc/argus/argusd.conf` and uncomment the `ARGUS_CONFIG` line:

```bash
ARGUS_CONFIG=/etc/argus/argusd.toml
```

#### 3. Choose: TLS + auth or plain HTTP

**With TLS + auth** (recommended for multi-node / untrusted networks):

```bash
# Generate a self-signed cert and bearer token
sudo mkdir -p /etc/argus/tls
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /etc/argus/tls/server.key -out /etc/argus/tls/server.crt \
  -days 365 -nodes -subj "/CN=argusd"
sudo sh -c 'openssl rand -hex 32 > /etc/argus/token'
sudo chmod 600 /etc/argus/token
```

The TOML already references these paths. No edits needed.

**Without TLS** (trusted network, simpler setup): edit `/etc/argus/argusd.toml` and delete the `[tls]` and `[auth]` sections.

#### 4. Start the agent

```bash
sudo systemctl enable --now argusd
```

Verify it's running:

```bash
# Plain HTTP:
curl http://localhost:9100/health

# With TLS + auth:
TOKEN=$(sudo cat /etc/argus/token)
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:9100/health
```

You should see `{"state":"HEALTHY",...}`. If not, check `journalctl -u argusd -n 20`.

#### 5. Add ARGUS to your Prometheus

Add to your `prometheus.yml` (full examples in `deploy/examples/prometheus-scrape-argus.yml`):

**With TLS + auth:**

```yaml
scrape_configs:
  - job_name: argus
    scrape_interval: 5s
    scheme: https
    tls_config:
      insecure_skip_verify: true   # or ca_file: /path/to/ca.crt
    bearer_token_file: /etc/prometheus/argus-token
    static_configs:
      - targets: ["node01:9100", "node02:9100"]
```

Copy the token to your Prometheus host:

```bash
# On the Prometheus host — paste the token value from: sudo cat /etc/argus/token
echo "YOUR_TOKEN_HERE" | sudo tee /etc/prometheus/argus-token > /dev/null
sudo chmod 600 /etc/prometheus/argus-token
```

**Without TLS:**

```yaml
scrape_configs:
  - job_name: argus
    scrape_interval: 5s
    static_configs:
      - targets: ["node01:9100", "node02:9100"]
```

#### 6. Import dashboards into your Grafana

1. In Grafana, go to **Dashboards > New > Import**
2. Click **Upload dashboard JSON file**
3. Upload each file from `deploy/observability/grafana/dashboards/`:
   - `argus-fleet-overview.json`
   - `argus-node-detail.json`
   - `argus-link-drilldown.json`
4. When prompted, select your Prometheus datasource
5. Click **Import**

The dashboards use template variables so they'll auto-populate with your ARGUS nodes once Prometheus starts scraping.

**Push-based delivery** (firewalled nodes that can't be scraped): see `deploy/examples/prometheus-agent-sidecar.yml` for a Prometheus agent-mode sidecar that `remote_write`s to your central store.

---

### Attaching the TUI

The full terminal dashboard can be attached to any running `argusd` without interrupting it:

```bash
argus-tui                            # local node (localhost:9100)
argus-tui --attach 192.168.105.17    # remote node (port 9100 implied)
argusd --attach 10.0.0.5:9200        # non-default port
```

Press `q` or `Esc` to detach. The agent keeps running.

---

### Configuration reference

ARGUS supports two configuration layers, usable independently or together.

**Environment file** (`/etc/argus/argusd.conf`) — sourced by the systemd unit:
```bash
ARGUS_MODE=live
ARGUS_EBPF_PATH=/usr/local/lib/argus/argus-ebpf
ARGUS_METRICS_ADDR=0.0.0.0:9100
ARGUS_LOG_LEVEL=info
ARGUS_WINDOW_SECS=3
# ARGUS_CONFIG=/etc/argus/argusd.toml   # uncomment to enable TOML config
```

**TOML config file** (`/etc/argus/argusd.toml`) — must be enabled via `ARGUS_CONFIG`:

```toml
[agent]
mode = "live"
ebpf_path = "/usr/local/lib/argus/argus-ebpf"
log_level = "info"
window_secs = 3

[metrics]
addr = "0.0.0.0:9100"

[tls]                                    # omit to disable TLS
cert = "/etc/argus/tls/server.crt"
key  = "/etc/argus/tls/server.key"

[auth]                                   # omit to disable auth
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
# port_disable = false

# Scheduler integration (optional). Omit this section to disable.
# [scheduler]
# backend = "slurm"            # "slurm" or "noop"
# dry_run = false               # log drain/resume without executing
# drain_on_degraded = false     # drain on Degraded, not just Critical
# resume_cooldown_secs = 60     # minimum healthy seconds before auto-resume
# reconcile_interval_secs = 10  # how often to check scheduler state
# contested_cooldown_secs = 300 # cooldown when an external actor resumes a drained node
# state_file = "/var/lib/argus/scheduler-state.json"
```

**Precedence**: CLI flags > env file > TOML config > built-in defaults.

Example configs: `deploy/examples/standalone.toml`, `deploy/examples/integration.toml`.

### Scheduler integration

ARGUS can automatically drain and resume nodes via a workload scheduler when it detects health changes. A state-driven reconciliation loop compares ARGUS's *desired* node state (derived from health) against the *observed* scheduler state and converges them.

ARGUS does not install or manage SLURM (or any scheduler). You bring a working scheduler; ARGUS integrates with it.

**Prerequisites**: A running SLURM cluster where this node is registered, `scontrol` is in PATH, and munge is active. Validate with:

```bash
argus-scheduler validate
```

**Enable integration**:

```bash
sudo argus-scheduler enable slurm   # validates prerequisites, updates argusd.conf, restarts argusd
argus-scheduler status              # verify it's active
```

**Operator holds**: If someone drains a node outside ARGUS (e.g., `scontrol update State=DRAIN Reason="maintenance"`), ARGUS detects the external drain and enters `HeldByOperator` mode — it will not resume the node.

```bash
argus-scheduler hold              # set hold manually
argus-scheduler release           # release hold
sudo argus-scheduler disable      # turn off scheduler integration entirely
```

**TOML configuration** (alternative to CLI):

```toml
[scheduler]
backend = "slurm"
dry_run = false
drain_on_degraded = false
resume_cooldown_secs = 60
reconcile_interval_secs = 10
```

**CLI flags** (override TOML):
- `--scheduler slurm` / `--scheduler noop` — backend selection
- `--scheduler-dry-run` — log actions without executing
- `--drain-on-degraded` — drain on Degraded (default: only Critical)
- `--resume-cooldown 60` — seconds healthy before auto-resume

### Kubernetes deployment

A DaemonSet manifest with headless Service and ServiceMonitor (for Prometheus Operator) is provided at `deploy/examples/k8s-daemonset.yaml`.

## HTTP endpoints

When `--metrics-addr` is set (always set in systemd mode), the agent exposes:

| Endpoint | Content | Use |
|---|---|---|
| `/metrics` | Prometheus text format | Scrape target for Prometheus |
| `/health` | JSON (state, uptime, event count) | Kubernetes liveness/readiness, SLURM health checks |
| `/status` | JSON (full metrics + alerts) | TUI attach mode, external tooling |
| `/scheduler/hold` | JSON | Set operator hold (stops ARGUS from resuming) |
| `/scheduler/release` | JSON | Release operator hold |

```bash
curl http://localhost:9100/health
# {"state":"HEALTHY","uptime_secs":42.3,"events_processed":14200,"last_window_ts":1710000000}

# With TLS + auth:
TOKEN=$(sudo cat /etc/argus/token)
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:9100/metrics
```

## Running with live eBPF (manual)

If you prefer to run ARGUS directly without systemd:

```bash
just setup-ebpf     # one-time: install nightly toolchain and bpf-linker
just build-ebpf     # build the eBPF probes

sudo ./target/release/argus-agent \
  --mode live \
  --ebpf-path argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf \
  --tui
```

After eBPF programs are loaded, ARGUS drops all capabilities and sets `PR_SET_NO_NEW_PRIVS`.

### Artifact integrity

Pin the expected eBPF binary hash for hardened deployments:

```bash
sha256sum argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf
sudo ./target/release/argus-agent --mode live \
  --ebpf-path argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf \
  --ebpf-hash <sha256hex>
```

## Replay mode

```bash
cargo run --release -- --mode replay --file argus-test-scenarios/scenarios/link_flap_critical.json --tui
```

Scenarios include expected state transitions so they double as regression tests. See `argus-test-scenarios/scenarios/` for examples.

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

ARGUS is scheduler-agnostic. External systems consume its health signals through Prometheus, the health endpoint, or structured logs.

## Project layout

```
argus-agent/              Userspace daemon (Rust, tokio)
argus-ebpf/               eBPF kernel probes (Rust, aya-ebpf, compiled with nightly)
argus-common/             Shared types between agent and tests
argus-test-scenarios/     JSON scenario files for replay and regression testing
xtask/                    Build tooling (eBPF compilation)
scripts/
  install.sh              Build + install argusd as a systemd service
  argus-status            CLI health check
  argus-tui               Symlink → argusd; TUI attach mode
  argus-discover          Subnet scanner, generates Prometheus targets
  argus-manage-targets    Add/remove/list/verify scrape targets
  argus-scheduler         Scheduler integration CLI (enable, hold, setup-slurm)
  export-dashboards.sh    Export dashboards for import into external Grafana
  e2e-test.sh             End-to-end + fault injection tests
deploy/
  argusd.service          Systemd unit
  argusd.conf             Environment file
  examples/               TOML configs, Prometheus snippets, K8s manifests
  observability/
    argus-targets.json    Prometheus file_sd targets (hot-reloaded)
    grafana/dashboards/   Portable Grafana dashboards
```

## Testing

```bash
cargo test --workspace                                        # all tests
PROPTEST_CASES=1000 cargo test --workspace --test proptest_detection  # extended proptests
sudo scripts/e2e-test.sh                                      # E2E (tiered by capability)
```

### Testing without InfiniBand

You can test RDMA detection using Soft-RoCE:

```bash
sudo scripts/setup-soft-roce.sh
```

This creates an RDMA device over a regular Ethernet interface. Combined with `tc netem` for fault injection, you can exercise the full detection pipeline without real IB hardware.

## Platform support

| Feature | Linux | macOS | Windows |
|---|---|---|---|
| Mock/replay modes | yes | yes | yes |
| TUI dashboard | yes | yes | yes |
| Prometheus endpoint | yes | yes | yes |
| eBPF kernel probes | yes | — | — |
| IB hardware counters | yes | — | — |

## Security

- **Privilege dropping**: All capabilities dropped after eBPF load. `PR_SET_NO_NEW_PRIVS` enforced.
- **Artifact verification**: `--ebpf-hash` validates SHA-256 before loading.
- **Seccomp**: `--seccomp` restricts syscalls after initialization.
- **Input validation**: Replay files capped at 100MB / 10M events.
- **Dependency auditing**: `cargo deny` and `cargo audit` in CI.
- **Unsafe minimized**: `argus-common` uses `#![forbid(unsafe_code)]`. The agent uses `#![deny(unsafe_code)]`. Only `unsafe` is in eBPF probes (required by BPF) and the prctl call, both documented.

## Resource overhead

In live mode, the agent sleeps between aggregation windows (default 3s), wakes to read 3 BPF maps + sysfs counters, runs detection rules, and goes back to sleep.

**Expected CPU usage**: <1% in steady state. eBPF probes add nanoseconds per tracepoint hit.

The systemd unit ships with resource limits:
```ini
CPUQuota=5%
Nice=19
IOSchedulingClass=idle
MemoryMax=256M
```

| Window | CPU overhead | Detection latency |
|--------|-------------|-------------------|
| 1s     | ~2-3%       | ~2s (hysteresis)  |
| 3s     | <1%         | ~6s               |
| 10s    | <0.1%       | ~20s              |
| 30s    | negligible  | ~60s              |

For most HPC clusters, 3-10 seconds is a good balance.

## Detection thresholds

All thresholds are configurable via CLI, TOML (`[detection]` section), or the `DetectionConfig` struct:

| Parameter | Default | Description |
|---|---|---|
| `--window-secs` | 3 | Aggregation window duration |
| `irq_skew_threshold_pct` | 70.0 | % of IRQs on one CPU to trigger skew alert |
| `rdma_spike_factor` | 5.0 | Latency multiplier over baseline |
| `slab_pressure_min_allocs` | 100 | Minimum slab allocs per window to evaluate |
| `slab_pressure_alloc_rate_threshold` | 5000 | Alloc rate above which pressure is suspected |

## Contributing

Contributions are welcome. Areas we'd especially appreciate help:

- Additional eBPF probes (scheduler latency, page faults, cgroup pressure)
- Smarter detection rules (ML-based anomaly detection, signal correlation)
- Better scenario coverage and fuzz testing
- Packaging (RPM/DEB, container images)

If you're running InfiniBand clusters and have opinions about what "link degradation" looks like in practice, we especially want to hear from you.

```bash
just setup          # install dev tools
cargo test          # make sure everything passes
```

Open a PR against `main`. Tests must pass. We use `cargo fmt`, `cargo clippy` with pedantic lints, and `cargo deny`.

## License

Apache-2.0. See [LICENSE](LICENSE) for details.

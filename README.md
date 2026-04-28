# ARGUS

**Adaptive RDMA Guard & Utilization Sentinel**

ARGUS is a lightweight, node-local telemetry agent that uses eBPF to detect InfiniBand link degradation before applications are affected. It monitors kernel-level signals (interrupt distribution, slab pressure, NAPI saturation) and IB hardware counters, runs them through a hardened detection engine, and classifies each node as **Healthy**, **Degraded**, or **Critical**. When integrated with a workload scheduler, it can automatically drain unhealthy nodes and resume them once they recover.

Metrics are exposed as a standard Prometheus endpoint. If you already run Grafana, jump to [Integrate with existing Prometheus + Grafana](#option-b-integrate-with-existing-prometheus--grafana).

*ARGUS is under active development. We'd love your help — email kjweiss1995@gmail.com if this project interests you.*

## What it monitors

**Kernel probes** (eBPF):
- `kmem/kmem_cache_alloc`, `kmem_cache_free` — slab allocator pressure
- `irq/irq_handler_entry` — interrupt affinity distribution across CPUs
- `napi/napi_poll` — NIC polling saturation
- CQ submit/poll kprobes — completion queue jitter (Soft-RoCE and hardware)

**Hardware counters** (sysfs):
- Symbol errors, link downed, port receive errors, transmit discards
- Receive/transmit throughput deltas
- Remote physical errors, link integrity errors, buffer overruns
- Soft-RoCE (rxe) counters: duplicate requests, sequence errors, retries

**Detection rules** (11 rules — reactive + predictive):
- IRQ affinity skew, RDMA latency spikes, IB link degradation, slab pressure correlation
- Rising error trend, latency drift (z-score), throughput drop, NAPI saturation
- CQ jitter, congestion spread, PCIe bottleneck detection

State transitions use a hardened state machine with asymmetric hysteresis, EWMA + peak-hold smoothing, and dwell timers to prevent flapping.

## Quick start

```bash
git clone https://github.com/KevinWeiss1995/ARGUS.git
cd ARGUS
cargo run --release -- --mode mock --profile skew --tui
```

No root, eBPF, or IB hardware needed. Mock mode generates synthetic events through the full pipeline. Try `--profile pressure` or `--profile spike` for other failure scenarios.

## Deployment

| | Standalone | External Integration |
|---|---|---|
| Who runs Prometheus/Grafana | ARGUS (bundled Docker stack) | Your infrastructure |
| TLS + bearer auth | Optional | Recommended |
| Best for | Single-node, demos, dev | Multi-node clusters, HPC |

### Prerequisites

- Linux with eBPF support (kernel 5.4+)
- Root or `CAP_BPF`
- Rust toolchain (install script handles this)
- Docker + Compose (standalone mode only)

---

### Option A: Standalone (ARGUS manages Grafana + Prometheus)

```bash
git clone https://github.com/KevinWeiss1995/ARGUS.git
cd ARGUS
sudo ./scripts/install.sh
sudo systemctl enable --now argusd
```

Verify:

```bash
argus-status                  # quick health check
argus-status --watch          # live refresh every 3s
curl localhost:9100/health    # raw JSON
```

Start the observability stack:

```bash
sudo argus-discover --subnet 10.0.0.0/24 --start
```

Open `http://<host-ip>:3000` (login: `admin`/`admin`). Three dashboards are pre-loaded: **Fleet Overview**, **Node Detail**, and **Link Drill-Down**.

Manage monitored nodes:

```bash
argus-manage-targets add 10.0.0.5
argus-manage-targets remove 10.0.0.5
argus-manage-targets list
argus-discover --subnet 10.0.0.0/24 --output deploy/observability/argus-targets.json
```

Prometheus picks up target changes within 30 seconds via [file-based service discovery](https://prometheus.io/docs/guides/file-sd/).

---

### Option B: Integrate with existing Prometheus + Grafana

#### 1. Install the agent (each monitored node)

```bash
git clone https://github.com/KevinWeiss1995/ARGUS.git && cd ARGUS
sudo ./scripts/install.sh
```

#### 2. (Optional) Enable TLS + auth

```bash
sudo cp deploy/examples/integration.toml /etc/argus/argusd.toml
# Edit /etc/argus/argusd.conf → uncomment: ARGUS_CONFIG=/etc/argus/argusd.toml

sudo mkdir -p /etc/argus/tls
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /etc/argus/tls/server.key -out /etc/argus/tls/server.crt \
  -days 365 -nodes -subj "/CN=argusd"
sudo sh -c 'openssl rand -hex 32 > /etc/argus/token'
sudo chmod 600 /etc/argus/token
```

Skip this step for trusted networks — plain HTTP works out of the box.

#### 3. Start the agent

```bash
sudo systemctl enable --now argusd
curl http://localhost:9100/health    # should return {"state":"HEALTHY",...}
```

#### 4. Add to your Prometheus

```yaml
scrape_configs:
  - job_name: argus
    scrape_interval: 5s
    static_configs:
      - targets: ["node01:9100", "node02:9100"]
```

For TLS + auth, see `deploy/examples/prometheus-scrape-argus.yml`.

#### 5. Import dashboards

Upload the JSON files from `deploy/observability/grafana/dashboards/` into Grafana (**Dashboards > Import**):
- `argus-fleet-overview.json`
- `argus-node-detail.json`
- `argus-link-drilldown.json`

Select your Prometheus datasource when prompted. Dashboards use template variables and auto-populate.

---

### Scheduler integration

ARGUS can automatically drain and resume nodes via a workload scheduler. A reconciliation loop compares ARGUS's desired state against the scheduler's observed state and converges them.

ARGUS does not install or manage SLURM. You bring a working scheduler; ARGUS integrates with it.

```bash
argus-scheduler validate              # check prerequisites (scontrol, munge, permissions)
sudo argus-scheduler enable slurm     # enable integration, restart argusd
argus-scheduler status                # verify active
```

Operator holds prevent ARGUS from resuming externally-drained nodes:

```bash
argus-scheduler hold                  # set hold
argus-scheduler release               # release hold
sudo argus-scheduler disable          # disable integration entirely
```

TOML alternative:

```toml
[scheduler]
backend = "slurm"
dry_run = false
drain_on_degraded = false
resume_cooldown_secs = 60
```

CLI flags: `--scheduler slurm`, `--scheduler-dry-run`, `--drain-on-degraded`, `--resume-cooldown 60`.

---

### TUI

Attach a live dashboard to any running agent without interrupting it:

```bash
argus-tui                            # localhost:9100
argus-tui --attach 192.168.105.17    # remote node
```

Press `q` to detach. The agent keeps running.

---

### Installed paths

| Path | Description |
|---|---|
| `/usr/local/bin/argusd` | Agent binary |
| `/usr/local/bin/argus-tui` | TUI attach mode |
| `/usr/local/bin/argus-status` | CLI health check |
| `/usr/local/bin/argus-discover` | Subnet scanner |
| `/usr/local/bin/argus-manage-targets` | Prometheus target management |
| `/usr/local/bin/argus-scheduler` | Scheduler integration CLI |
| `/usr/local/lib/argus/argus-ebpf` | eBPF object |
| `/etc/argus/argusd.conf` | Env config (never overwritten on upgrade) |
| `/etc/argus/argusd.toml` | TOML config (never overwritten on upgrade) |

---

## Configuration reference

**Env file** (`/etc/argus/argusd.conf`):
```bash
ARGUS_MODE=live
ARGUS_EBPF_PATH=/usr/local/lib/argus/argus-ebpf
ARGUS_METRICS_ADDR=0.0.0.0:9100
ARGUS_LOG_LEVEL=info
ARGUS_WINDOW_SECS=3
# ARGUS_CONFIG=/etc/argus/argusd.toml
```

**TOML** (`/etc/argus/argusd.toml`):

```toml
[agent]
mode = "live"
ebpf_path = "/usr/local/lib/argus/argus-ebpf"
log_level = "info"
window_secs = 3

[metrics]
addr = "0.0.0.0:9100"

[tls]
cert = "/etc/argus/tls/server.crt"
key  = "/etc/argus/tls/server.key"

[auth]
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

[scheduler]
backend = "slurm"
dry_run = false
drain_on_degraded = false
resume_cooldown_secs = 60
```

Precedence: CLI flags > env file > TOML > defaults. Example configs in `deploy/examples/`.

## HTTP endpoints

| Endpoint | Content | Use |
|---|---|---|
| `/metrics` | Prometheus text format | Scrape target |
| `/health` | JSON | Liveness probes, SLURM health checks |
| `/status` | JSON (full metrics + alerts) | TUI attach, external tooling |
| `/scheduler/hold` | JSON | Set operator hold |
| `/scheduler/release` | JSON | Release operator hold |

## Running without systemd

```bash
just setup-ebpf     # one-time: nightly toolchain + bpf-linker
just build-ebpf     # build eBPF probes

sudo ./target/release/argus-agent \
  --mode live \
  --ebpf-path argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf \
  --tui
```

Pin eBPF artifact hash for hardened deployments:

```bash
sudo ./target/release/argus-agent --mode live \
  --ebpf-path argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf \
  --ebpf-hash $(sha256sum argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf | cut -d' ' -f1)
```

## Replay mode

```bash
cargo run --release -- --mode replay --file argus-test-scenarios/scenarios/link_flap_critical.json --tui
```

Scenarios include expected states and double as regression tests.

## Testing without InfiniBand

Soft-RoCE + `tc netem` exercises the full detection pipeline over regular Ethernet:

```bash
sudo scripts/setup-soft-roce.sh
```

Detailed Lima VM setup instructions: (WIP)

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
     │  11 rules · EWMA + peak-hold ·        │
     │  state machine · scheduler integration│
     └──────┬──────────────┬──────────────────┘
            │              │
     ┌──────▼──────┐  ┌───▼──────────────┐
     │  TUI        │  │  Prometheus      │
     │  Dashboard  │  │  /metrics /health│
     └─────────────┘  └──────────────────┘
```

High-frequency tracepoints increment per-CPU BPF map counters in-kernel (nanosecond-scale, no ring buffer). Userspace reads maps once per window (default 3s), keeping CPU < 1%.

## Platform support

| Feature | Linux | macOS | Windows |
|---|---|---|---|
| Mock/replay modes | yes | yes | yes |
| TUI dashboard | yes | yes | yes |
| Prometheus endpoint | yes | yes | yes |
| eBPF kernel probes | yes | — | — |
| IB hardware counters | yes | — | — |

## Security

- **Privilege dropping**: all capabilities dropped after eBPF load; `PR_SET_NO_NEW_PRIVS` enforced
- **Artifact verification**: `--ebpf-hash` validates SHA-256 before loading
- **Seccomp**: `--seccomp` restricts syscalls post-init
- **Input validation**: replay files capped at 100MB / 10M events
- **Unsafe minimized**: `argus-common` uses `#![forbid(unsafe_code)]`; agent uses `#![deny(unsafe_code)]`

## Resource overhead

| Window | CPU | Detection latency |
|--------|-----|-------------------|
| 1s | ~2-3% | ~2s |
| 3s (default) | <1% | ~6s |
| 10s | <0.1% | ~20s |

Systemd unit ships with `CPUQuota=5%`, `Nice=19`, `MemoryMax=256M`.

## Testing

```bash
cargo test --workspace
PROPTEST_CASES=1000 cargo test --workspace --test proptest_detection
sudo scripts/e2e-test.sh
```

## Contributing

Areas we'd especially appreciate help:
- Additional eBPF probes (scheduler latency, page faults, cgroup pressure)
- Smarter detection (ML anomaly detection, signal correlation)
- Packaging (RPM/DEB, container images)
- Real-world IB failure pattern characterization

```bash
just setup && cargo test
```

Open a PR against `main`. We use `cargo fmt`, `cargo clippy` (pedantic), and `cargo deny`.

## License

Apache-2.0. See [LICENSE](LICENSE).

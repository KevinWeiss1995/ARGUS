# ARGUS

**Adaptive RDMA Guard & Utilization Sentinel**

[arguslabs.dev](https://arguslabs.dev)

ARGUS is a lightweight eBPF agent that detects InfiniBand link degradation before applications are affected. It monitors kernel-level signals (interrupt distribution, slab allocation latency, NAPI saturation, CQ completion jitter) alongside IB hardware counters, classifying each node as **Healthy**, **Degraded**, or **Critical** in real time. Nodes can be automatically drained and resumed via SLURM or other schedulers.

Metrics are exposed as a standard Prometheus endpoint. Dashboards ship ready to import.

## What it monitors

**Kernel probes** (eBPF):
- `kmem_cache_alloc` kprobe/kretprobe — slab allocation latency
- `kmem/kmem_cache_alloc`, `kmem_cache_free` tracepoints — slab alloc/free accounting
- `irq/irq_handler_entry` — interrupt affinity distribution across CPUs
- `napi/napi_poll` — NIC polling saturation
- CQ submit/poll kprobes — completion queue jitter (mlx5, rxe)

**Hardware counters** (sysfs):
- Symbol errors, link downed, port receive errors, transmit discards
- Receive/transmit throughput deltas
- Remote physical errors, link integrity errors, buffer overruns
- Soft-RoCE (rxe) counters: duplicate requests, sequence errors, retries

**Detection** (11 rules — reactive + predictive):
- IRQ affinity skew, RDMA latency spikes, IB link degradation, slab pressure correlation
- Rising error trend, latency drift (z-score), throughput drop, NAPI saturation
- CQ jitter, congestion spread, PCIe bottleneck detection

State transitions use asymmetric hysteresis, EWMA + peak-hold smoothing, and dwell timers to prevent flapping.

## Quick start

```bash
git clone https://github.com/KevinWeiss1995/ARGUS.git
cd ARGUS
cargo run --release -- --mode mock --profile skew --tui
```

No root, eBPF, or IB hardware needed. Mock mode generates synthetic events through the full pipeline. Try `--profile pressure` or `--profile spike` for other failure scenarios.

## Install

```bash
sudo ./scripts/install.sh
sudo systemctl enable --now argusd
argus-status
```

Verify: `curl localhost:9100/health`

For multi-node discovery and the bundled Grafana/Prometheus stack:

```bash
sudo argus-discover --subnet 10.0.0.0/24 --start
```

Open `http://<host-ip>:3000` (login: `admin`/`admin`).

## Integrate with existing Prometheus

```yaml
scrape_configs:
  - job_name: argus
    scrape_interval: 5s
    static_configs:
      - targets: ["node01:9100", "node02:9100"]
```

Import dashboards from `deploy/observability/grafana/dashboards/` into Grafana. For TLS + auth examples, see `deploy/examples/`.

## Configuration

ARGUS reads configuration from three sources (highest precedence first): CLI flags, environment variables, TOML config file.

All env vars use the `ARGUS_` prefix and map directly to CLI flags — no shell wrapper needed. See `argusd --help` for the full list.

**Env file** (`/etc/argus/argusd.conf`):

```bash
ARGUS_MODE=live
ARGUS_EBPF_PATH=/usr/lib/argus/argus-ebpf
ARGUS_METRICS_ADDR=127.0.0.1:9100
ARGUS_LOG_LEVEL=info
# ARGUS_SCHEDULER=slurm
```

**TOML** (`/etc/argus/argusd.toml`) — see `deploy/examples/` for full examples including TLS, auth, detection tuning, and scheduler integration.

## TUI

Attach a live dashboard to any running agent:

```bash
argus-tui                            # localhost
argus-tui --attach 192.168.105.17    # remote node
```

## Installed paths

| Path | Description |
|---|---|
| `/usr/bin/argusd` | Agent binary |
| `/usr/lib/argus/argus-ebpf` | eBPF object |
| `/etc/argus/argusd.conf` | Env config (preserved on upgrade) |
| `/etc/argus/argusd.toml` | TOML config (preserved on upgrade) |
| `/usr/lib/systemd/system/argusd.service` | Systemd unit |

CLI tools: `argus-tui`, `argus-status`, `argus-discover`, `argus-manage-targets`, `argus-scheduler`

## HTTP endpoints

| Endpoint | Use |
|---|---|
| `/metrics` | Prometheus scrape target |
| `/health` | Liveness probes, scheduler health checks |
| `/status` | TUI attach, external tooling |

## Architecture

```
┌──────────────────────────────────────────────┐
│                  Linux Kernel                │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ kmem     │ │ irq      │ │ napi / CQ    │  │
│  │ probes   │ │ probes   │ │ probes       │  │
│  └────┬─────┘ └────┬─────┘ └──────┬───────┘  │
│  ┌────▼─────┐ ┌────▼─────┐ ┌──────▼───────┐  │
│  │PerCpuMap │ │PerCpuMap │ │  PerCpuMap   │  │
│  └──────────┘ └──────────┘ └──────────────┘  │
└──────────────────────────────────────────────┘
              │ read maps (once per window)
     ┌────────▼────────┐    ┌─────────────────┐
     │  BPF Map Reader │    │  HW Counter     │
     │  (eBPF source)  │    │  Reader (sysfs) │
     └────────┬────────┘    └────────┬────────┘
              │                      │
     ┌────────▼──────────────────────▼────────┐
     │           Aggregator + Detection       │
     │  11 rules · EWMA + peak-hold ·         │
     │  state machine · scheduler integration │
     └──────┬──────────────┬──────────────────┘
            │              │
     ┌──────▼──────┐  ┌───▼──────────────┐
     │  TUI        │  │  Prometheus      │
     │  Dashboard  │  │  /metrics /health│
     └─────────────┘  └──────────────────┘
```

## Security

- **Systemd hardening**: `ProtectSystem=strict`, `MemoryDenyWriteExecute`, syscall filtering, capability bounding, `ProtectProc=invisible`, `NoNewPrivileges`
- **eBPF integrity**: SHA-256 hash verification before loading probes
- **Privilege dropping**: capabilities dropped after eBPF load; `PR_SET_NO_NEW_PRIVS` enforced
- **Metrics auth**: optional TLS + bearer token with constant-time comparison
- **Seccomp**: optional post-init syscall restriction via `--seccomp`
- **Config protection**: `argusd.conf` installed mode `0640`

## Platform support

| Feature | Linux | macOS | Windows |
|---|---|---|---|
| Mock/replay + TUI | yes | yes | yes |
| Prometheus endpoint | yes | yes | yes |
| eBPF kernel probes | yes | — | — |
| IB hardware counters | yes | — | — |

## Testing

```bash
cargo test --workspace
PROPTEST_CASES=1000 cargo test --workspace --test proptest_detection
sudo scripts/e2e-test.sh
```

## Contributing

```bash
just setup && cargo test
```

Open a PR against `main`. We use `cargo fmt`, `cargo clippy` (pedantic), and `cargo deny`.

Areas we'd appreciate help: additional eBPF probes, smarter detection (ML anomaly detection), real-world IB failure pattern characterization, Kubernetes integration.

## License

Apache-2.0. See [LICENSE](LICENSE).

# ARGUS

**Adaptive RDMA Guard & Utilization Sentinel**

ARGUS is a lightweight, node-local telemetry agent that uses eBPF to monitor kernel behavior related to RDMA networking, interrupt handling, and memory allocation. It's designed to catch the early warning signs of InfiniBand link degradation and system imbalance *before* your applications notice; not after.

We built this to fill a gap we saw in other fabric monitors. In most cases, by the time a job hangs on an NCCL/MPI timeout the link has usually been degraded for minutes. The hardware counters were screaming the whole time, but with nobody listening at the right layer the degradation goes undected until jobs become painfully slow. ARGUS intends to fix that.

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

## Running with live eBPF

This requires Linux with eBPF support and root (or `CAP_BPF` + `CAP_PERFMON`).

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

```bash
# Enable the metrics server
./target/release/argus-agent --mode mock --metrics-addr 127.0.0.1:9090

# Scrape metrics
curl http://127.0.0.1:9090/metrics

# Health check (for Kubernetes probes, SLURM health checks, etc.)
curl http://127.0.0.1:9090/health
```

The health endpoint returns JSON:
```json
{"state":"HEALTHY","uptime_secs":42.3,"events_processed":14200,"last_window_ts":1710000000}
```

## Don't have an HPC cluster but want to test ARGUS?
No problem. Detailed instructions for setting up Lima VMs with soft-roce can be found here: 

## Architecture

```
┌─────────────────────────────────────────────┐
│                  Linux Kernel                │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
│  │ kmem     │ │ irq      │ │ napi         │ │
│  │ probes   │ │ probes   │ │ probes       │ │
│  └────┬─────┘ └────┬─────┘ └──────┬───────┘ │
│       └─────────┬──┘───────────────┘         │
│            Ring Buffer                       │
└─────────────┬───────────────────────────────┘
              │
     ┌────────▼────────┐    ┌─────────────────┐
     │  Event Source    │    │  HW Counter     │
     │  (eBPF/mock/    │    │  Reader (sysfs) │
     │   replay)       │    │                 │
     └────────┬────────┘    └────────┬────────┘
              │                      │
     ┌────────▼──────────────────────▼────────┐
     │              Aggregator                 │
     │  (per-window metrics: IRQ dist, slab,  │
     │   RDMA, NAPI, IB counter deltas)       │
     └────────────────┬───────────────────────┘
                      │
     ┌────────────────▼───────────────────────┐
     │          Detection Engine               │
     │  8 rules · EWMA rolling stats ·        │
     │  hysteresis · composite health score   │
     └──────┬──────────────┬──────────────────┘
            │              │
     ┌──────▼──────┐  ┌───▼──────────────┐
     │  TUI        │  │  Prometheus       │
     │  Dashboard  │  │  /metrics /health │
     └─────────────┘  └──────────────────┘
```

ARGUS is scheduler-agnostic. It doesn't talk to Kubernetes, SLURM, or any orchestrator directly. External systems consume its health signals through Prometheus, the health endpoint, or structured logs.

## Project layout

```
argus-agent/          Userspace daemon (Rust, tokio)
argus-ebpf/           eBPF kernel probes (Rust, aya-ebpf, compiled with nightly)
argus-common/         Shared types between agent and tests
argus-test-scenarios/ JSON scenario files for replay and regression testing
xtask/                Build tooling (eBPF compilation)
scripts/              E2E tests, fault injection, Soft-RoCE setup
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

## Configuration

All detection thresholds are configurable via CLI or the `DetectionConfig` struct. Defaults are tuned for typical HPC InfiniBand clusters:

| Parameter | Default | Description |
|---|---|---|
| `--window-secs` | 3 | Aggregation window duration |
| `irq_skew_threshold_pct` | 70.0 | % of IRQs on one CPU to trigger skew alert |
| `rdma_spike_factor` | 5.0 | Latency multiplier over baseline to trigger spike |
| `rdma_link_min_error_delta` | 1 | Minimum IB error delta to trigger link degradation |
| `slab_pressure_min_allocs` | 100 | Minimum slab allocations per window to evaluate |
| `slab_pressure_alloc_rate_threshold` | 5000 | Alloc rate above which pressure is suspected |

## Contributing

Contributions are welcome. This project is still young and there's a lot of ground to cover — particularly around:

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

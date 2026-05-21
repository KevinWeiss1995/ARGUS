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

**Hardware counters** (sysfs — polled regardless of traffic, so passive monitoring stays on for idle links):
- Symbol errors, link downed, port receive errors, transmit discards
- Receive/transmit throughput deltas
- Remote physical errors, link integrity errors, buffer overruns
- Link error recovery (the leading predictor of cable failure)
- Soft-RoCE (rxe) counters: duplicate requests, sequence errors, retries

**Detection** (11 rules — reactive + predictive):
- IRQ affinity skew, RDMA latency spikes, IB link degradation, slab pressure correlation
- Rising error trend, latency drift (z-score), throughput drop, NAPI saturation
- CQ jitter, congestion spread, PCIe bottleneck detection

State transitions use asymmetric hysteresis, EWMA + peak-hold smoothing, and dwell timers to prevent flapping. When IB traffic is absent, the score is carried forward so a quiet fabric doesn't drift back to Healthy while an impairment persists.

---

## Try it locally (no hardware needed)

```bash
git clone https://github.com/KevinWeiss1995/ARGUS.git
cd ARGUS
cargo run --release -- --mode mock --profile skew --tui
```

Mock mode generates synthetic events through the full pipeline. Try `--profile pressure` or `--profile spike` for other failure scenarios. Works on Linux, macOS, and Windows. No root, eBPF, or IB required.

---

## Deploy on a real node

```bash
# As root on any Rocky 8 / RHEL 8 node:
dnf install -y \
    https://github.com/KevinWeiss1995/ARGUS/releases/download/v0.1.0/argus-0.1.0-1.el8.x86_64.rpm \
    https://github.com/KevinWeiss1995/ARGUS/releases/download/v0.1.0/argus-selinux-0.1.0-1.el8.noarch.rpm

argus-preflight                       # validate the host
systemctl enable --now argusd         # start the daemon
curl -s localhost:9100/health         # confirm: {"state":"HEALTHY",...}
argus-status                          # human-readable health line
```

That's the whole production install. The `argus-selinux` package is only
needed if `getenforce` reports `Enforcing` — drop it otherwise.

**Newer releases:** browse <https://github.com/KevinWeiss1995/ARGUS/releases>
and substitute the tag. Verify the download against the published
SHA-256 if you care:

```bash
TAG=v0.1.0
URL=https://github.com/KevinWeiss1995/ARGUS/releases/download/$TAG
wget $URL/argus-${TAG#v}-1.el8.x86_64.rpm.sha256
sha256sum -c argus-${TAG#v}-1.el8.x86_64.rpm.sha256
```

### Prerequisites

| Component         | Requirement                                                                 |
| ----------------- | --------------------------------------------------------------------------- |
| Linux kernel      | RHEL/Rocky 8.5+ stock (4.18 with backports), or any upstream ≥ 5.4           |
| InfiniBand stack  | `/sys/class/infiniband` populated (or skip live mode)                        |
| systemd           | any recent version (RHEL 8's systemd 239 works with the default unit)        |
| chronyd or ntpd   | active (fleet-wide alert correlation needs it)                               |

`argus-preflight` checks all of these and exits non-zero on FAIL. Run it
before installing if you want a heads-up.

**RHEL 8 / Rocky 8 stock kernels are fully supported.** RHEL 8.5 onward
(kernel `4.18.0-348.*` and later) ships every BPF feature ARGUS needs via
Red Hat backports. The systemd unit defaults to `CAP_SYS_ADMIN` so it
works across stock RHEL 8 systemd 239 and modern systemd alike. For
RHEL 8.4 or older, install ELRepo kernel-ml or upgrade the OS.

### Fleet deploy via Ansible

For more than a couple of nodes, use the bundled playbook — preflight on
every node, RPM install, firewalld, SELinux module if needed, config
templates, and a verify pass.

```bash
cd deploy/ansible
cp inventory.example.ini inventory.ini
cp group_vars/all.yml.example group_vars/all.yml
$EDITOR inventory.ini group_vars/all.yml      # hosts + RPM URL + recipients

ansible-playbook -i inventory.ini argus.yml --tags preflight    # dry-check
ansible-playbook -i inventory.ini argus.yml                     # full deploy
```

Required `group_vars` keys:

- `argus_rpm_source` — the same `https://github.com/.../argus-*.rpm` URL, or a local path
- `argus_metrics_addr` — usually `0.0.0.0:9100`
- `argus_install_selinux` — `true` on Enforcing clusters
- `argus_scheduler` — `slurm` to enable SLURM drain/resume

Tags let you re-run subsets: `--tags preflight`, `--tags install`,
`--tags verify`. See [`deploy/ansible/README.md`](deploy/ansible/README.md).

### Day-2 upgrade

```bash
TAG=v0.1.1      # whatever's new
URL=https://github.com/KevinWeiss1995/ARGUS/releases/download/$TAG
dnf upgrade -y $URL/argus-${TAG#v}-1.el8.x86_64.rpm
systemctl restart argusd
argus-preflight && curl -s localhost:9100/health
```

Or via Ansible: bump `argus_rpm_source` in `group_vars/all.yml` and
`ansible-playbook ... --tags install,verify`. Config files at
`/etc/argus/argusd.{conf,toml}` are `%config(noreplace)` — your edits
survive the upgrade.

### Build your own RPM

Only needed if you want to rebuild from source — the published RPM is
identical in content to what you'd produce locally. Three professional,
dependency-managed paths exist that avoid installing the Rust/LLVM
toolchain bare-metal:

```bash
./scripts/build-rpm.sh --apptainer        # HPC-friendly; SIF-based
./scripts/build-rpm.sh --container podman # Podman or Docker
spack install argus +rpm                  # Spack-managed sites
```

Full comparison: [`docs/hpc-build.md`](docs/hpc-build.md).
Production runbook: [`docs/production-deployment.md`](docs/production-deployment.md).

---

## Monitoring integration

ARGUS exposes a standard Prometheus endpoint; everything else builds on that.

### Existing Prometheus / Grafana

Add a scrape job and import the dashboards:

```yaml
scrape_configs:
  - job_name: argus
    scrape_interval: 5s
    static_configs:
      - targets: ["node01:9100", "node02:9100"]
```

Drop `deploy/observability/alert_rules.yml` into your rule_files, and
import the JSON dashboards from `deploy/observability/grafana/dashboards/`.

For dynamic node discovery across a subnet:

```bash
argus-discover --subnet 10.0.0.0/24 --output /etc/prometheus/argus-targets.json
```

### Standalone Prometheus + Grafana + Alertmanager (turnkey)

```bash
cd deploy/observability
./scripts/start-observability.sh
```

Brings up Prometheus :9091, Grafana :3000 (admin/admin), Alertmanager :9093.

### Email alerts (Alertmanager)

Edit `deploy/observability/alertmanager.yml`, fill in the lines marked
`[REQUIRED]` (your SMTP relay and recipient list), and reload Alertmanager.
Full walkthrough in [`docs/email-setup.md`](docs/email-setup.md).

### Zabbix

Import `deploy/zabbix/argus_template.yaml` (Zabbix 6.x / 7.x) and link it
to your HPC host group. The template scrapes `/metrics` via HTTP-agent
items — no `zabbix_agentd` shim required. Macros and trigger tuning in
[`docs/zabbix-integration.md`](docs/zabbix-integration.md).

### TLS + bearer-token authentication

Both Prometheus and Zabbix integrations support TLS + Bearer auth out of
the box. See [`deploy/examples/integration.toml`](deploy/examples/integration.toml)
for a full config example.

---

## Configuration

ARGUS reads configuration from three sources (highest precedence first):
CLI flags, environment variables, TOML config file.

All env vars use the `ARGUS_` prefix and map directly to CLI flags — no
shell wrapper needed. See `argusd --help` for the full list.

**Env file** (`/etc/argus/argusd.conf` — sourced by systemd):

```bash
ARGUS_CONFIG=/etc/argus/argusd.toml
ARGUS_MODE=live
ARGUS_EBPF_PATH=/usr/lib/argus/argus-ebpf
ARGUS_METRICS_ADDR=0.0.0.0:9100
ARGUS_LOG_LEVEL=info
# ARGUS_SCHEDULER=slurm
# ARGUS_SCHEDULER_DRY_RUN=true
```

**TOML** (`/etc/argus/argusd.toml`) — extended config including TLS, auth,
detection tuning, scheduler integration, and per-fabric profile overrides.
See [`deploy/examples/integration.toml`](deploy/examples/integration.toml).

Both files are tagged `%config(noreplace)` in the RPM — your customisations
survive `dnf upgrade`.

---

## TUI

Attach a live dashboard to any running agent:

```bash
argus-tui                            # localhost
argus-tui --attach 192.168.105.17    # remote node
```

The header shows `IB: traffic` when the fabric is active, or
`IB: passive (Ns idle)` when no throughput is observed — passive
monitoring of an idle link is still real monitoring; hardware error
counters keep firing regardless.

---

## HTTP endpoints

| Endpoint              | Use                                                  |
| --------------------- | ---------------------------------------------------- |
| `/metrics`            | Prometheus scrape target                             |
| `/health`             | Liveness probes, scheduler health checks             |
| `/status`             | TUI attach, full snapshot for external tooling       |
| `/coverage`           | Capability detection report (which backends ran)     |
| `/scheduler/hold`     | POST — operator hold (won't auto-resume)             |
| `/scheduler/release`  | POST — clear operator hold                           |

---

## Installed paths

| Path                                      | Description                          |
| ----------------------------------------- | ------------------------------------ |
| `/usr/bin/argusd`                         | Agent binary                         |
| `/usr/bin/argus-preflight`                | Readiness checker                    |
| `/usr/lib/argus/argus-ebpf`               | eBPF object                          |
| `/etc/argus/argusd.conf`                  | Env config (preserved on upgrade)    |
| `/etc/argus/argusd.toml`                  | TOML config (preserved on upgrade)   |
| `/etc/argus/ebpf.sha256`                  | eBPF integrity hash                  |
| `/usr/lib/systemd/system/argusd.service`  | Systemd unit                         |
| `/usr/share/argus/selinux/argus.pp`       | SELinux module (argus-selinux RPM)   |
| `/var/lib/argus/`                         | Persistent state, scheduler audit log |
| `/run/argus/`                             | PID and scheduler lock files         |

CLI tools: `argus-tui`, `argus-status`, `argus-preflight`, `argus-discover`,
`argus-manage-targets`, `argus-scheduler`.

---

## Upgrades and rollback

```bash
# Single host:
sudo dnf upgrade -y argus argus-selinux
sudo systemctl restart argusd
sudo argus-preflight
curl localhost:9100/health

# Ansible-managed fleet:
ansible-playbook -i inventory.ini argus.yml --tags install,verify
```

The install role's handler restarts argusd automatically when the binary
or config changes. To roll back, `dnf downgrade argus` (if the previous
RPM is still in the repo) or `rpm -Uvh --oldpackage argus-<prev>.rpm`.

Detailed upgrade procedure, rollback strategy, and failure-mode triage
table in [`docs/production-deployment.md`](docs/production-deployment.md).

---

## Troubleshooting

First two things, in order:

```bash
sudo argus-preflight                    # is the host configured correctly?
sudo journalctl -u argusd -e --no-pager # what does the agent itself say?
```

For SELinux denials, slow-starting probes, scheduler dry-run gotchas, and
nine other common diagnostic paths, see
[`docs/troubleshooting.md`](docs/troubleshooting.md).

---

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
- **SELinux**: optional policy module supports Enforcing mode on Rocky 8 / RHEL 8
- **eBPF integrity**: SHA-256 hash verification before loading probes
- **Privilege dropping**: capabilities dropped after eBPF load; `PR_SET_NO_NEW_PRIVS` enforced
- **Metrics auth**: optional TLS + bearer token with constant-time comparison
- **Seccomp**: optional post-init syscall restriction via `--seccomp`
- **Config protection**: `argusd.conf` installed mode `0640`

## Platform support

| Feature              | Linux | macOS | Windows |
| -------------------- | ----- | ----- | ------- |
| Mock/replay + TUI    | yes   | yes   | yes     |
| Prometheus endpoint  | yes   | yes   | yes     |
| eBPF kernel probes   | yes   | —     | —       |
| IB hardware counters | yes   | —     | —       |
| RPM packaging        | yes   | —     | —       |
| SELinux module       | yes   | —     | —       |

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

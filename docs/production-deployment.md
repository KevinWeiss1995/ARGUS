# ARGUS v0.1.0 — Production deployment on Rocky 8 / RHEL 8

This is the runbook for putting ARGUS on a real HPC cluster. It assumes
you're a Linux ops engineer comfortable with systemd, RPMs, and
either an existing Prometheus stack or Zabbix.

If you just want to evaluate ARGUS, see `README.md` for the mock-mode quick
start — none of this document is required for that.

## 1. Prerequisites

| Component               | Requirement                                                                      | Why                                                  |
| ----------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Linux kernel            | RHEL/Rocky/Alma 8.5+ stock (4.18 + backports), or upstream ≥ 5.4                  | BPF programs, kprobes, tracepoints                   |
| BTF                     | Best if present; ARGUS ships compiled-in fallbacks covering RHEL 8                | improves CO-RE accuracy, not strictly required       |
| InfiniBand stack        | `/sys/class/infiniband` populated (or skip live mode)                             | counter polling                                      |
| systemd                 | any version (RHEL 8's systemd 239 works with the default unit)                    | unit file                                            |
| chronyd / ntpd          | active and synced                                                                 | cross-node alert correlation                         |
| SELinux                 | Permissive *or* `argus-selinux` subpackage loaded                                 | Enforcing mode without the policy will block BPF     |
| firewalld               | port 9100/tcp allowed (or disabled on internal net)                               | Prometheus/Zabbix scrape path                        |

### RHEL 8 / Rocky 8 kernel matrix

RHEL 8 stock kernels report as `4.18.0` regardless of which point release
they came from. The backports for BPF features land at different RHEL
minor versions:

| RHEL/Rocky 8.x         | Kernel revision               | Status with default unit                          |
| ---------------------- | ----------------------------- | ------------------------------------------------- |
| 8.10 (current)         | `4.18.0-553.*`                | **Fully supported**                                |
| 8.5 — 8.9              | `4.18.0-348.*` — `4.18.0-513.*` | **Fully supported**                                |
| 8.4 and older          | `4.18.0-305.*` and earlier    | Best-effort; upgrade or install ELRepo kernel-ml   |
| Pre-RHEL-8 / non-EL    | any 4.18 without `.el8` tag   | Not validated; run in mock mode first              |

`argus-preflight` distinguishes these cases automatically. RHEL 9 / Rocky 9
(kernel 5.14.0) is fully supported by definition.

The systemd unit defaults to `CAP_SYS_ADMIN`, which works on every
supported configuration including stock RHEL 8 (whose systemd 239 does
not recognize the `CAP_BPF` capability name in unit files). On kernel
5.8+ outside the RHEL 8 family, the installers auto-activate the
`CAP_BPF` + `CAP_PERFMON` fine-grained drop-in at
`/etc/systemd/system/argusd.service.d/modern-caps.conf`.

For sites that want to push beyond 8.4:

```bash
sudo dnf install -y elrepo-release
sudo dnf install -y kernel-ml      # ELRepo mainline kernel; reboot to activate
```

For test-only sites with no IB hardware, `--mode mock` runs the full
detection pipeline on any kernel with no eBPF requirement.

## 2. Get the RPM

You can either **download the published RPM** (recommended — no
toolchain, no privileges) or **build it yourself** if your site
requires reproducible local builds.

### Option A: Download the published RPM

Every tagged release at <https://github.com/KevinWeiss1995/ARGUS/releases>
publishes signed RPMs and SHA-256 attestations.

```bash
TAG=v0.1.0
ARCH=x86_64
URL=https://github.com/KevinWeiss1995/ARGUS/releases/download/$TAG

# Fetch + verify
wget $URL/argus-${TAG#v}-1.el8.$ARCH.rpm \
     $URL/argus-${TAG#v}-1.el8.$ARCH.rpm.sha256
sha256sum -c argus-${TAG#v}-1.el8.$ARCH.rpm.sha256
```

The RPM is built by CI in the same Rocky 8 + pinned-toolchain container
that local Apptainer builds use, so it's bit-identical to what a
fakeroot-enabled site would produce locally.

### Option B: Build the RPM locally

Build paths in order of HPC suitability:

```bash
# Apptainer SIF (HPC default; needs fakeroot or admin-built SIF)
./scripts/build-rpm.sh --apptainer

# Spack (sites already using Lmod + Spack)
spack install argus +rpm

# Podman / Docker (sites with OCI runtime but not Apptainer)
./scripts/build-rpm.sh --container podman

# Bare-metal (only if Rust is OK installed system-wide)
sudo dnf install -y rpm-build rust cargo clang llvm openssl-devel pkg-config
just setup-ebpf
sudo ./scripts/build-rpm.sh
```

Full build comparison: [`docs/hpc-build.md`](hpc-build.md).

For SELinux Enforcing sites, all paths produce the optional
`argus-selinux` subpackage automatically when `selinux-policy-devel`
is available. For airgapped / repro builds, layer `--mock rocky-8-x86_64`
on top of any local-build path.

To sign the RPM (recommended for repo-deployed installs):

```bash
RPM_GPG_KEY_ID="ARGUS Build" sudo ./scripts/build-rpm.sh --sign
```

## 3. Deploy to a fleet

The Ansible playbook handles install, config, firewalld, service start,
and a verify pass. Setup is in `deploy/ansible/README.md`; the short
version:

```bash
cd deploy/ansible
cp inventory.example.ini inventory.ini
cp group_vars/all.yml.example group_vars/all.yml
$EDITOR group_vars/all.yml      # set argus_rpm_source and recipients
ansible-playbook -i inventory.ini argus.yml
```

Preflight runs first on every node. If any host FAILs, the whole play
aborts before installing anything destructive.

For one-off installs without Ansible:

```bash
# Copy the RPM to the node, then:
sudo dnf install -y /tmp/argus-0.1.0-1.x86_64.rpm
sudo dnf install -y /tmp/argus-selinux-0.1.0-1.noarch.rpm   # optional
sudo argus-preflight
sudo systemctl enable --now argusd
curl localhost:9100/health
```

## 4. Wire up monitoring

### Existing Prometheus

Add a scrape job:

```yaml
scrape_configs:
  - job_name: argus
    scrape_interval: 5s
    static_configs:
      - targets:
          - node01.cluster.example.org:9100
          - node02.cluster.example.org:9100
```

For dynamic discovery across a subnet, use `argus-discover` on the
monitoring host:

```bash
argus-discover --subnet 10.0.0.0/24 --output /etc/prometheus/argus-targets.json
```

Add alert rules from `deploy/observability/alert_rules.yml` to your
Prometheus rule_files. Add the dashboards in
`deploy/observability/grafana/dashboards/`.

### Standalone Prometheus + Grafana (turnkey)

```bash
cd deploy/observability
./scripts/start-observability.sh
```

This brings up Prometheus on :9091, Grafana on :3000 (admin/admin), and
Alertmanager on :9093. See `docs/email-setup.md` to point Alertmanager at
your SMTP relay.

### Zabbix

Import `deploy/zabbix/argus_template.yaml` and link it to your HPC host
group. See `docs/zabbix-integration.md` for macros, triggers, and TLS.

## 5. Configuration cookbook

Defaults are in `/etc/argus/argusd.conf` (env-style, sourced by systemd) and
`/etc/argus/argusd.toml` (extended config, optional). The .conf overrides
the .toml. See `argusd --help` for the full flag list.

### Bind only to localhost

```ini
# /etc/argus/argusd.conf
ARGUS_METRICS_ADDR=127.0.0.1:9100
```

Useful when each node is scraped via SSH tunnel or stunnel.

### Bearer token + TLS

```toml
# /etc/argus/argusd.toml
[tls]
cert = "/etc/argus/tls/server.crt"
key  = "/etc/argus/tls/server.key"

[auth]
bearer_token_file = "/etc/argus/token"
```

```bash
echo "your-long-random-string" > /etc/argus/token
chmod 600 /etc/argus/token
```

Reload TLS without restart by `kill -HUP <pid>` (or
`systemctl reload argusd`).

### SLURM drain on Critical

```toml
[scheduler]
backend = "slurm"
dry_run = true                      # ALWAYS start with dry_run for a new fleet
drain_on_degraded = false
resume_cooldown_secs = 300
```

`scontrol` must be in `$PATH` and the service must be able to talk to
the controller. Watch the journal for `scheduler.action=drain_node`
log lines before flipping `dry_run = false`.

### Per-fabric tuning

```toml
[detection.profile.softroce]
irq_skew_threshold_pct = 85.0
rdma_spike_factor = 4.0
```

The fabric is auto-detected at startup; the matching profile is applied
on top of the base `[detection]` block.

## 6. Upgrade procedure

```bash
# Build / push the new RPM, then on each node:
sudo dnf upgrade -y argus argus-selinux
sudo systemctl restart argusd
sudo argus-preflight        # sanity check post-upgrade
curl localhost:9100/health
```

For an Ansible-managed fleet, the install role's handler restarts argusd
automatically when the binary or config changes.

The configuration files are tagged `%config(noreplace)` in the RPM, so
your `/etc/argus/argusd.conf` is preserved. The new defaults arrive as
`*.rpmnew` if they changed.

## 7. Rollback

```bash
sudo dnf downgrade argus argus-selinux       # if the previous RPM is still in the repo
# or
sudo rpm -Uvh --oldpackage argus-0.0.x-1.x86_64.rpm
sudo systemctl restart argusd
```

Persistent state in `/var/lib/argus` is compatible across the 0.0.x → 0.1.0
boundary — no migration step is required.

## 8. Failure modes

| Symptom                                       | First thing to check                              |
| --------------------------------------------- | ------------------------------------------------- |
| `systemctl status argusd` shows "failed"      | `journalctl -u argusd -e` for the panic line     |
| `/health` returns 503 or timeout              | `argus-preflight`, then firewalld and SELinux    |
| All nodes Healthy but no IB metrics           | `/sys/class/infiniband` empty? IB driver loaded? |
| Metric values frozen                          | Aggregator stuck — `argus-status --watch`         |
| `bpf_prog_load(...): Operation not permitted` | systemd unit didn't grant CAP_SYS_ADMIN (or CAP_BPF if you switched to the modern-caps drop-in) |
| SELinux denials in audit.log                  | See `docs/troubleshooting.md`                    |

See `docs/troubleshooting.md` for the full playbook.

## 9. Capacity planning

A single argusd uses:

- ≤ 5% of one CPU under default `window_secs=3` (systemd `CPUQuota=5%`)
- ≤ 256 MB RSS (`MemoryMax=256M`)
- ~50 KB/s outbound during Prometheus scrape (5s interval)

Per-fleet, Prometheus storage at 5s intervals is ~1.2 MB/node/day with
the shipped retention. Plan ~500 MB for 90 days of 1000 nodes.

Alertmanager and Grafana have no per-node footprint; one monitoring
host is enough for clusters up to a few thousand nodes.

# ARGUS v0.1.0 — Production deployment on Rocky 8 / RHEL 8

This is the runbook for putting ARGUS on a real HPC cluster. It assumes
you're a Linux ops engineer comfortable with systemd, RPMs, and
either an existing Prometheus stack or Zabbix.

If you just want to evaluate ARGUS, see `README.md` for the mock-mode quick
start — none of this document is required for that.

## 1. Prerequisites

| Component               | Requirement                                       | Why                                                  |
| ----------------------- | ------------------------------------------------- | ---------------------------------------------------- |
| Linux kernel            | ≥ 5.4 (5.8+ recommended)                          | CAP_BPF + BTF for CO-RE eBPF                          |
| BTF                     | `/sys/kernel/btf/vmlinux` readable                | required for CO-RE eBPF                              |
| InfiniBand stack        | `/sys/class/infiniband` populated (or skip live)  | counter polling                                      |
| systemd                 | any modern version                                | unit file                                            |
| chronyd / ntpd          | active and synced                                 | cross-node alert correlation                         |
| SELinux                 | Permissive *or* `argus-selinux` subpackage loaded | enforcing mode without the policy will block BPF    |
| firewalld               | port 9100/tcp allowed (or disabled on internal net) | Prometheus/Zabbix scrape path                        |

Rocky 8 ships with kernel 4.18. **You need a newer kernel.** Options:

- Install ELRepo kernel-ml (recommended): `dnf install -y elrepo-release && dnf install -y kernel-ml`.
- Use a RHEL 8.4+ kernel with backported BPF (subset of features only — preflight will warn).
- For test-only sites: run ARGUS in mock/replay mode, which has no kernel requirement.

## 2. Build the RPM

On any Rocky 8 build host with the Rust toolchain installed:

```bash
git clone https://github.com/KevinWeiss1995/ARGUS.git
cd ARGUS
sudo dnf install -y rpm-build rust cargo clang llvm openssl-devel pkg-config
just setup-ebpf                          # nightly + bpf-linker
sudo ./scripts/build-rpm.sh              # produces ~/rpmbuild/RPMS/$arch/argus-0.1.0-1.*.rpm
```

For SELinux Enforcing sites, also build `deploy/selinux/argus.pp` first
so the `argus-selinux` subpackage gets bundled:

```bash
sudo dnf install -y selinux-policy-devel policycoreutils-python-utils
make -C deploy/selinux
sudo ./scripts/build-rpm.sh
```

For airgapped / repro builds, use mock:

```bash
sudo ./scripts/build-rpm.sh --mock rocky-8-x86_64
```

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
| `bpf_prog_load(...): Operation not permitted` | Kernel <5.8 without CAP_SYS_ADMIN fallback        |
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

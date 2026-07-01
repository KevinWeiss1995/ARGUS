# Troubleshooting ARGUS

When argusd misbehaves, work through these checks in order. Most production
problems fall into one of three buckets:

1. **The agent isn't running** — systemd unit failure, missing binaries.
2. **The agent is running but not collecting data** — eBPF load failure,
   SELinux denials, missing kernel features.
3. **Data is flowing but values look wrong** — config drift, fabric
   misdetection, scheduler dry-run flag stuck.

Run `argus-preflight` first. If it FAILs anything, fix that first.

## 1. Is argusd running?

```bash
systemctl status argusd
journalctl -u argusd -e --no-pager | tail -50
```

If the unit is in `failed` state, the journal usually has the panic
location. Common causes:

- **eBPF artifact not found.** `ARGUS_EBPF_PATH=/usr/lib/argus/argus-ebpf`
  in `/etc/argus/argusd.conf` is the default; if the file is missing the
  RPM didn't install correctly.
- **eBPF hash mismatch.** The RPM's `%post` writes
  `/etc/argus/ebpf.sha256`. If it disagrees with the binary, argusd
  refuses to load. Re-install or delete the hash file to disable check.
- **PID lock.** Only one argusd may run per node. If a previous instance
  crashed without releasing `/var/run/argus/argusd.pid`, the new one
  refuses to start. `rm` it and try again.

## 2. Can I reach /health?

```bash
curl -i http://127.0.0.1:9100/health
```

- **`Connection refused`** — argusd isn't running or isn't listening on
  that port. `ss -tlnp | grep 9100` to confirm.
- **`401 Unauthorized`** — auth_token is set; pass `-H "Authorization:
  Bearer $(cat /etc/argus/token)"`.
- **TLS handshake errors** — you configured `[tls]` but Prometheus /
  Zabbix isn't sending HTTPS. Either drop TLS or fix the scraper.

If `/health` works from the node but not from Prometheus:

```bash
# On the scraper host:
curl -v http://node07:9100/health
```

If this fails, it's firewalld. On the node:

```bash
firewall-cmd --zone=public --add-port=9100/tcp --permanent
firewall-cmd --reload
```

## 3. ARGUS_NODE_DEGRADED — what triggered it?

```bash
# Quickest read: argus-status with watch
argus-status --watch

# Or pull the recent alerts directly:
curl -s http://127.0.0.1:9100/status | python3 -m json.tool | less
```

The `recent_alerts` array carries up to 100 recent alerts with their
`kind_name` (the rule), `severity`, and `message`. Cross-reference with
Grafana's "Node detail" dashboard to see which underlying signal pushed
the score up.

Most common DEGRADED causes on a healthy-but-bursty cluster:

- **Interrupt skew** during NUMA-pinned IB jobs. Tune
  `[detection] irq_skew_threshold_pct` higher in
  `/etc/argus/argusd.toml`.
- **CQ jitter** on a node sharing IB with disk I/O. Usually transient;
  if persistent, suspect a saturated NIC or PCIe lane.
- **NAPI saturation** on networking-heavy nodes. The default 70%
  threshold is conservative; sites with sustained 80%+ utilization
  should raise it.

## 4. argusd is up but Prometheus shows no IB metrics

```bash
ls /sys/class/infiniband/
```

If empty, no IB driver is loaded. `lsmod | grep -E 'mlx5|hfi1|rxe|siw'`
to check. ARGUS will run without IB; it just won't have the per-port
gauges.

If `/sys/class/infiniband/` has devices but `/metrics` lacks
`argus_ib_*` lines, check whether argusd has CAP_DAC_READ_SEARCH (needed
to read counter files on restrictively-mounted sysfs):

```bash
journalctl -u argusd -e | grep -i 'permission denied'
getcap /usr/bin/argusd
```

The systemd unit grants `CAP_DAC_READ_SEARCH` ambient — if you've
overridden the unit, restore that line.

## 5. SELinux denials

```bash
ausearch -m AVC -ts recent | head -20
```

If the source context is `argusd_t`, the policy module is missing a rule.
Generate the diff:

```bash
ausearch -m AVC -ts recent | audit2allow -R
```

Either:

- Install the latest `argus-selinux` package (most denials come from
  drift between the kernel surface and the shipped policy), or
- File an issue with the audit2allow output and the kernel version, or
- Switch to Permissive temporarily: `setenforce 0`.

## 6. Scheduler stuck in dry-run

A common gotcha after first-pass deployment:

```bash
grep -E "scheduler" /etc/argus/argusd.{conf,toml}
```

If `ARGUS_SCHEDULER_DRY_RUN=true` or `dry_run = true`, argusd logs
`[DRY RUN] would drain node` but never executes. This is the
recommended initial state for a new fleet — once you've watched several
state transitions and decided you trust the integration, flip to
`false` and restart.

## 7. Counters look frozen

If the same Prometheus values come back from several scrapes in a row:

```bash
# Check that argusd is actually advancing windows:
curl -s http://127.0.0.1:9100/health | jq .last_window_ts
sleep 5
curl -s http://127.0.0.1:9100/health | jq .last_window_ts
# Two readings ~5s apart should differ
```

If they don't:

- **eBPF map read failure.** journalctl will show repeated
  `failed to read BPF map` warnings — usually means the kernel BPF
  subsystem is in a degraded state. Reboot is the fix.
- **The pipeline is wedged.** Take a core dump:
  `gcore $(pidof argusd)` and file an issue.

## 8. IB fabric idle alert when traffic should be flowing

`ArgusFabricIdleSanityCheck` (info-severity) means no IB throughput was
observed for >24h. This is informational — passive monitoring of
symbol errors, link recovery, and link_downed continues. Suppress on
idle-by-design clusters (academic, batch-only).

If the fabric *should* have traffic and this alert fires:

```bash
# Confirm on the node:
ibstat | grep -i state
cat /sys/class/infiniband/mlx5_0/ports/1/state
# State should be "ACTIVE"; if it says "DOWN" or "INIT", the link is
# physically up but no QPs are bound — fabric is reachable for error
# counters but no workload is using it.

# Look at the throughput counter directly:
cat /sys/class/infiniband/mlx5_0/ports/1/counters/port_xmit_data
```

If `port_xmit_data` never increments, no application is sending — that's
your real diagnostic, not ARGUS.

## 9. Upgrade leaves argusd in a weird state

```bash
systemctl daemon-reload
systemctl restart argusd
argus-preflight                       # post-upgrade sanity
journalctl -u argusd --since "5 min ago"
```

If the journal shows `eBPF artifact hash mismatch`, the RPM updated the
binary but not the hash file. Re-run the post-install scriptlet:

```bash
sha256sum /usr/lib/argus/argus-ebpf | awk '{print $1}' > /etc/argus/ebpf.sha256
systemctl restart argusd
```

## 10. RHEL 8 / Rocky 8 capability problems

If you see `Failed to set capabilities`, `Invalid capability "CAP_BPF"`, or
`Operation not permitted` from `bpf_prog_load`, the systemd unit and the
kernel disagree about which capability names exist.

```bash
# 1. Confirm what systemd thinks the unit asks for
systemctl show argusd | grep -E 'AmbientCapabilities|CapabilityBoundingSet'

# 2. Check whether the modern-caps drop-in is active
ls -la /etc/systemd/system/argusd.service.d/

# 3. Check the kernel and systemd versions
uname -r && systemctl --version | head -1
```

If you're on RHEL 8 / Rocky 8 (kernel `*.el8*`) and the drop-in is
present, **remove it** — RHEL 8's systemd 239 does not recognize
`CAP_BPF` in unit files even though the kernel itself supports CAP_BPF
syscalls:

```bash
sudo rm /etc/systemd/system/argusd.service.d/modern-caps.conf
sudo systemctl daemon-reload
sudo systemctl restart argusd
```

The default unit uses `CAP_SYS_ADMIN`, which works on RHEL 8 systemd 239
and grants every BPF-related kernel call ARGUS needs.

If you're on a non-RHEL-8 distro with kernel < 5.8, you also want the
default `CAP_SYS_ADMIN` unit — same fix as above.

To explicitly opt in to fine-grained caps on a non-RHEL-8 host with
kernel >= 5.8:

```bash
sudo install -m 0644 /usr/share/argus/systemd/modern-caps.conf \
    /etc/systemd/system/argusd.service.d/modern-caps.conf
sudo systemctl daemon-reload
sudo systemctl restart argusd
journalctl -u argusd -n 20 | grep "effective capabilities"
# Should show: cap_bpf, cap_perfmon, cap_dac_read_search, cap_syslog
```

## 11. Alert runbook anchors

The shipped Prometheus alert rules link to the sections below by name.

### ArgusNodeDegraded

`argus_health_state == 1` held for 30s. Start with section 3 above —
`argus-status --watch` on the node, then the Node Detail dashboard to
see which rule is firing. Most degraded states with no IB error deltas
are host-side (IRQ skew, NAPI saturation, slab pressure).

### ArgusNodeCritical

`argus_health_state == 2` held for 15s. If scheduler integration is
enabled the node is being drained — check `argus-scheduler status` on
the node. Inspect `argus_ib_link_downed_delta` and
`argus_ib_link_error_recovery_delta`; non-zero values mean a physical
layer problem (cable/optic/switch port), not a tuning problem.

### ArgusNodeRecovering

`argus_health_state == 3`. The node exited Critical and is in the
recovery dwell; ARGUS resumes it (if scheduler-managed) only after the
dwell completes. No action needed unless the node oscillates between
Critical and Recovering — oscillation means the underlying fault is
intermittent, which for IB links almost always means a marginal cable
seating or optic. Treat a flapping node as Critical and drain it
manually: `argus-scheduler hold`.

## 12. None of the above

```bash
# Collect a bundle for support:
mkdir /tmp/argus-debug
journalctl -u argusd --since "1 hour ago" > /tmp/argus-debug/journal.log
cp /etc/argus/argusd.{conf,toml} /tmp/argus-debug/
argus-preflight --json > /tmp/argus-debug/preflight.json
curl -s http://127.0.0.1:9100/metrics > /tmp/argus-debug/metrics.txt
curl -s http://127.0.0.1:9100/status > /tmp/argus-debug/status.json
curl -s http://127.0.0.1:9100/coverage > /tmp/argus-debug/coverage.json
uname -a > /tmp/argus-debug/uname.txt
ibstat > /tmp/argus-debug/ibstat.txt 2>&1
ausearch -m AVC -ts recent > /tmp/argus-debug/avc.log 2>&1
tar -czf /tmp/argus-debug.tar.gz -C /tmp argus-debug
```

Attach `/tmp/argus-debug.tar.gz` to a new GitHub issue.

# Changelog

All notable changes are recorded here. Versions follow semver.

## [0.1.0] — 2026-05-22 (slow-degradation detection)

### Added — Mellanox mlx5 extended counters (Fix A)

Eleven new IB hardware counters are now read on every window from
`/sys/class/infiniband/<mlx5_*>/ports/<n>/hw_counters/`. These are
the slow-degradation indicators NVIDIA / OFED documentation flags
as primary for marginal-link diagnosis on Mellanox hardware:

  local_ack_timeout_err     packet_seq_err
  implied_nak_seq_err       out_of_buffer
  out_of_sequence           req_cqe_error
  resp_cqe_error            roce_adp_retrans
  roce_slow_restart         np_cnp_sent
  rp_cnp_handled

Each emits a per-port `argus_ib_mlx5_<counter>_delta{device,port}`
Prometheus gauge. Aggregate convenience methods on `IbCounterDeltas`:
`mlx5_slow_degradation_signal()` (sum of the four "creep" counters)
and `mlx5_cqe_error_total()` (RDMA work-request error sum).

### Added — Absolute counter values for long-window slope analysis (Fix B)

`HwCounterReader` now caches the latest absolute (cumulative since
boot) value of every counter it reads, exposed via `absolute_counters()`.
The Prometheus exporter publishes them as `argus_ib_counter_total{device,
port,counter}`. External Prometheus queries can now compute:

    rate(argus_ib_counter_total{counter="symbol_error_count"}[24h]) > N

which is the 24-72h slow-creep detection pattern documented by
El-Sayed & Schroeder (DSN 2013, "Reading between the lines of
failure logs") and used by NVIDIA UFM's Health Score. Previously
only per-window deltas were exposed, making long-window trend
analysis impossible.

### Added — Long-window slow-degradation detection rule (Fix C)

New `SlowDegradationRule` (`detection/rules.rs`) maintains a rolling
window of ~1200 samples (≈1 hour at 3s/window) over two signals:

  - Aggregate Mellanox slow-degradation counter (local_ack_timeout
    + packet_seq_err + implied_nak_seq_err + roce_adp_retrans)
  - Standard IB `symbol_error_count` delta

Fires DEGRADED — not CRITICAL — when the rolling mean stays above
the noise threshold for the full window. This is "schedule a
maintenance window," not "drain now." Catastrophic events still
trigger CRITICAL via the other rules.

Memory cost: ~10 KB per rule instance. Cooldown of 1200 windows
between repeat fires prevents alert flooding from sustained
degradation.

### Added — Host-side NIC health (Fix D + E)

New `sources/nic_health.rs` module reads two signals invisible to
IB counters:

  - **PCIe lane state**: compares `current_link_width` vs
    `max_link_width` and `current_link_speed` vs `max_link_speed`
    from `/sys/bus/pci/devices/<bdf>/`. Catches NIC slot, contact,
    or thermal throttling that downgrades the host-NIC bus without
    breaking IB. Exposed as `argus_nic_pcie_current_link_width`,
    `argus_nic_pcie_max_link_width`, `argus_nic_pcie_degraded`.

  - **NIC thermal**: walks `/sys/class/hwmon/*` to find the temp1
    sensor linked to each IB device's PCI parent. Mellanox NICs
    always expose this. Sustained >75°C predicts hardware failure
    hours-to-days in advance per NVIDIA field data. Exposed as
    `argus_nic_temperature_celsius{device}`.

### Changed — ebpf bootstrap logging downgraded INFO → DEBUG

The first-three-windows diagnostic logs in `sources/ebpf.rs`
(`IRQ_COUNTS raw per-cpu values`, `SLAB_STATS summed totals`) were
emitting at INFO. On 80-CPU nodes the IRQ log dumps an 80-element
vector per restart — way too noisy for production. Now DEBUG; set
`ARGUS_LOG_LEVEL=debug` to investigate cold-start behavior.



### Added — operator visibility for "is monitoring alive?"

The cpu164 deployment showed all-zero IB error deltas, which was
correct behaviour on a healthy idle link but indistinguishable from
"sysfs reader is broken." Adding direct evidence the polling loop
is running:

- `argus_hw_counter_polls_total{device,port}` — counter that
  increments once per window per polled IB port. If this stays flat
  across multiple Prometheus scrapes, polling really is broken.
  If it climbs, polling is alive and zero deltas are the truth.
- `argus_hw_counter_last_read_unix_seconds{device,port}` — wall-clock
  timestamp of the most recent sysfs read. `time() - this` is the
  freshness of the counter data.

### Changed — detection rules tightened (false-positive prevention)

Same shape as the ThroughputDropRule fix earlier in this release:
single-signal CRITICAL/DEGRADED firings replaced with stronger gates.

- **`SlabPressureRule`** now requires HARD IB errors (symbol,
  link_downed, link_error_recovery, integrity, remote_physical,
  buffer_overrun) instead of any error. Previously a single soft RoCE
  error coinciding with a slab spike fired DEGRADED. New behaviour
  ignores soft errors and port_rcv/xmit_discards as triggers — those
  are workload-dependent noise.
- **`RisingErrorTrendRule`** now requires both the monotonic-rise
  criterion AND a magnitude floor (`min_magnitude`, default 10).
  Previously a 1 → 2 → 3 rise was enough to fire DEGRADED. The
  consecutive-windows logic catches the trend but doesn't tell you
  whether the absolute count is actionable.

### Changed — systemd unit cleanup for Rocky 8

Moved `ProtectKernelLogs` (systemd 244+), `ProtectClock` (245+),
`ProtectHostname` (241+), and `ProtectProc` (247+) out of the default
unit and into a separately-shipped drop-in at
`/usr/share/argus/systemd/hardening-modern.conf`. Rocky 8 ships
systemd 239 which parses these as "Unknown lvalue" and emits warnings
on every daemon-reload. Sites on modern systemd opt in by copying the
drop-in into `/etc/systemd/system/argusd.service.d/`.

### Added — scheduler audit log rotation

`/etc/logrotate.d/argus` now shipped with the RPM. Weekly rotation,
12 generations kept, 50 MB max per file, gzipped after rotation.
Uses `copytruncate` so argusd doesn't need to handle SIGHUP-style
log rotation. Previously the audit log grew unbounded.



### Changed — ThroughputDropRule requires corroborating impairment signal

**Bug:** the rule fired CRITICAL on any ≥80% drop from EWMA baseline,
regardless of context. On the user-reported `cpu164` (academic HPC
node, idle between jobs), the rule fired immediately after each
workload finished because throughput went from ~161 to 0 with no
hard errors, no link events, nothing else wrong with the node.

This is the classic single-signal failure-detector anti-pattern
documented in network-monitoring research (Mahimkar et al. SIGCOMM
2009; Bertier et al. DSN 2002; Google SRE book §6).

**Fix:** the rule now requires at least one corroborating impairment
signal in the same window before firing at all:

- any hard IB error counter incremented (`total_hard_error_delta > 0`)
- `link_error_recovery_delta > 0` (the cable-failure predictor)
- `link_downed_delta > 0` (link physically down)
- `port_xmit_wait_delta > 0` (credit stall / upstream congestion)
- `cq_jitter.stall_count > 0` (driver or NIC stuck)

Without corroboration the rule stays silent — other rules
(`RdmaLinkDegradationRule`, `RisingErrorTrendRule`, `CqJitterRule`,
etc.) still catch actual-impairment cases independently.

The alert message now cites the specific corroborating counters so
operators can immediately see WHY the rule fired, not just THAT it
fired.

Five new unit tests cover the four corroboration paths, the
quiet-idle case, and the partial-drop+corroboration → Degraded
case. Tested via `cargo test detection::rules`.

### Fixed — eBPF artifact installed to wrong path on x86_64 (libdir mismatch)

`packaging/argus.spec` installed the eBPF object to `%{_libdir}/argus/`
which on x86_64 RHEL/Rocky is `/usr/lib64/argus/`. The shipped
`/etc/argus/argusd.conf` hardcoded `ARGUS_EBPF_PATH=/usr/lib/argus/argus-ebpf`,
so argusd looked in the wrong place and crash-looped with
`Error: eBPF artifact not found: /usr/lib/argus/argus-ebpf`.

eBPF objects target `bpfel-unknown-none` and are not host-CPU-specific,
so `/usr/lib/argus/` is the correct location regardless of arch.
Spec now installs there explicitly; install.sh already used the same
path. Existing installs can patch the conf to point at the actual
location (`sed -i 's|/usr/lib/argus/argus-ebpf|/usr/lib64/argus/argus-ebpf|'
/etc/argus/argusd.conf`) until they upgrade to a new RPM build.



### Changed — SELinux is now opt-in post-install (no separate RPM)

The argus-selinux subpackage is **removed**. The policy source files
(argus.te / .fc / .if) still ship — they now install into the main
argus RPM at `/usr/share/argus/selinux/`. Loading the policy is a
deliberate post-install step:

    sudo argus-selinux-enable           # build + load + relabel
    sudo argus-selinux-enable --status  # check
    sudo argus-selinux-enable --disable # unload

Rationale: mirrors ARGUS's SLURM pattern. The integration code is
always shipped, but enabling it is a site decision. Imposing a
selinux-policy-base `Requires:` (as the old subpackage did) caused
real damage on hosts running SELinux Disabled — dnf pulled in
~13 MB of selinux-policy-minimum that the host couldn't use, plus
rpm-plugin-selinux which then wedged every subsequent dnf transaction.

Net effect for sites:

  - SELinux Disabled  → install argus, done. No SELinux touched.
  - SELinux Permissive → install argus, optionally run argus-selinux-enable.
  - SELinux Enforcing  → install argus + dnf install selinux-policy-devel,
    then argus-selinux-enable. Same outcome as the old subpackage but
    without the dnf cascade surprises.

The Ansible install role now drives argus-selinux-enable behind
`argus_install_selinux: true` instead of installing a second RPM.



### Added — Pre-built RPM via GitHub release

- `.github/workflows/release.yml` builds a Rocky 8 RPM (and the
  optional argus-selinux subpackage) inside the same toolchain
  container local builds use, then attaches the RPMs and SHA-256
  attestations to the GitHub release for the tag that was pushed.
  Triggers on `v*.*.*` tags and on manual workflow_dispatch.
- Workflow also pushes the build container to
  `ghcr.io/<owner>/argus-build:<tag>` so sites that DO want
  reproducible local builds can `apptainer pull` it instead of
  running `apptainer build --fakeroot` (which is disabled at most
  HPC sites).
- Release notes now include the exact `dnf install -y <url>` one-liner
  the operator can paste, plus the SHA-256 verification command.
- README and the production runbook lead with "Path 0 — install the
  published RPM" so sites that can't / don't want to build locally
  get the fastest path first.

### Added — HPC-friendly build paths (no bare-metal toolchain)

- **Apptainer build container.** `deploy/container/argus-build.def`
  defines a Rocky 8 SIF with pinned Rust 1.83 + nightly 2025-01-15 +
  bpf-linker 0.9.13 + LLVM 17. Build host needs only `apptainer`;
  nothing else gets installed bare-metal. Rootless via `--fakeroot`.
- **Podman / Docker fallback.**
  `deploy/container/Containerfile.build` produces an equivalent image
  for sites that have a container runtime but not Apptainer.
- **Spack package + environment.** `deploy/spack/packages/argus/package.py`
  and `deploy/spack/spack.yaml` let Spack-managed sites get build deps
  as Lmod modules and optionally install ARGUS itself via Spack.
- **`scripts/build-rpm.sh --apptainer / --container [podman|docker]`** —
  one-command wrapper that builds the image if missing, runs the build,
  and drops RPMs into `./out/`.
- **`docs/hpc-build.md`** — guide comparing Apptainer / Spack /
  Podman / bare-metal build paths and when to use each.

### Added — RHEL 8 / Rocky 8 first-class support

- Default systemd unit now grants `CAP_SYS_ADMIN` (the only cap RHEL 8
  systemd 239 reliably understands for BPF access). This works
  unchanged on RHEL 8.5+ stock kernels (kernel `4.18.0-348.*` and
  later — including the user-reported `4.18.0-553.89.1.el8_10`) as
  well as on modern kernels.
- Fine-grained `CAP_BPF` + `CAP_PERFMON` drop-in shipped separately at
  `/usr/share/argus/systemd/modern-caps.conf` and auto-activated by
  the install scripts on non-RHEL-8 hosts running kernel ≥ 5.8.
  Ansible exposes the same logic via `argus_force_modern_caps`.
- `argus-agent/src/security.rs::drop_privileges` now keeps whichever
  of `{CAP_BPF, CAP_SYS_ADMIN}` is actually held, plus
  `CAP_DAC_READ_SEARCH`, `CAP_PERFMON`, `CAP_SYSLOG` when present.
  Previous behaviour kept only `CAP_BPF` — on RHEL 8 stock where the
  unit holds `CAP_SYS_ADMIN`, that stranded the agent with no caps
  after init, breaking ongoing BPF map reads.
- `scripts/argus-preflight` now distinguishes RHEL 8.5+ (`.el8` +
  kernel revision ≥ 348) as OK, RHEL 8.4 and older as WARN with
  remediation, and RHEL 9 as OK. The previous policy of marking 4.18
  as FAIL was wrong.
- `scripts/argus-preflight` downgrades the BTF-missing check from
  FAIL to WARN — the agent ships compiled-in struct offsets covering
  RHEL 8 in `argus-agent/src/sources/kallsyms.rs`, so BTF improves
  CO-RE accuracy but is not strictly required.
- SELinux policy now includes `sys_admin` in the capability class so
  the fallback path works under Enforcing mode.
- RPM spec drops the bogus `Requires: kernel >= 5.4` line and stages
  the modern-caps drop-in under `/usr/share/argus/systemd/`.

### Notes for upgrades from prior 0.1.0 builds

- After upgrading, restart argusd. Existing hosts running pre-fix
  builds may have leaked privileges (kept fewer caps than they should
  have). The new drop_privileges path logs the keep-list explicitly
  in the journal; check with:
  `journalctl -u argusd | grep "post-drop keep-list"`

## [0.1.0-rc1] — 2026-05-20

First production release. Target environment is Rocky Linux 8 / RHEL 8 HPC
clusters running InfiniBand, RoCEv2, or Soft-RoCE fabrics.

### Added — agent

- **IB fabric idle visibility.** New per-port idle tracker surfaces
  `argus_ib_port_idle_seconds{device,port}`, `argus_ib_fabric_idle`, and
  `argus_ib_max_idle_seconds` gauges. The TUI header gains an "IB: passive
  (Ns idle)" indicator. Hardware error counters keep firing regardless of
  idle state — passive monitoring of an idle link is still real monitoring.
- New `IbPortIdle` struct on `AggregatedMetrics` and `StatusSnapshot` so
  `/status` carries the per-port idle list to TUI attach clients.

### Added — deployment

- `scripts/argus-preflight` — Rocky 8 readiness checker (kernel, BTF, IB
  stack, SELinux, firewalld, NTP, capabilities). Outputs human-readable
  or `--json`.
- `scripts/build-rpm.sh` — wraps cargo + rpmbuild, with optional `--mock`
  chroot build and `--sign` GPG signing.
- `deploy/selinux/` — argus.te / .fc / .if policy module plus Makefile.
  Loaded by the optional `argus-selinux` RPM subpackage; supports
  SELinux Enforcing on Rocky 8.
- `deploy/ansible/` — bootstrap playbook (preflight, install, firewalld,
  service, verify roles) with example inventory + group_vars. Idempotent
  and tag-runnable.
- `packaging/argus.spec` updated for Rocky 8: `Requires: kernel >= 5.4`,
  `chrony`, optional `argus-selinux` subpackage with its own `%post` that
  loads the policy module and relabels installed paths.

### Added — observability

- Alertmanager `email_configs` template with critical/digest routing,
  per-severity inhibits, and SMTP relay knobs.
- Alert rules grew `summary`/`description`/`runbook` annotations so email
  bodies render usefully.
- New informational `ArgusFabricIdleSanityCheck` rule (idle >24h).
- `deploy/observability/templates/email.tmpl` — Go template for
  subject + plain-text + HTML email bodies, color-coded by severity.
- `deploy/zabbix/argus_template.yaml` — Zabbix 6.x/7.x HTTP-agent
  template with per-port discovery, triggers, and value maps. No
  zabbix_agentd shim required.

### Added — docs

- `docs/production-deployment.md` — operator runbook (prereqs,
  install paths, config cookbook, upgrade, rollback, failure modes).
- `docs/troubleshooting.md` — first-ten-things-to-check for argusd
  triage.
- `docs/email-setup.md` — SMTP relay configuration walkthrough.
- `docs/zabbix-integration.md` — site-admin guide.

### Changed

- `Pipeline::finalize_idle_window` is the new per-window hook the main
  loop calls between `evaluate()` and `reset_window()` so idle state
  rides along into the snapshot.
- `install.sh` calls `argus-preflight` upfront and installs the
  SELinux module when present.

### Notes for upgrades

- This is the first tagged release; there is no upgrade path to define.
- The `AggregatedMetrics` JSON gained the optional `ib_port_idle` field
  (`#[serde(default)]`), so existing replay scenario files load without
  modification.

# Changelog

All notable changes are recorded here. Versions follow semver.

## [0.1.0] — 2026-05-21

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

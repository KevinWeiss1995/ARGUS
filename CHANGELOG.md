# Changelog

All notable changes are recorded here. Versions follow semver.

## [0.1.0] — 2026-05-20

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

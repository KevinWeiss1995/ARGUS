# ARGUS SELinux policy module

This directory contains the policy source for an `argusd` SELinux module that
lets the agent run under Rocky 8 / RHEL 8 with SELinux in **Enforcing** mode.

ARGUS works without this module if your site runs SELinux in Permissive or
Disabled. It is shipped as a separate artifact (and an optional `argus-selinux`
RPM subpackage) so sites can opt in.

## Build & install

```bash
# On the target host (Rocky 8 / RHEL 8):
sudo dnf install -y selinux-policy-devel policycoreutils-python-utils
make                  # produces argus.pp
sudo make reload      # installs and re-labels /usr/bin/argusd, /etc/argus, etc.
```

Verify:

```bash
semodule -l | grep argus           # expect: argus
ls -Z /usr/bin/argusd              # expect: argusd_exec_t
sesearch -A -s argusd_t | head     # human-readable summary
```

## What it grants

Briefly:

- `CAP_BPF`, `CAP_PERFMON`, `CAP_DAC_READ_SEARCH`
- BPF `prog_load`, `map_create`, `map_read`, `map_write`
- `perf_event_open()`
- Read `/proc/kallsyms`, `/sys/kernel/btf/*`, `/sys/class/infiniband/*`,
  `/sys/kernel/{tracing,debug/tracing}`
- Bind TCP port 9100 (label `argusd_port_t`)
- Read `/etc/argus/*`, write `/var/lib/argus/*` and `/run/argus/*`
- Connect to outbound TCP (webhooks, Alertmanager, scheduler endpoints)

It does **not** grant `CAP_NET_ADMIN` or write access to
`/sys/class/infiniband/*/admin_state` — port-disable is opt-in and requires
site-specific extension.

## When SELinux still denies you

If you see denials in `/var/log/audit/audit.log` after installing the module,
generate a diff:

```bash
ausearch -m AVC -ts recent | audit2allow -R
```

Then either extend `argus.te` with the new rules and rebuild, or file an issue
including the audit log lines.

## Uninstall

```bash
sudo semodule -r argus
sudo restorecon -RFv /usr/bin/argusd /etc/argus /var/lib/argus /run/argus
```

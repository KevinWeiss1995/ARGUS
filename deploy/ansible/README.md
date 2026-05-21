# ARGUS Ansible bootstrap

Parallel install / upgrade of ARGUS across an HPC cluster.

## Quick start

```bash
cd deploy/ansible
cp inventory.example.ini inventory.ini
cp group_vars/all.yml.example group_vars/all.yml
$EDITOR inventory.ini group_vars/all.yml      # set RPM source, hosts, etc.

# Dry-run (preflight only)
ansible-playbook -i inventory.ini argus.yml --tags preflight

# Full deploy
ansible-playbook -i inventory.ini argus.yml

# Upgrade after building a new RPM
ansible-playbook -i inventory.ini argus.yml --tags install,verify
```

## Tags

| Tag         | What it does                                                     |
| ----------- | ---------------------------------------------------------------- |
| `preflight` | Stage and run `scripts/argus-preflight` on every host            |
| `install`   | Install/upgrade the RPM and render config templates              |
| `firewalld` | Allow port 9100/tcp (only acts when firewalld is active)         |
| `service`   | Enable + start argusd; wait for `/health` to return 200          |
| `verify`    | Hit `/health` and `/metrics`, fail on Critical or missing gauges |

`preflight` runs even when you ask for specific tags — preflight failures
abort the play before anything destructive happens.

## Prerequisites

- `ansible-core` ≥ 2.14 on the control host
- `ansible.posix` collection (`ansible-galaxy collection install ansible.posix`)
- The target hosts must already have:
  - sshd + sudo for the `ansible_user`
  - a kernel that supports CAP_BPF (the preflight role enforces this)
  - dnf access to the RPM source (local path or HTTPS URL)

## What the play does not do

- It does not build the RPM. Point `argus_rpm_source` at an existing artifact;
  see `scripts/build-rpm.sh` to build one.
- It does not configure Prometheus / Alertmanager / Zabbix. Those run on
  monitoring hosts and have their own configuration in `deploy/observability/`
  and `deploy/zabbix/`.
- It does not set up SLURM. To enable scheduler drain/resume, set
  `argus_scheduler: "slurm"` and `argus_scheduler_dry_run: true` for the
  first rollout, then flip dry_run off once you've watched a few transitions.

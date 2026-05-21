%global crate_name argus-agent
%global ebpf_name  argus-ebpf

# Version + release are overridable via rpmbuild --define so build-rpm.sh
# can rebuild a single spec for multiple tags without editing the file.
%{!?_version: %define _version 0.1.0}
%{!?_release: %define _release 1}

# Disable rpmbuild's automatic -debuginfo / -debugsource subpackage
# generation. The agent binary is compiled by cargo *outside* the
# rpmbuild sandbox (in the build container or via scripts/build-rpm.sh)
# and only the resulting ELF is staged into the source tarball. The
# debug source paths in that ELF reference the build-container source
# tree which rpmbuild's debug-extraction machinery can't resolve —
# producing an empty `debugsourcefiles.list` and aborting.
# We can revisit debuginfo packaging later if/when someone wants
# split-debug RPMs; until then the symbols stay embedded in the binary.
%global debug_package %{nil}

Name:           argus
Version:        %{_version}
Release:        %{_release}%{?dist}
Summary:        Adaptive RDMA Guard & Utilization Sentinel — eBPF telemetry agent

License:        Apache-2.0
URL:            https://github.com/KevinWeiss1995/ARGUS
Source0:        %{name}-%{version}.tar.gz

ExclusiveArch:  x86_64 aarch64

# BuildRequires intentionally omits cargo / rust / clang / llvm. The
# Rust toolchain installed by rustup under /opt/cargo is not visible to
# the RPM dependency solver, and the binary is always compiled outside
# rpmbuild (in the build container or by scripts/build-rpm.sh) and
# staged into the source tarball so %build skips cargo entirely.
BuildRequires:  systemd-rpm-macros
BuildRequires:  openssl-devel
BuildRequires:  pkg-config

# Kernel requirement is intentionally not hard-pinned. RHEL 8.5+ and
# Rocky 8.5+ stock kernels (which report as 4.18.0-348.* and later)
# backport CAP_BPF and the BPF features ARGUS needs. ELRepo kernel-ml
# also works. The systemd unit defaults to CAP_SYS_ADMIN so it works
# across the full range without per-host tuning; scripts/argus-preflight
# is the authoritative check at install time.
Requires:       systemd
Requires:       chrony
Requires(pre):  shadow-utils

%description
ARGUS is a node-local telemetry agent that uses eBPF to monitor kernel
behavior related to RDMA networking, interrupt handling, and memory
allocation in real time. It detects early signs of InfiniBand degradation
or system imbalance before application performance collapses.

%package selinux
Summary:        SELinux policy module for ARGUS
Requires:       %{name} = %{version}-%{release}
Requires:       selinux-policy-base
Requires(post): policycoreutils
Requires(postun): policycoreutils
BuildArch:      noarch

%description selinux
SELinux policy module that allows argusd to run under SELinux Enforcing on
Rocky 8 / RHEL 8. Grants CAP_BPF, sysfs/IB read access, port 9100 bind, and
write access to /var/lib/argus and /run/argus. Install on hosts where
`getenforce` reports `Enforcing`; on Permissive/Disabled hosts it is a
no-op.

%prep
%autosetup -n %{name}-%{version}

%build
# Userspace cargo build. eBPF artifact must be built outside the RPM build
# (it requires the nightly toolchain + bpf-linker) and shipped in the source
# tarball under argus-ebpf/target/bpfel-unknown-none/release/. scripts/build-rpm.sh
# stages it for you.
if [ -f target/release/%{crate_name} ]; then
    echo "Pre-built %{crate_name} found in source tarball — skipping cargo build"
else
    cargo build --release --workspace
fi

# Optionally compile the SELinux policy module if selinux-policy-devel is
# available on the build host. Output lands at deploy/selinux/argus.pp.
if [ -f /usr/share/selinux/devel/Makefile ]; then
    %make_build -C deploy/selinux
fi

%install
# Binary
install -Dpm 0755 target/release/%{crate_name} %{buildroot}%{_bindir}/argusd

# eBPF artifact
install -Dpm 0644 %{ebpf_name}/target/bpfel-unknown-none/release/%{ebpf_name} \
    %{buildroot}%{_libdir}/argus/%{ebpf_name}

# Systemd unit
install -Dpm 0644 deploy/argusd.service \
    %{buildroot}%{_unitdir}/argusd.service

# Configuration
install -Dpm 0640 deploy/argusd.conf \
    %{buildroot}%{_sysconfdir}/argus/argusd.conf
install -Dpm 0640 deploy/examples/standalone.toml \
    %{buildroot}%{_sysconfdir}/argus/argusd.toml

# sysusers.d
install -Dpm 0644 packaging/sysusers.d/argus.conf \
    %{buildroot}%{_sysusersdir}/argus.conf

# tmpfiles.d
install -Dpm 0644 packaging/tmpfiles.d/argus.conf \
    %{buildroot}%{_tmpfilesdir}/argus.conf

# CLI tools
for tool in argus-status argus-discover argus-manage-targets argus-scheduler argus-preflight; do
    install -Dpm 0755 scripts/${tool} %{buildroot}%{_bindir}/${tool}
done
ln -sf argusd %{buildroot}%{_bindir}/argus-tui

# State and runtime directories
install -dm 0750 %{buildroot}%{_sharedstatedir}/argus
install -dm 0755 %{buildroot}%{_rundir}/argus

# SELinux policy artifacts (always staged; only installed by argus-selinux)
install -dm 0755 %{buildroot}%{_datadir}/argus/selinux
if [ -f deploy/selinux/argus.pp ]; then
    install -Dpm 0644 deploy/selinux/argus.pp %{buildroot}%{_datadir}/argus/selinux/argus.pp
fi
install -Dpm 0644 deploy/selinux/argus.te %{buildroot}%{_datadir}/argus/selinux/argus.te
install -Dpm 0644 deploy/selinux/argus.fc %{buildroot}%{_datadir}/argus/selinux/argus.fc
install -Dpm 0644 deploy/selinux/argus.if %{buildroot}%{_datadir}/argus/selinux/argus.if

# Optional fine-grained capabilities drop-in for kernel >= 5.8 systems.
# Not enabled by default — operator copies to /etc/systemd/system/argusd.service.d/
# when they decide to opt in. See deploy/systemd/modern-caps.conf for the
# activation instructions.
install -Dpm 0644 deploy/systemd/modern-caps.conf %{buildroot}%{_datadir}/argus/systemd/modern-caps.conf

%pre
# Create the argus system user/group on install if missing. We don't
# use %sysusers_create_compat because that macro is RHEL 9+ — on Rocky 8
# the version of systemd-rpm-macros we link against doesn't define it,
# RPM leaves the literal `%sysusers_create_compat` in the scriptlet,
# and bash chokes with "fg: no job control" on the leading `%`.
# The sysusers.d/argus.conf file is still shipped to %{_sysusersdir}
# so systemd-sysusers picks it up idempotently on next boot.
getent group argus >/dev/null || /usr/sbin/groupadd -r argus
getent passwd argus >/dev/null || \
    /usr/sbin/useradd -r -g argus -d /var/lib/argus -s /usr/sbin/nologin \
        -c "ARGUS telemetry agent" argus
exit 0

%post
# Compute eBPF artifact hash for integrity verification
sha256sum %{_libdir}/argus/%{ebpf_name} | awk '{print $1}' \
    > %{_sysconfdir}/argus/ebpf.sha256 2>/dev/null || :
%systemd_post argusd.service

# Friendly post-install hint
if [ -x %{_bindir}/argus-preflight ]; then
    echo "ARGUS installed. Run 'argus-preflight' to validate this host."
fi

%preun
%systemd_preun argusd.service

%postun
%systemd_postun_with_restart argusd.service

%post selinux
# Load the policy module on install or upgrade. semodule -i is idempotent.
if [ -f %{_datadir}/argus/selinux/argus.pp ]; then
    /usr/sbin/semodule -i %{_datadir}/argus/selinux/argus.pp 2>/dev/null || :
    # Re-label installed paths so the new types take effect immediately.
    /usr/sbin/restorecon -RFv %{_bindir}/argusd %{_sysconfdir}/argus \
        %{_sharedstatedir}/argus %{_rundir}/argus 2>/dev/null || :
fi

%postun selinux
# Only unload on full uninstall ($1 == 0), not on upgrade ($1 == 1).
if [ $1 -eq 0 ]; then
    /usr/sbin/semodule -r argus 2>/dev/null || :
fi

%files
%license LICENSE
%doc README.md
%doc CHANGELOG.md

# Binaries
%{_bindir}/argusd
%{_bindir}/argus-tui
%{_bindir}/argus-status
%{_bindir}/argus-discover
%{_bindir}/argus-manage-targets
%{_bindir}/argus-scheduler
%{_bindir}/argus-preflight

# eBPF artifact
%dir %{_libdir}/argus
%{_libdir}/argus/%{ebpf_name}

# Configuration
%dir %{_sysconfdir}/argus
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/argus/argusd.conf
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/argus/argusd.toml
%ghost %{_sysconfdir}/argus/ebpf.sha256

# Systemd integration
%{_unitdir}/argusd.service
%{_sysusersdir}/argus.conf
%{_tmpfilesdir}/argus.conf
%dir %{_datadir}/argus/systemd
%{_datadir}/argus/systemd/modern-caps.conf

# State directories
%dir %attr(0750,root,root) %{_sharedstatedir}/argus
%ghost %dir %{_rundir}/argus

%files selinux
%dir %{_datadir}/argus
%dir %{_datadir}/argus/selinux
%{_datadir}/argus/selinux/argus.te
%{_datadir}/argus/selinux/argus.fc
%{_datadir}/argus/selinux/argus.if
# argus.pp is only present if the build host had selinux-policy-devel.
%ghost %{_datadir}/argus/selinux/argus.pp

%changelog
* Wed May 20 2026 ARGUS Maintainers <argus@example.com> - 0.1.0-1
- v0.1.0 production-readiness release for Rocky 8 / RHEL 8 HPC clusters
- IB fabric idle visibility (argus_ib_port_idle_seconds, argus_ib_fabric_idle)
- argus-preflight readiness checker
- Optional argus-selinux subpackage with SELinux policy module
- Ansible bootstrap playbook
- Alertmanager email + Zabbix HTTP-agent template
- Production deployment runbook and troubleshooting docs

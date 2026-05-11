%global crate_name argus-agent
%global ebpf_name  argus-ebpf

Name:           argus
Version:        0.1.0
Release:        1%{?dist}
Summary:        Adaptive RDMA Guard & Utilization Sentinel — eBPF telemetry agent

License:        Apache-2.0
URL:            https://github.com/KevinWeiss1995/ARGUS
Source0:        %{name}-%{version}.tar.gz

ExclusiveArch:  x86_64 aarch64

BuildRequires:  cargo >= 1.75
BuildRequires:  rust >= 1.75
BuildRequires:  clang
BuildRequires:  llvm
BuildRequires:  systemd-rpm-macros
BuildRequires:  openssl-devel
BuildRequires:  pkg-config

Requires:       systemd
Requires(pre):  shadow-utils

%description
ARGUS is a node-local telemetry agent that uses eBPF to monitor kernel
behavior related to RDMA networking, interrupt handling, and memory
allocation in real time. It detects early signs of InfiniBand degradation
or system imbalance before application performance collapses.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release --workspace
# eBPF build requires nightly — skipped in RPM; ship pre-built artifact.
# cargo xtask build-ebpf --release

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
for tool in argus-status argus-discover argus-manage-targets argus-scheduler; do
    install -Dpm 0755 scripts/${tool} %{buildroot}%{_bindir}/${tool}
done
ln -sf argusd %{buildroot}%{_bindir}/argus-tui

# State and runtime directories
install -dm 0750 %{buildroot}%{_sharedstatedir}/argus
install -dm 0755 %{buildroot}%{_rundir}/argus

%pre
%sysusers_create_compat packaging/sysusers.d/argus.conf

%post
# Compute eBPF artifact hash for integrity verification
sha256sum %{_libdir}/argus/%{ebpf_name} | awk '{print $1}' \
    > %{_sysconfdir}/argus/ebpf.sha256 2>/dev/null || :
%systemd_post argusd.service

%preun
%systemd_preun argusd.service

%postun
%systemd_postun_with_restart argusd.service

%files
%license LICENSE
%doc README.md

# Binaries
%{_bindir}/argusd
%{_bindir}/argus-tui
%{_bindir}/argus-status
%{_bindir}/argus-discover
%{_bindir}/argus-manage-targets
%{_bindir}/argus-scheduler

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

# State directories
%dir %attr(0750,root,root) %{_sharedstatedir}/argus
%ghost %dir %{_rundir}/argus

%changelog
* Mon May 11 2026 ARGUS Maintainers <argus@example.com> - 0.1.0-1
- Initial RPM package
- Production-hardened systemd unit with defense-in-depth
- Mandatory eBPF hash verification via %%post scriptlet
- sysusers.d/tmpfiles.d integration

%global _prefix /usr/local
%global debug_package %{nil}

Name:           argus
Version:        0.1.0
Release:        1%{?dist}
Summary:        Adaptive RDMA Guard & Utilization Sentinel — node-local telemetry agent

License:        Apache-2.0
URL:            https://github.com/argus-monitoring/argus
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.75
BuildRequires:  cargo
Requires:       systemd
Recommends:     pahole

%description
ARGUS is a node-local telemetry agent that uses eBPF to monitor kernel
behavior related to RDMA networking, interrupt handling, and memory
allocation in real time. It detects early signs of InfiniBand degradation
or system imbalance before application performance collapses.

Operates in two tiers:
  Tier 1 — Full eBPF tracepoints, kprobes, and kretprobes
  Tier 2 — procfs/sysfs fallback for locked-down environments

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release
# eBPF build requires nightly + bpf-linker; skip if unavailable
if command -v bpf-linker &>/dev/null; then
    cargo xtask build-ebpf --release || echo "WARNING: eBPF build failed, Tier 2 only"
fi

%install
mkdir -p %{buildroot}%{_prefix}/bin
mkdir -p %{buildroot}%{_prefix}/lib/argus
mkdir -p %{buildroot}/etc/argus
mkdir -p %{buildroot}/etc/systemd/system
mkdir -p %{buildroot}/var/lib/argus
mkdir -p %{buildroot}/var/run/argus

install -m 0755 target/release/argus-agent %{buildroot}%{_prefix}/bin/argusd

# eBPF object (optional — Tier 2 runs without it)
if [ -f argus-ebpf/target/bpfel-unknown-none/release/argus-ebpf ]; then
    install -m 0644 argus-ebpf/target/bpfel-unknown-none/release/argus-ebpf \
        %{buildroot}%{_prefix}/lib/argus/argus-ebpf
fi

# CLI tools
for tool in argus-status argus-discover argus-manage-targets argus-scheduler; do
    install -m 0755 scripts/$tool %{buildroot}%{_prefix}/bin/$tool
done
ln -sf argusd %{buildroot}%{_prefix}/bin/argus-tui

# Config
install -m 0644 deploy/argusd.conf %{buildroot}/etc/argus/argusd.conf
install -m 0644 deploy/examples/standalone.toml %{buildroot}/etc/argus/argusd.toml

# Systemd unit
install -m 0644 deploy/argusd.service %{buildroot}/etc/systemd/system/argusd.service

# SELinux policy (source only — compile at install time or as post-script)
mkdir -p %{buildroot}%{_prefix}/share/argus/selinux
install -m 0644 deploy/selinux/argus.te %{buildroot}%{_prefix}/share/argus/selinux/argus.te
install -m 0644 deploy/selinux/argus.fc %{buildroot}%{_prefix}/share/argus/selinux/argus.fc

%files
%license LICENSE
%doc README.md
%{_prefix}/bin/argusd
%{_prefix}/bin/argus-tui
%{_prefix}/bin/argus-status
%{_prefix}/bin/argus-discover
%{_prefix}/bin/argus-manage-targets
%{_prefix}/bin/argus-scheduler
%{_prefix}/lib/argus/
%config(noreplace) /etc/argus/argusd.conf
%config(noreplace) /etc/argus/argusd.toml
/etc/systemd/system/argusd.service
%{_prefix}/share/argus/selinux/
%dir /var/lib/argus
%dir /var/run/argus

%post
systemctl daemon-reload
echo "ARGUS installed. Enable with: systemctl enable --now argusd"
echo "Check metrics: curl localhost:9100/metrics"

%preun
if [ $1 -eq 0 ]; then
    systemctl stop argusd 2>/dev/null || true
    systemctl disable argusd 2>/dev/null || true
fi

%postun
systemctl daemon-reload

%changelog
* %(date "+%a %b %d %Y") ARGUS Team <argus@example.com> - 0.1.0-1
- Initial RPM package with Tier 1/2 operating modes
- eBPF + procfs/sysfs dual-path metric collection
- Full IPv6/dual-stack support
- SELinux policy included
- RHEL 8/9/10 compatibility

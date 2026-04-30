%global debug_package %{nil}
%bcond_without ebpf

Name:           argus
Version:        %{?_version}%{!?_version:0.1.0}
Release:        1%{?dist}
Summary:        Adaptive RDMA Guard & Utilization Sentinel

License:        Apache-2.0
URL:            https://github.com/KevinWeiss1995/ARGUS
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  openssl-devel
BuildRequires:  elfutils-libelf-devel
Requires:       systemd
%if %{with ebpf}
Recommends:     argus-ebpf = %{version}-%{release}
%endif
Recommends:     pahole

%description
ARGUS is a node-local telemetry agent that uses eBPF to monitor kernel
behavior related to RDMA networking, interrupt handling, and memory
allocation in real time. It detects early signs of InfiniBand degradation
or system imbalance before application performance collapses.

Operates in two tiers:
  Tier 1: Full eBPF tracepoints, kprobes, and kretprobes
  Tier 2: procfs/sysfs fallback for locked-down environments

# NOTE: Rust toolchain (cargo, rustc) must be available on the build host.
# It is installed via rustup in CI, not via BuildRequires, because RHEL's
# rust-toolset may be too old. See .github/workflows/release.yml.

%if %{with ebpf}
%package -n argus-ebpf
Summary:        ARGUS eBPF kernel probes
Requires:       argus = %{version}-%{release}

%description -n argus-ebpf
eBPF kernel probe object for ARGUS Tier 1 mode. Provides high-fidelity
tracepoint and kprobe-based monitoring of IRQ distribution, slab allocation,
NAPI polling, and RDMA completion queue jitter.

Not required for Tier 2 (procfs/sysfs) operation.
%endif

%prep
%autosetup -n %{name}-%{version}

%build
export PATH="$HOME/.cargo/bin:$PATH"
# Skip rebuild if pre-built artifacts exist (e.g., from `just rpm`)
if [ ! -f target/release/argus-agent ]; then
    cargo build --release
fi
%if %{with ebpf}
if [ ! -f argus-ebpf/target/bpfel-unknown-none/release/argus-ebpf ]; then
    if command -v bpf-linker &>/dev/null; then
        cargo xtask build-ebpf --release || echo "WARNING: eBPF build failed, Tier 2 only"
    fi
fi
%endif

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_libdir}/argus
mkdir -p %{buildroot}%{_sysconfdir}/argus
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_datadir}/argus/selinux
mkdir -p %{buildroot}%{_sharedstatedir}/argus

install -m 0755 target/release/argus-agent %{buildroot}%{_bindir}/argusd
ln -sf argusd %{buildroot}%{_bindir}/argus-tui

for tool in argus-status argus-discover argus-manage-targets argus-scheduler; do
    install -m 0755 scripts/$tool %{buildroot}%{_bindir}/$tool
done

install -m 0644 deploy/argusd.conf %{buildroot}%{_sysconfdir}/argus/argusd.conf
install -m 0644 deploy/examples/standalone.toml %{buildroot}%{_sysconfdir}/argus/argusd.toml
install -m 0644 deploy/argusd.service %{buildroot}%{_unitdir}/argusd.service
install -m 0644 deploy/selinux/argus.te %{buildroot}%{_datadir}/argus/selinux/argus.te
install -m 0644 deploy/selinux/argus.fc %{buildroot}%{_datadir}/argus/selinux/argus.fc

%if %{with ebpf}
if [ -f argus-ebpf/target/bpfel-unknown-none/release/argus-ebpf ]; then
    install -m 0644 argus-ebpf/target/bpfel-unknown-none/release/argus-ebpf \
        %{buildroot}%{_libdir}/argus/argus-ebpf
fi
%endif

%pre
getent group argus >/dev/null || groupadd -r argus
getent passwd argus >/dev/null || \
    useradd -r -g argus -d %{_sharedstatedir}/argus -s /sbin/nologin \
    -c "ARGUS telemetry agent" argus
exit 0

%post
%systemd_post argusd.service

%preun
%systemd_preun argusd.service

%postun
%systemd_postun_with_restart argusd.service

%files
%license LICENSE
%doc README.md
%{_bindir}/argusd
%{_bindir}/argus-tui
%{_bindir}/argus-status
%{_bindir}/argus-discover
%{_bindir}/argus-manage-targets
%{_bindir}/argus-scheduler
%config(noreplace) %{_sysconfdir}/argus/argusd.conf
%config(noreplace) %{_sysconfdir}/argus/argusd.toml
%{_unitdir}/argusd.service
%{_datadir}/argus/selinux/
%dir %{_sharedstatedir}/argus
%dir %{_libdir}/argus

%if %{with ebpf}
%files -n argus-ebpf
%{_libdir}/argus/argus-ebpf
%endif

%changelog
* Tue Apr 29 2026 ARGUS Team <argus@example.com> - 0.1.0-1
- Production RPM with FHS paths and systemd macros
- Tier 1/2 operating modes with eBPF sub-package
- Full IPv6/dual-stack support
- SELinux policy sources included
- RHEL 8/9/10 compatibility

#!/usr/bin/env bash
# ARGUS install script — builds and installs argusd as a systemd service.
#
# Usage:
#   sudo ./scripts/install.sh            # full build + install
#   sudo ./scripts/install.sh --no-build # install pre-built binaries only
#
# The script will:
#   1. Detect the invoking user's Rust toolchain (handles sudo PATH correctly)
#   2. Install missing prerequisites (nightly, rust-src, bpf-linker)
#   3. Build as the invoking user (not root — cargo hates that)
#   4. Install binaries, config, and systemd unit as root
#
# Installed paths:
#   /usr/local/bin/argusd                  — agent binary
#   /usr/local/lib/argus/argus-ebpf       — eBPF object
#   /etc/argus/argusd.conf                 — env configuration (preserved on upgrade)
#   /etc/argus/argusd.toml                 — TOML config example (preserved on upgrade)
#   /etc/systemd/system/argusd.service     — systemd unit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

AGENT_BIN="$REPO_ROOT/target/release/argus-agent"
EBPF_BIN="$REPO_ROOT/argus-ebpf/target/bpfel-unknown-none/release/argus-ebpf"

INSTALL_BIN="/usr/local/bin/argusd"
INSTALL_EBPF_DIR="/usr/local/lib/argus"
INSTALL_EBPF="$INSTALL_EBPF_DIR/argus-ebpf"
INSTALL_CONF_DIR="/etc/argus"
INSTALL_CONF="$INSTALL_CONF_DIR/argusd.conf"
INSTALL_TOML="$INSTALL_CONF_DIR/argusd.toml"
INSTALL_UNIT="/etc/systemd/system/argusd.service"

NO_BUILD=false
NO_EBPF=false

for arg in "$@"; do
    case "$arg" in
        --no-build) NO_BUILD=true ;;
        --no-ebpf)  NO_EBPF=true ;;
        --help|-h)
            echo "Usage: sudo $0 [--no-build] [--no-ebpf]"
            echo "  --no-build   Skip compilation, install pre-built binaries"
            echo "  --no-ebpf    Skip eBPF build (Tier 2 procfs/sysfs mode only)"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done

# --- Helpers ---

info()  { echo -e "\033[1;34m==>\033[0m $*"; }
ok()    { echo -e "\033[1;32m OK\033[0m $*"; }
warn()  { echo -e "\033[1;33mWRN\033[0m $*"; }
die()   { echo -e "\033[1;31mERR\033[0m $*" >&2; exit 1; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (sudo $0)"
    fi
}

# --- Preflight ---

require_root

if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
    die "Run this script from the ARGUS repo root (or via scripts/install.sh)"
fi

if ! systemctl --version &>/dev/null; then
    die "systemd not found — this installer requires a systemd-based Linux system"
fi

# --- System build dependencies ---
# Cargo crates with build scripts (proc-macro2, etc.) need a C compiler and linker.
# Install them now so `cargo build` and `cargo install bpf-linker` don't fail.

wait_for_apt_lock() {
    local tries=0
    while fuser /var/lib/dpkg/lock-frontend &>/dev/null 2>&1; do
        if [[ $tries -eq 0 ]]; then
            info "Waiting for dpkg lock (unattended-upgrades?)..."
        fi
        sleep 5
        tries=$((tries + 1))
        if [[ $tries -ge 60 ]]; then
            die "Timed out waiting for dpkg lock after 5 minutes"
        fi
    done
}

install_system_deps() {
    if command -v apt-get &>/dev/null; then
        if ! dpkg -s build-essential &>/dev/null 2>&1; then
            info "Installing build-essential (gcc, make, libc-dev)..."
            wait_for_apt_lock
            apt-get update -qq
            wait_for_apt_lock
            apt-get install -y -qq build-essential pkg-config libssl-dev
            ok "System build dependencies installed"
        fi
    elif command -v dnf &>/dev/null; then
        if ! rpm -q gcc &>/dev/null 2>&1; then
            info "Installing gcc and development tools (RHEL/dnf)..."
            dnf install -y gcc make pkgconf-pkg-config openssl-devel elfutils-libelf-devel
            ok "System build dependencies installed"
        fi
    elif command -v yum &>/dev/null; then
        if ! rpm -q gcc &>/dev/null 2>&1; then
            info "Installing gcc and development tools (yum)..."
            yum install -y gcc make pkgconf-pkg-config openssl-devel elfutils-libelf-devel
            ok "System build dependencies installed"
        fi
    elif command -v pacman &>/dev/null; then
        if ! pacman -Qi base-devel &>/dev/null 2>&1; then
            info "Installing base-devel..."
            pacman -S --noconfirm base-devel openssl pkg-config
            ok "System build dependencies installed"
        fi
    else
        if ! command -v cc &>/dev/null && ! command -v gcc &>/dev/null; then
            die "No C compiler found and couldn't detect package manager. Install gcc manually."
        fi
    fi
}

install_system_deps

# --- Resolve the invoking user's environment ---
# sudo strips PATH, so cargo/rustup in ~/.cargo/bin become invisible.
# We recover them via SUDO_USER.

BUILD_USER="${SUDO_USER:-${USER:-root}}"
BUILD_HOME=$(eval echo "~$BUILD_USER")

resolve_cargo_env() {
    local cargo_bin="$BUILD_HOME/.cargo/bin"
    if [[ -d "$cargo_bin" ]]; then
        export PATH="$cargo_bin:$PATH"
    fi
    if [[ -f "$BUILD_HOME/.cargo/env" ]]; then
        # shellcheck source=/dev/null
        source "$BUILD_HOME/.cargo/env" 2>/dev/null || true
    fi
}

resolve_cargo_env

# Run a command as the build user (not root) to avoid cargo/rustup permission mess.
# We use `env PATH=...` instead of --preserve-env because sudoers secure_path
# overrides PATH even with --preserve-env.
as_build_user() {
    if [[ "$BUILD_USER" == "root" ]]; then
        "$@"
    else
        sudo -u "$BUILD_USER" -- env \
            "PATH=$PATH" \
            "HOME=$BUILD_HOME" \
            "RUSTUP_HOME=${RUSTUP_HOME:-$BUILD_HOME/.rustup}" \
            "CARGO_HOME=${CARGO_HOME:-$BUILD_HOME/.cargo}" \
            "$@"
    fi
}

# --- Build ---

if [[ "$NO_BUILD" == false ]]; then
    info "Checking build prerequisites..."
    info "Build user: $BUILD_USER ($BUILD_HOME)"

    if ! command -v cargo &>/dev/null; then
        info "Rust toolchain not found — installing via rustup..."
        as_build_user bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
        resolve_cargo_env
    fi

    if ! command -v cargo &>/dev/null; then
        die "cargo still not found after install attempt. Check $BUILD_HOME/.cargo/bin"
    fi

    ok "cargo: $(cargo --version)"

    if ! as_build_user rustup toolchain list | grep -q nightly; then
        info "Installing nightly toolchain..."
        as_build_user rustup install nightly
    fi

    if ! as_build_user rustup component list --toolchain nightly 2>/dev/null | grep -q "rust-src (installed)"; then
        info "Adding rust-src component to nightly..."
        as_build_user rustup component add rust-src --toolchain nightly
    fi

    info "Building agent (release)..."
    cd "$REPO_ROOT"
    as_build_user cargo build --release

    if [[ "$NO_EBPF" == false ]]; then
        if ! command -v bpf-linker &>/dev/null; then
            info "Installing bpf-linker (this may take a few minutes)..."
            as_build_user cargo install bpf-linker
        fi

        info "Building eBPF programs (release)..."
        as_build_user cargo xtask build-ebpf --release
    else
        warn "Skipping eBPF build (--no-ebpf). Agent will run in Tier 2 (procfs/sysfs) mode."
    fi

    ok "Build complete"
fi

# --- Verify artifacts exist ---

if [[ ! -f "$AGENT_BIN" ]]; then
    die "Agent binary not found at $AGENT_BIN — run without --no-build first"
fi

if [[ ! -f "$EBPF_BIN" ]]; then
    if [[ "$NO_EBPF" == true ]]; then
        warn "eBPF binary not found (--no-ebpf mode). Agent will use procfs/sysfs fallback."
    else
        die "eBPF binary not found at $EBPF_BIN — run without --no-build first (or use --no-ebpf)"
    fi
fi

# --- Install binaries ---

info "Installing argusd to $INSTALL_BIN"
install -m 0755 "$AGENT_BIN" "$INSTALL_BIN"
ok "$INSTALL_BIN"

if [[ -f "$EBPF_BIN" ]]; then
    info "Installing eBPF object to $INSTALL_EBPF"
    mkdir -p "$INSTALL_EBPF_DIR"
    install -m 0644 "$EBPF_BIN" "$INSTALL_EBPF"
    ok "$INSTALL_EBPF"
else
    warn "eBPF object not available — skipping (Tier 2 mode)"
fi

info "Installing CLI tools to /usr/local/bin"
for tool in argus-status argus-discover argus-manage-targets argus-scheduler; do
    install -m 0755 "$REPO_ROOT/scripts/$tool" "/usr/local/bin/$tool"
done
ln -sf /usr/local/bin/argusd /usr/local/bin/argus-tui
ok "argus-status, argus-discover, argus-manage-targets, argus-scheduler, argus-tui"

# --- Install config (preserve existing) ---

mkdir -p "$INSTALL_CONF_DIR"

if [[ -f "$INSTALL_CONF" ]]; then
    warn "Config already exists at $INSTALL_CONF — not overwriting (your settings are preserved)"
    warn "New defaults are in $REPO_ROOT/deploy/argusd.conf for reference"
else
    info "Installing default config to $INSTALL_CONF"
    install -m 0644 "$REPO_ROOT/deploy/argusd.conf" "$INSTALL_CONF"
    ok "$INSTALL_CONF"
fi

if [[ -f "$INSTALL_TOML" ]]; then
    warn "TOML config already exists at $INSTALL_TOML — not overwriting"
else
    info "Installing example TOML config to $INSTALL_TOML"
    install -m 0644 "$REPO_ROOT/deploy/examples/standalone.toml" "$INSTALL_TOML"
    ok "$INSTALL_TOML"
fi

# --- Create runtime directories ---

mkdir -p /var/lib/argus /var/run/argus
ok "Runtime directories (/var/lib/argus, /var/run/argus)"

# --- Install systemd unit ---

info "Installing systemd unit to $INSTALL_UNIT"
install -m 0644 "$REPO_ROOT/deploy/argusd.service" "$INSTALL_UNIT"
systemctl daemon-reload
ok "$INSTALL_UNIT (daemon-reload done)"

# --- Done ---

# --- Detect and report operating tier ---

detect_tier() {
    if [[ ! -f "$INSTALL_EBPF" ]]; then
        echo "Tier 2"
        return
    fi
    if [[ -f /sys/kernel/security/lockdown ]]; then
        local mode
        mode=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "")
        if [[ "$mode" == *"[confidentiality]"* ]]; then
            echo "Tier 2"
            return
        fi
    fi
    if [[ -d /sys/kernel/tracing ]] || [[ -d /sys/kernel/debug/tracing ]]; then
        echo "Tier 1"
    else
        echo "Tier 2"
    fi
}

DETECTED_TIER=$(detect_tier)

echo ""
echo "============================================"
echo "  ARGUS installed successfully"
echo "============================================"
echo ""
echo "  Detected tier:    $DETECTED_TIER (eBPF=${DETECTED_TIER##Tier })"
if [[ "$DETECTED_TIER" == "Tier 1" ]]; then
    echo "                     Full eBPF: tracepoints + kprobes + kretprobes"
else
    echo "                     Fallback: procfs/sysfs collection (eBPF unavailable)"
fi
echo ""
echo "  Enable on boot:   systemctl enable argusd"
echo "  Start now:         systemctl start argusd"
echo "  View logs:         journalctl -u argusd -f"
echo "  Check metrics:     curl localhost:9100/metrics"
echo ""
echo "  Config files:"
echo "    Env:  $INSTALL_CONF"
echo "    TOML: $INSTALL_TOML  (enable in argusd.conf: ARGUS_CONFIG=$INSTALL_TOML)"
echo ""
echo "  TLS + auth:"
echo "    sudo cp $REPO_ROOT/deploy/examples/integration.toml $INSTALL_TOML"
echo ""
echo "  Standalone Grafana/Prometheus stack:"
echo "    $REPO_ROOT/deploy/observability/scripts/start-observability.sh"
echo ""

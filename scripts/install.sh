#!/usr/bin/env bash
# ARGUS install script — builds and installs argusd as a systemd service.
#
# Usage:
#   sudo ./scripts/install.sh            # full build + install
#   sudo ./scripts/install.sh --no-build # install pre-built binaries only
#
# Prerequisites (the script checks for these):
#   - Rust toolchain (rustup + cargo)
#   - nightly toolchain + rust-src (for eBPF build)
#   - bpf-linker (cargo install bpf-linker)
#   - Linux with systemd
#
# Installed paths:
#   /usr/local/bin/argusd                  — agent binary
#   /usr/local/lib/argus/argus-ebpf       — eBPF object
#   /etc/argus/argusd.conf                 — configuration (preserved on upgrade)
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
INSTALL_UNIT="/etc/systemd/system/argusd.service"

NO_BUILD=false

for arg in "$@"; do
    case "$arg" in
        --no-build) NO_BUILD=true ;;
        --help|-h)
            echo "Usage: sudo $0 [--no-build]"
            echo "  --no-build   Skip compilation, install pre-built binaries"
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

require_cmd() {
    command -v "$1" &>/dev/null || die "'$1' not found. $2"
}

# --- Preflight ---

require_root

if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
    die "Run this script from the ARGUS repo root (or via scripts/install.sh)"
fi

if ! systemctl --version &>/dev/null; then
    die "systemd not found — this installer requires a systemd-based Linux system"
fi

# --- Build ---

if [[ "$NO_BUILD" == false ]]; then
    info "Checking build prerequisites..."

    require_cmd cargo "Install Rust: https://rustup.rs"
    require_cmd rustup "Install Rust: https://rustup.rs"

    if ! rustup toolchain list | grep -q nightly; then
        info "Installing nightly toolchain..."
        rustup install nightly
    fi

    if ! rustup component list --toolchain nightly 2>/dev/null | grep -q "rust-src (installed)"; then
        info "Adding rust-src component to nightly..."
        rustup component add rust-src --toolchain nightly
    fi

    if ! command -v bpf-linker &>/dev/null; then
        info "Installing bpf-linker..."
        cargo install bpf-linker
    fi

    info "Building agent (release)..."
    cd "$REPO_ROOT"
    cargo build --release

    info "Building eBPF programs (release)..."
    cargo xtask build-ebpf --release

    ok "Build complete"
fi

# --- Verify artifacts exist ---

if [[ ! -f "$AGENT_BIN" ]]; then
    die "Agent binary not found at $AGENT_BIN — run without --no-build first"
fi

if [[ ! -f "$EBPF_BIN" ]]; then
    die "eBPF binary not found at $EBPF_BIN — run without --no-build first"
fi

# --- Install binaries ---

info "Installing argusd to $INSTALL_BIN"
install -m 0755 "$AGENT_BIN" "$INSTALL_BIN"
ok "$INSTALL_BIN"

info "Installing eBPF object to $INSTALL_EBPF"
mkdir -p "$INSTALL_EBPF_DIR"
install -m 0644 "$EBPF_BIN" "$INSTALL_EBPF"
ok "$INSTALL_EBPF"

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

# --- Install systemd unit ---

info "Installing systemd unit to $INSTALL_UNIT"
install -m 0644 "$REPO_ROOT/deploy/argusd.service" "$INSTALL_UNIT"
systemctl daemon-reload
ok "$INSTALL_UNIT (daemon-reload done)"

# --- Done ---

echo ""
echo "============================================"
echo "  ARGUS installed successfully"
echo "============================================"
echo ""
echo "  Enable on boot:   systemctl enable argusd"
echo "  Start now:         systemctl start argusd"
echo "  View logs:         journalctl -u argusd -f"
echo "  Check metrics:     curl localhost:9100/metrics"
echo "  Edit config:       $INSTALL_CONF"
echo ""
echo "  To deploy the Grafana/Prometheus stack:"
echo "    $REPO_ROOT/deploy/observability/scripts/start-observability.sh"
echo ""

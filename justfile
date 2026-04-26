default:
    @just --list

# Build the agent (default workspace member)
build:
    cargo build

# Build in release mode
build-release:
    cargo build --release

# Run all unit and integration tests
test:
    cargo test --workspace

# Run tests with output visible
test-verbose:
    cargo test --workspace -- --nocapture

# Run clippy with pedantic lints
lint:
    cargo clippy --workspace -- -W clippy::pedantic -W clippy::nursery

# Format all code
fmt:
    cargo fmt --all

# Check formatting without modifying
fmt-check:
    cargo fmt --all -- --check

# Run cargo-deny checks (advisories, licenses, bans, sources)
deny:
    cargo deny check

# ---------------------------------------------------------------------------
# Agent run commands — all use `cargo run` with default-members
# ---------------------------------------------------------------------------

# Run mock mode with TUI (default healthy profile)
run:
    cargo run -- --tui

# Run mock mode with a specific profile (healthy, skew, spike, pressure)
run-profile profile:
    cargo run -- --mode mock --profile {{profile}} --tui

# Replay an event/scenario file with TUI
run-replay file:
    cargo run -- --mode replay --file {{file}} --tui

# Run live eBPF mode (Linux only)
run-live:
    cargo run --release -- --mode live --ebpf-path argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf --tui

# Quick demo: cycle through all mock profiles
demo:
    @echo "=== healthy ==="
    cargo run -- --mode mock --profile healthy --tui --max-events 300
    @echo ""
    @echo "=== interrupt skew ==="
    cargo run -- --mode mock --profile skew --tui --max-events 300
    @echo ""
    @echo "=== RDMA latency spike ==="
    cargo run -- --mode mock --profile spike --tui --max-events 300
    @echo ""
    @echo "=== slab pressure ==="
    cargo run -- --mode mock --profile pressure --tui --max-events 300

# Run property-based tests with extended cases
proptest:
    PROPTEST_CASES=10000 cargo test --workspace

# ---------------------------------------------------------------------------
# eBPF (Linux only)
# ---------------------------------------------------------------------------

# Build eBPF programs (requires nightly + bpf-linker)
build-ebpf:
    cargo xtask build-ebpf

# Build eBPF programs in release mode
build-ebpf-release:
    cargo xtask build-ebpf --release

# Inspect compiled eBPF binary — verify program sections have code
inspect-ebpf:
    #!/usr/bin/env bash
    set -euo pipefail
    BPF_BIN="argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf"
    if [ ! -f "$BPF_BIN" ]; then
        echo "eBPF binary not found. Run: just build-ebpf"
        exit 1
    fi
    echo "=== eBPF binary: $(wc -c < "$BPF_BIN") bytes ==="
    # Find llvm-objdump: PATH, then rustup sysroot
    OBJDUMP=""
    if command -v llvm-objdump &>/dev/null; then
        OBJDUMP="llvm-objdump"
    else
        SYSROOT="$(rustc --print sysroot 2>/dev/null || true)"
        if [ -n "$SYSROOT" ]; then
            FOUND="$(find "$SYSROOT" -name 'llvm-objdump' -type f 2>/dev/null | head -1)"
            [ -n "$FOUND" ] && OBJDUMP="$FOUND"
        fi
    fi
    if [ -z "$OBJDUMP" ]; then
        echo "No llvm-objdump found. Run: rustup component add llvm-tools"
        exit 1
    fi
    echo "Using: $OBJDUMP"
    echo ""
    "$OBJDUMP" -d "$BPF_BIN"

# Build everything (eBPF + userspace)
build-all:
    cargo xtask build-all

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# Setup development environment
setup:
    rustup component add rustfmt clippy
    cargo install cargo-deny cargo-audit cargo-insta just
    @echo "Development environment ready."

# Setup Linux eBPF development (run on Linux VM or target)
setup-ebpf:
    rustup install nightly
    rustup component add rust-src --toolchain nightly
    cargo install bpf-linker
    @echo "eBPF development environment ready."

# Run security audit
audit:
    cargo audit
    cargo deny check advisories

# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------

# Build and install argusd as a systemd service (requires sudo)
install:
    sudo scripts/install.sh

# Install pre-built binaries only (skip compilation)
install-no-build:
    sudo scripts/install.sh --no-build

# Start the Prometheus + Grafana observability stack
install-observability:
    deploy/observability/scripts/start-observability.sh

# Show what the Jetson / Linux target can do
check-capabilities:
    @echo "=== System ==="
    uname -a
    @echo ""
    @echo "=== Agent binary ==="
    @ls -la target/release/argus-agent 2>/dev/null || ls -la target/debug/argus-agent 2>/dev/null || echo "Not built yet — run: just build"
    @echo ""
    @echo "=== eBPF artifact ==="
    @ls -la argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf 2>/dev/null || echo "Not built — run: just build-ebpf"
    @echo ""
    @echo "=== Fault injection ==="
    @sudo bash scripts/inject-faults.sh lo capabilities 2>/dev/null || echo "Run with sudo for full capabilities check"

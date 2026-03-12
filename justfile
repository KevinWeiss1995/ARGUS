default:
    @just --list

# Build all userspace crates
build:
    cargo build --workspace

# Run all unit and integration tests (Tier 0)
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

# Run a test scenario by name (e.g., just scenario interrupt-skew)
scenario name:
    cargo run --bin argus-agent -- --mode scenario --scenario {{name}}

# Run in replay mode with a recorded event file
replay file:
    cargo run --bin argus-agent -- --mode replay --replay-file {{file}}

# Run the agent in mock mode (generates synthetic events)
mock:
    cargo run --bin argus-agent -- --mode mock

# Run property-based tests with extended cases
proptest:
    PROPTEST_CASES=10000 cargo test --workspace

# Build eBPF programs (Linux only, requires nightly + bpf-linker)
build-ebpf:
    cargo xtask build-ebpf

# Build eBPF programs in release mode
build-ebpf-release:
    cargo xtask build-ebpf --release

# Build everything (eBPF + userspace)
build-all:
    cargo xtask build-all

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

# Run eBPF tests in OrbStack/Lima VM (macOS development)
vm-test:
    @echo "Start an ARM64 Linux VM with OrbStack or Lima,"
    @echo "then run: just setup-ebpf && just build-ebpf && just test"

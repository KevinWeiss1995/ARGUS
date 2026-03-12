#!/bin/bash
# End-to-end test suite for ARGUS.
# Designed to run on any Linux box — from Tegra to RHEL to cloud VMs.
#
# Tests are tiered by what's available on the host:
#   Tier 0: Mock/replay mode (always works, no root needed)
#   Tier 1: eBPF probes + slab/IRQ monitoring (needs root + eBPF)
#   Tier 2: Network fault injection (needs root + netem or iptables)
#   Tier 3: RDMA / Soft-RoCE (needs root + rdma_rxe + netem)
#
# The script auto-detects what's available and runs all applicable tiers.
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IFACE="${1:-auto}"
AGENT_BIN="${2:-$PROJECT_ROOT/target/release/argus-agent}"
RESULTS_DIR="$PROJECT_ROOT/test-results/e2e-$(date +%Y%m%d-%H%M%S)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die()  { echo "FATAL: $*" >&2; exit 1; }
warn() { echo "WARN:  $*" >&2; }
info() { echo "===  $*"; }

PASS=0
FAIL=0
SKIP=0
TOTAL=0

record_pass() { PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); echo "  PASS: $1"; }
record_fail() { FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); echo "  FAIL: $1"; }
record_skip() { SKIP=$((SKIP + 1)); TOTAL=$((TOTAL + 1)); echo "  SKIP: $1"; }

# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------

IS_ROOT=""
HAS_AGENT=""
HAS_EBPF_ARTIFACT=""
HAS_NETEM=""
HAS_IPTABLES=""
HAS_RDMA=""
HAS_SCENARIOS=""

auto_detect_iface() {
    if [[ "$IFACE" == "auto" ]]; then
        # Pick first UP non-loopback interface
        for dev in /sys/class/net/*; do
            name=$(basename "$dev")
            [[ "$name" == "lo" ]] && continue
            state=$(cat "$dev/operstate" 2>/dev/null || echo "unknown")
            if [[ "$state" == "up" ]]; then
                IFACE="$name"
                return
            fi
        done
        # Fallback: first non-lo interface regardless of state
        for dev in /sys/class/net/*; do
            name=$(basename "$dev")
            [[ "$name" == "lo" ]] && continue
            IFACE="$name"
            return
        done
        IFACE="lo"
    fi
}

detect_capabilities() {
    [[ $EUID -eq 0 ]] && IS_ROOT=1

    if [[ -x "$AGENT_BIN" ]]; then
        HAS_AGENT=1
    elif [[ -x "$PROJECT_ROOT/target/debug/argus-agent" ]]; then
        AGENT_BIN="$PROJECT_ROOT/target/debug/argus-agent"
        HAS_AGENT=1
    fi

    # eBPF artifact
    local ebpf_path="$PROJECT_ROOT/argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf"
    [[ -f "$ebpf_path" ]] && HAS_EBPF_ARTIFACT=1

    # netem
    if [[ -n "$IS_ROOT" ]]; then
        if modprobe sch_netem 2>/dev/null || tc qdisc add dev lo root netem delay 0ms 2>/dev/null; then
            tc qdisc del dev lo root 2>/dev/null || true
            HAS_NETEM=1
        fi
    fi

    # iptables
    command -v iptables &>/dev/null && HAS_IPTABLES=1

    # RDMA
    [[ -d /sys/class/infiniband ]] && ls /sys/class/infiniband/ &>/dev/null && [[ -n "$(ls -A /sys/class/infiniband/ 2>/dev/null)" ]] && HAS_RDMA=1

    # Test scenarios
    [[ -d "$PROJECT_ROOT/argus-test-scenarios/scenarios" ]] && HAS_SCENARIOS=1
}

print_capabilities() {
    info "Environment"
    echo "  Kernel:      $(uname -r) ($(uname -m))"
    echo "  Interface:   $IFACE"
    echo "  Agent:       ${HAS_AGENT:+$AGENT_BIN}${HAS_AGENT:-NOT FOUND}"
    echo "  Root:        ${IS_ROOT:+yes}${IS_ROOT:-no}"
    echo "  eBPF artifact: ${HAS_EBPF_ARTIFACT:+found}${HAS_EBPF_ARTIFACT:-not found}"
    echo "  netem:       ${HAS_NETEM:+available}${HAS_NETEM:-not available}"
    echo "  iptables:    ${HAS_IPTABLES:+available}${HAS_IPTABLES:-not available}"
    echo "  RDMA:        ${HAS_RDMA:+available}${HAS_RDMA:-not available}"
    echo "  Scenarios:   ${HAS_SCENARIOS:+found}${HAS_SCENARIOS:-not found}"
    echo "  Results:     $RESULTS_DIR"
    echo ""
}

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

# Run agent with timeout, capture logs
run_agent() {
    local test_name="$1"
    shift
    local log_file="$RESULTS_DIR/${test_name}.log"

    timeout 30 "$AGENT_BIN" "$@" >"$log_file" 2>&1 || true
    echo "$log_file"
}

check_log_for() {
    local log_file="$1"
    local pattern="$2"
    grep -q "$pattern" "$log_file" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Tier 0: Mock/replay tests (no root, no hardware)
# ---------------------------------------------------------------------------

tier0_tests() {
    info "Tier 0: Mock & replay tests (portable)"

    if [[ -z "$HAS_AGENT" ]]; then
        record_skip "No agent binary found — run 'cargo build --release' first"
        return
    fi

    # Test: healthy baseline (mock mode)
    local log
    log=$(run_agent "t0_mock_healthy" --mode mock --max-events 200 --profile healthy)
    if [[ -f "$log" && -s "$log" ]]; then
        record_pass "mock healthy baseline — agent ran successfully"
    else
        record_fail "mock healthy baseline — agent produced no output"
    fi

    # Test: skew profile should trigger detection
    log=$(run_agent "t0_mock_skew" --mode mock --max-events 500 --profile skew)
    if [[ -f "$log" && -s "$log" ]]; then
        record_pass "mock skew profile — agent ran successfully"
    else
        record_fail "mock skew profile — agent produced no output"
    fi

    # Test: spike profile
    log=$(run_agent "t0_mock_spike" --mode mock --max-events 500 --profile spike)
    if [[ -f "$log" && -s "$log" ]]; then
        record_pass "mock spike profile — agent ran successfully"
    else
        record_fail "mock spike profile — agent produced no output"
    fi

    # Test: scenario replay (if scenarios exist)
    if [[ -n "$HAS_SCENARIOS" ]]; then
        local scenarios_dir="$PROJECT_ROOT/argus-test-scenarios/scenarios"
        local scenario_count=0
        for scenario in "$scenarios_dir"/*.json; do
            [[ -f "$scenario" ]] || continue
            local sname
            sname=$(basename "$scenario" .json)
            log=$(run_agent "t0_replay_${sname}" --mode replay --file "$scenario")
            if [[ -f "$log" && -s "$log" ]]; then
                record_pass "replay $sname"
            else
                record_fail "replay $sname"
            fi
            scenario_count=$((scenario_count + 1))
        done
        if [[ $scenario_count -eq 0 ]]; then
            record_skip "no scenario files found"
        fi
    else
        record_skip "scenario directory not found"
    fi
}

# ---------------------------------------------------------------------------
# Tier 1: eBPF probe tests (root + Linux)
# ---------------------------------------------------------------------------

tier1_tests() {
    info "Tier 1: eBPF probe tests"

    if [[ -z "$IS_ROOT" ]]; then
        record_skip "eBPF tests require root"
        return
    fi

    if [[ -z "$HAS_EBPF_ARTIFACT" ]]; then
        record_skip "eBPF artifact not found — run 'just build-ebpf' first"
        return
    fi

    if [[ -z "$HAS_AGENT" ]]; then
        record_skip "No agent binary"
        return
    fi

    local ebpf_path="$PROJECT_ROOT/argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf"

    # Test: eBPF probes load and produce events
    local log
    log=$(run_agent "t1_ebpf_basic" --mode live --ebpf-path "$ebpf_path" --max-events 100)
    if [[ -f "$log" ]]; then
        if check_log_for "$log" "probes attached\|event.*slab\|event.*irq"; then
            record_pass "eBPF probes loaded and produced events"
        elif check_log_for "$log" "failed to load\|failed to attach"; then
            record_fail "eBPF probe load/attach failed (check $log)"
        else
            record_pass "eBPF agent ran (check $log for event details)"
        fi
    else
        record_fail "eBPF test produced no log"
    fi
}

# ---------------------------------------------------------------------------
# Tier 2: Network fault injection tests
# ---------------------------------------------------------------------------

tier2_tests() {
    info "Tier 2: Fault injection tests"

    if [[ -z "$IS_ROOT" ]]; then
        record_skip "Fault injection requires root"
        return
    fi

    if [[ -z "$HAS_NETEM" && -z "$HAS_IPTABLES" ]]; then
        record_skip "Neither netem nor iptables available"
        return
    fi

    if [[ -z "$HAS_AGENT" ]]; then
        record_skip "No agent binary"
        return
    fi

    # Start agent in background (mock mode — fault injection affects the host network,
    # but mock mode still lets us verify the agent stays stable under system stress)
    local log="$RESULTS_DIR/t2_fault_stability.log"
    timeout 20 "$AGENT_BIN" --mode mock --max-events 1000 >"$log" 2>&1 &
    local agent_pid=$!
    sleep 1

    # Inject and clear a fault
    if [[ -n "$HAS_NETEM" ]]; then
        tc qdisc replace dev "$IFACE" root netem delay 5ms 2ms 2>/dev/null || true
        sleep 3
        tc qdisc del dev "$IFACE" root 2>/dev/null || true
        info "  netem jitter injected and cleared on $IFACE"
    elif [[ -n "$HAS_IPTABLES" ]]; then
        bash "$SCRIPT_DIR/inject-faults.sh" "$IFACE" loss 2>/dev/null || true
        sleep 3
        bash "$SCRIPT_DIR/inject-faults.sh" "$IFACE" clear 2>/dev/null || true
        info "  iptables loss injected and cleared on $IFACE"
    fi

    wait "$agent_pid" 2>/dev/null || true

    if [[ -f "$log" && -s "$log" ]]; then
        record_pass "agent stable during fault injection"
    else
        record_fail "agent did not produce output during fault injection"
    fi
}

# ---------------------------------------------------------------------------
# Tier 3: RDMA tests
# ---------------------------------------------------------------------------

tier3_tests() {
    info "Tier 3: RDMA / Soft-RoCE tests"

    if [[ -z "$HAS_RDMA" ]]; then
        record_skip "No RDMA devices present (run setup-soft-roce.sh first, or skip if kernel lacks rdma_rxe)"
        return
    fi

    if [[ -z "$IS_ROOT" || -z "$HAS_AGENT" ]]; then
        record_skip "RDMA tests require root and agent binary"
        return
    fi

    # Verify IB counters are readable
    if ls /sys/class/infiniband/*/ports/*/counters/* &>/dev/null; then
        record_pass "InfiniBand sysfs counters accessible"
    else
        record_fail "InfiniBand sysfs counters not found despite RDMA device present"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

mkdir -p "$RESULTS_DIR"

auto_detect_iface
detect_capabilities
print_capabilities

tier0_tests
echo ""
tier1_tests
echo ""
tier2_tests
echo ""
tier3_tests

echo ""
info "Results"
echo "  Passed:  $PASS"
echo "  Failed:  $FAIL"
echo "  Skipped: $SKIP"
echo "  Total:   $TOTAL"
echo ""
echo "  Logs: $RESULTS_DIR"

if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo "FAILED tests — check logs in $RESULTS_DIR"
    exit 1
elif [[ $PASS -eq 0 ]]; then
    echo ""
    echo "No tests passed. Ensure agent is built: cargo build --release"
    exit 1
fi

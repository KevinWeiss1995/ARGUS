#!/bin/bash
# Fault injection for ARGUS end-to-end testing.
# Designed to work across Tegra, RHEL derivatives, Ubuntu, and minimal kernels.
# Run as root on a Linux host.
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
IFACE="${1:-}"
ACTION="${2:-help}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die()  { echo "FATAL: $*" >&2; exit 1; }
warn() { echo "WARN:  $*" >&2; }
info() { echo "INFO:  $*"; }

live_mode_reminder() {
    echo ""
    echo "NOTE: Fault injection affects the real kernel. To observe its effects in ARGUS,"
    echo "      run in live eBPF mode (not mock):"
    echo ""
    echo "  sudo argus-agent --mode live --ebpf-path argus-ebpf/target/bpfel-unknown-none/debug/argus-ebpf --tui"
    echo ""
}

require_root() {
    [[ $EUID -eq 0 ]] || die "Must run as root (try: sudo $SCRIPT_NAME $*)"
}

require_iface() {
    [[ -n "$IFACE" ]] || die "No interface specified. Usage: $SCRIPT_NAME <interface> <action>"
    [[ -d "/sys/class/net/$IFACE" ]] || die "Interface '$IFACE' does not exist. Available: $(ls /sys/class/net/ | tr '\n' ' ')"
    local state
    state=$(cat "/sys/class/net/$IFACE/operstate" 2>/dev/null || echo "unknown")
    if [[ "$state" != "up" && "$state" != "unknown" ]]; then
        warn "Interface '$IFACE' is $state — fault injection may have no effect"
    fi
}

# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------

HAS_NETEM=""
HAS_IPTABLES=""

detect_capabilities() {
    # tc netem
    if try_ensure_netem 2>/dev/null; then
        HAS_NETEM=1
    fi
    # iptables statistic match (works on virtually all kernels)
    if command -v iptables &>/dev/null; then
        HAS_IPTABLES=1
    fi
}

try_ensure_netem() {
    # If netem is built-in, tc will just work. If it's a module, try loading it.
    if modprobe sch_netem 2>/dev/null; then
        return 0
    fi
    # Check if it's already available (built-in or previously loaded)
    if tc qdisc add dev lo root netem delay 0ms 2>/dev/null; then
        tc qdisc del dev lo root 2>/dev/null
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Netem-based fault injection (preferred)
# ---------------------------------------------------------------------------

netem_add() {
    local params="$*"
    # Replace any existing root qdisc
    tc qdisc replace dev "$IFACE" root netem $params
    info "netem active on $IFACE: $params"
    info "Remove with: $SCRIPT_NAME $IFACE clear"
}

# ---------------------------------------------------------------------------
# iptables-based fallback (works on virtually every Linux kernel)
# ---------------------------------------------------------------------------

IPTABLES_CHAIN="ARGUS_FAULT"

iptables_setup_chain() {
    iptables -N "$IPTABLES_CHAIN" 2>/dev/null || true
    # Ensure our chain is referenced from INPUT/OUTPUT for this interface
    iptables -C INPUT  -i "$IFACE" -j "$IPTABLES_CHAIN" 2>/dev/null || \
        iptables -I INPUT  -i "$IFACE" -j "$IPTABLES_CHAIN"
    iptables -C OUTPUT -o "$IFACE" -j "$IPTABLES_CHAIN" 2>/dev/null || \
        iptables -I OUTPUT -o "$IFACE" -j "$IPTABLES_CHAIN"
}

iptables_drop() {
    local pct="$1"
    iptables_setup_chain
    # statistic module: --every N drops 1-in-N packets
    # Convert percentage to 1/N: 0.5% -> 1/200, 5% -> 1/20
    local every
    every=$(awk "BEGIN { printf \"%d\", 100/$pct }")
    [[ "$every" -lt 1 ]] && every=1
    iptables -A "$IPTABLES_CHAIN" -m statistic --mode nth --every "$every" --packet 0 -j DROP
    info "iptables DROP active: ~${pct}% on $IFACE (every ${every}th packet)"
    info "Remove with: $SCRIPT_NAME $IFACE clear"
}

iptables_clear() {
    iptables -F "$IPTABLES_CHAIN" 2>/dev/null || true
    iptables -D INPUT  -i "$IFACE" -j "$IPTABLES_CHAIN" 2>/dev/null || true
    iptables -D OUTPUT -o "$IFACE" -j "$IPTABLES_CHAIN" 2>/dev/null || true
    iptables -X "$IPTABLES_CHAIN" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Slab pressure (kernel-agnostic — just needs a process that allocates)
# ---------------------------------------------------------------------------

slab_pressure() {
    if command -v stress-ng &>/dev/null; then
        info "Using stress-ng for slab/memory pressure"
        stress-ng --vm 2 --vm-bytes 256M --vm-method all --timeout 30s &
        info "stress-ng running for 30s (PID: $!)"
    elif command -v dd &>/dev/null; then
        info "stress-ng not found — falling back to dd-based memory pressure"
        for i in 1 2; do
            dd if=/dev/urandom of=/dev/null bs=1M count=256 2>/dev/null &
        done
        info "dd workers running (will self-terminate). For better results: apt install stress-ng"
    else
        die "No tool available for memory pressure injection"
    fi
}

# ---------------------------------------------------------------------------
# Status / diagnostics
# ---------------------------------------------------------------------------

show_status() {
    info "=== Fault injection status for $IFACE ==="
    echo ""
    echo "tc qdisc:"
    tc qdisc show dev "$IFACE" 2>/dev/null || echo "  (tc not available)"
    echo ""
    echo "iptables (ARGUS_FAULT chain):"
    iptables -L "$IPTABLES_CHAIN" -n -v 2>/dev/null || echo "  (no ARGUS_FAULT chain)"
    echo ""
    echo "Kernel capabilities:"
    echo "  netem:    ${HAS_NETEM:+available}${HAS_NETEM:-NOT available}"
    echo "  iptables: ${HAS_IPTABLES:+available}${HAS_IPTABLES:-NOT available}"
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

do_jitter() {
    if [[ -n "$HAS_NETEM" ]]; then
        netem_add delay 5ms 2ms distribution normal
    else
        warn "netem unavailable — cannot inject jitter (no iptables equivalent)"
        warn "Install sch_netem or rebuild kernel with CONFIG_NET_SCH_NETEM=m"
        exit 1
    fi
}

do_loss() {
    local pct="${1:-0.5}"
    if [[ -n "$HAS_NETEM" ]]; then
        netem_add loss "${pct}%"
    elif [[ -n "$HAS_IPTABLES" ]]; then
        warn "netem unavailable — using iptables statistical drop as fallback"
        iptables_drop "$pct"
    else
        die "Neither netem nor iptables available — cannot inject packet loss"
    fi
}

do_latency() {
    if [[ -n "$HAS_NETEM" ]]; then
        netem_add delay 50ms
    else
        warn "netem unavailable — cannot inject latency (no iptables equivalent)"
        warn "Install sch_netem or rebuild kernel with CONFIG_NET_SCH_NETEM=m"
        exit 1
    fi
}

do_clear() {
    info "=== Clearing all fault injection rules ==="
    tc qdisc del dev "$IFACE" root 2>/dev/null && info "netem rules cleared" || true
    iptables_clear 2>/dev/null && info "iptables rules cleared" || true
    info "All faults cleared on $IFACE"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

case "$ACTION" in
    help|--help|-h)
        cat <<EOF
Usage: $SCRIPT_NAME <interface> <action>

Actions:
  jitter          Add 5ms +/- 2ms jitter (netem required)
  loss            Add 0.5% packet loss (netem or iptables fallback)
  heavy-loss      Add 5% packet loss (netem or iptables fallback)
  latency         Add 50ms fixed latency (netem required)
  slab-pressure   Run memory pressure to stress slab allocator
  clear           Remove all fault injection rules
  status          Show current fault injection state and capabilities
  capabilities    Detect and report available fault injection methods

Available interfaces:
  $(ls /sys/class/net/ 2>/dev/null | tr '\n' ' ')

Examples:
  sudo $SCRIPT_NAME enP8p1s0 jitter
  sudo $SCRIPT_NAME enP8p1s0 loss
  sudo $SCRIPT_NAME enP8p1s0 clear
  sudo $SCRIPT_NAME enP8p1s0 status
EOF
        ;;
    capabilities)
        require_root
        detect_capabilities
        echo "Fault injection capabilities:"
        echo "  netem (tc):  ${HAS_NETEM:+YES}${HAS_NETEM:-NO — sch_netem module missing from $(uname -r)}"
        echo "  iptables:    ${HAS_IPTABLES:+YES}${HAS_IPTABLES:-NO}"
        echo "  stress-ng:   $(command -v stress-ng &>/dev/null && echo YES || echo 'NO (apt install stress-ng)')"
        echo ""
        if [[ -f /proc/config.gz ]]; then
            echo "Kernel config (network schedulers):"
            zcat /proc/config.gz 2>/dev/null | grep -E 'NET_SCH_NETEM|NET_SCH_TBF|NETFILTER' | sed 's/^/  /' || true
        elif [[ -f "/boot/config-$(uname -r)" ]]; then
            echo "Kernel config (network schedulers):"
            grep -E 'NET_SCH_NETEM|NET_SCH_TBF|NETFILTER' "/boot/config-$(uname -r)" | sed 's/^/  /' || true
        fi
        ;;
    jitter)
        require_root
        require_iface
        detect_capabilities
        do_jitter
        live_mode_reminder
        ;;
    loss)
        require_root
        require_iface
        detect_capabilities
        do_loss 0.5
        live_mode_reminder
        ;;
    heavy-loss)
        require_root
        require_iface
        detect_capabilities
        do_loss 5
        live_mode_reminder
        ;;
    latency)
        require_root
        require_iface
        detect_capabilities
        do_latency
        live_mode_reminder
        ;;
    slab-pressure)
        require_root
        slab_pressure
        live_mode_reminder
        ;;
    clear)
        require_root
        require_iface
        do_clear
        ;;
    status)
        require_root
        require_iface
        detect_capabilities
        show_status
        ;;
    *)
        die "Unknown action: $ACTION (try: $SCRIPT_NAME help)"
        ;;
esac

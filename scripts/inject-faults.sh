#!/bin/bash
# Fault injection for ARGUS end-to-end testing.
# Simulates network degradation that should trigger detection.
# Run as root on a Linux host with Soft-RoCE configured.
set -euo pipefail

IFACE="${1:-eth0}"
ACTION="${2:-help}"

case "$ACTION" in
    jitter)
        echo "=== Injecting jitter: 5ms +/- 2ms ==="
        tc qdisc add dev "$IFACE" root netem delay 5ms 2ms distribution normal
        echo "Fault active. Remove with: $0 $IFACE clear"
        ;;
    loss)
        echo "=== Injecting 0.5% packet loss ==="
        tc qdisc add dev "$IFACE" root netem loss 0.5%
        echo "Fault active. Remove with: $0 $IFACE clear"
        ;;
    heavy-loss)
        echo "=== Injecting 5% packet loss (severe) ==="
        tc qdisc add dev "$IFACE" root netem loss 5%
        echo "Fault active. Remove with: $0 $IFACE clear"
        ;;
    latency)
        echo "=== Injecting 50ms fixed latency ==="
        tc qdisc add dev "$IFACE" root netem delay 50ms
        echo "Fault active. Remove with: $0 $IFACE clear"
        ;;
    slab-pressure)
        echo "=== Inducing slab pressure with stress-ng ==="
        if command -v stress-ng &>/dev/null; then
            stress-ng --vm 2 --vm-bytes 256M --vm-method all --timeout 30s &
            echo "stress-ng running for 30 seconds (PID: $!)"
        else
            echo "stress-ng not installed. Install with: apt install stress-ng"
            exit 1
        fi
        ;;
    clear)
        echo "=== Clearing all netem rules ==="
        tc qdisc del dev "$IFACE" root 2>/dev/null || echo "No rules to clear"
        echo "Faults cleared."
        ;;
    help|*)
        echo "Usage: $0 <interface> <action>"
        echo ""
        echo "Actions:"
        echo "  jitter         - Add 5ms +/- 2ms jitter"
        echo "  loss           - Add 0.5% packet loss"
        echo "  heavy-loss     - Add 5% packet loss (severe)"
        echo "  latency        - Add 50ms fixed latency"
        echo "  slab-pressure  - Run stress-ng to pressure slab allocator"
        echo "  clear          - Remove all fault injection rules"
        echo ""
        echo "Example workflow:"
        echo "  1. $0 eth0 jitter     # Start fault"
        echo "  2. Watch ARGUS TUI    # Should show degradation"
        echo "  3. $0 eth0 clear      # Stop fault"
        ;;
esac

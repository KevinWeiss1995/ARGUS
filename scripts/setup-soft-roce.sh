#!/bin/bash
# Setup Soft-RoCE (RXE) for testing RDMA without InfiniBand hardware.
# Run as root on a Linux host (Jetson, VM, etc.)
set -euo pipefail

IFACE="${1:-eth0}"

echo "=== Setting up Soft-RoCE on $IFACE ==="

# Load the RXE kernel module
modprobe rdma_rxe

# Create an RXE device on the specified interface
rdma link add rxe_0 type rxe netdev "$IFACE" 2>/dev/null || {
    echo "RXE device may already exist, checking..."
}

# Verify
echo "=== RDMA devices ==="
rdma link show

echo "=== InfiniBand sysfs ==="
ls /sys/class/infiniband/ 2>/dev/null || echo "No IB devices found"

echo ""
echo "Soft-RoCE setup complete. You can now:"
echo "  - Run ARGUS in live mode to monitor the RXE device"
echo "  - Use 'ib_send_lat' and 'ib_write_bw' for baseline measurements"
echo "  - Use 'scripts/inject-faults.sh' to simulate degradation"

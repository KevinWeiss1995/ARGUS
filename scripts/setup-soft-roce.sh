#!/bin/bash
# Setup Soft-RoCE (RXE) for testing RDMA without InfiniBand hardware.
# Run as root on a Linux host (Jetson, VM, bare metal, etc.)
#
# Gracefully handles kernels that lack rdma_rxe (e.g. Tegra, minimal cloud images)
# and provides clear diagnostics and remediation guidance.
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
IFACE="${1:-}"
RXE_DEV="${2:-rxe_0}"

die()  { echo "FATAL: $*" >&2; exit 1; }
warn() { echo "WARN:  $*" >&2; }
info() { echo "INFO:  $*"; }

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

[[ $EUID -eq 0 ]] || die "Must run as root (try: sudo $SCRIPT_NAME $*)"

if [[ -z "$IFACE" ]]; then
    echo "Usage: $SCRIPT_NAME <interface> [rxe_device_name]"
    echo ""
    echo "Available interfaces:"
    for dev in /sys/class/net/*; do
        name=$(basename "$dev")
        state=$(cat "$dev/operstate" 2>/dev/null || echo "unknown")
        driver=$(basename "$(readlink -f "$dev/device/driver" 2>/dev/null)" 2>/dev/null || echo "unknown")
        printf "  %-16s  state=%-8s  driver=%s\n" "$name" "$state" "$driver"
    done
    exit 1
fi

[[ -d "/sys/class/net/$IFACE" ]] || die "Interface '$IFACE' not found"

# ---------------------------------------------------------------------------
# Kernel capability detection
# ---------------------------------------------------------------------------

check_kernel_config() {
    local key="$1"
    local config_file=""

    if [[ -f /proc/config.gz ]]; then
        if zcat /proc/config.gz 2>/dev/null | grep -q "^${key}=[ym]"; then
            return 0
        fi
        return 1
    elif [[ -f "/boot/config-$(uname -r)" ]]; then
        config_file="/boot/config-$(uname -r)"
    elif [[ -f "/lib/modules/$(uname -r)/config" ]]; then
        config_file="/lib/modules/$(uname -r)/config"
    fi

    if [[ -n "$config_file" ]]; then
        grep -q "^${key}=[ym]" "$config_file" 2>/dev/null
        return $?
    fi

    # Can't determine — return unknown (try anyway)
    return 2
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

info "=== Soft-RoCE Setup ==="
info "Kernel:    $(uname -r)"
info "Arch:      $(uname -m)"
info "Interface: $IFACE"
echo ""

# Step 1: Check RDMA subsystem
info "Checking RDMA subsystem..."
RDMA_OK=""

if check_kernel_config "CONFIG_INFINIBAND"; then
    info "  CONFIG_INFINIBAND: enabled"
    RDMA_OK=1
else
    ret=$?
    if [[ $ret -eq 1 ]]; then
        warn "  CONFIG_INFINIBAND: not enabled in kernel config"
    else
        info "  CONFIG_INFINIBAND: unknown (no kernel config found, will try anyway)"
        RDMA_OK=maybe
    fi
fi

# Try loading core RDMA modules
for mod in ib_core ib_uverbs rdma_ucm; do
    if modprobe "$mod" 2>/dev/null; then
        info "  Module $mod: loaded"
        RDMA_OK=1
    else
        # Might be built-in
        if [[ -d "/sys/module/$mod" ]]; then
            info "  Module $mod: built-in"
            RDMA_OK=1
        else
            warn "  Module $mod: not available"
        fi
    fi
done

if [[ -z "$RDMA_OK" ]]; then
    echo ""
    die "RDMA subsystem not available in kernel $(uname -r).
    
This kernel was built without InfiniBand/RDMA support.
To fix, rebuild the kernel with:
  CONFIG_INFINIBAND=y
  CONFIG_INFINIBAND_USER_ACCESS=m
  CONFIG_RDMA_RXE=m

For Jetson (L4T), see:
  https://docs.nvidia.com/jetson/archives/r36.4/DeveloperGuide/SD/Kernel/KernelCustomization.html"
fi

# Step 2: Load rdma_rxe
info ""
info "Loading Soft-RoCE (rdma_rxe)..."

if modprobe rdma_rxe 2>/dev/null; then
    info "  rdma_rxe: loaded"
elif [[ -d "/sys/module/rdma_rxe" ]]; then
    info "  rdma_rxe: already loaded"
else
    echo ""
    # Detailed diagnostics
    echo "=== Diagnostics ==="
    
    if check_kernel_config "CONFIG_RDMA_RXE"; then
        warn "CONFIG_RDMA_RXE is enabled in config but module failed to load"
        echo "  Check dmesg for errors: dmesg | tail -20"
    else
        ret=$?
        if [[ $ret -eq 1 ]]; then
            echo "CONFIG_RDMA_RXE is NOT enabled in kernel $(uname -r)"
        else
            echo "Could not determine CONFIG_RDMA_RXE status"
        fi
    fi

    echo ""
    echo "Available RDMA modules in this kernel:"
    find "/lib/modules/$(uname -r)" -name '*rdma*' -o -name '*rxe*' -o -name '*ib_*' 2>/dev/null | head -20 || echo "  (none found)"
    
    echo ""
    echo "=== Remediation ==="
    echo "Option 1: Rebuild kernel with CONFIG_RDMA_RXE=m"
    echo "Option 2: Use a distro kernel that includes RDMA (Ubuntu Server, RHEL, Rocky)"
    echo "Option 3: Test ARGUS without Soft-RoCE using mock/replay modes:"
    echo "  cargo run -- --mode mock --tui --profile spike"
    echo "  cargo run -- --mode replay --scenario argus-test-scenarios/scenarios/rdma_latency_spike.json --tui"
    echo ""
    echo "ARGUS eBPF probes for slab/IRQ/NAPI work without RDMA."
    echo "Only the CQ completion probe requires an RDMA device."
    exit 1
fi

# Step 3: Create the RXE device
info ""
info "Creating RXE device '$RXE_DEV' on $IFACE..."

if rdma link show "$RXE_DEV" &>/dev/null; then
    info "  $RXE_DEV already exists"
else
    if ! command -v rdma &>/dev/null; then
        die "'rdma' command not found. Install: apt install rdma-core (Debian/Ubuntu) or dnf install rdma-core (RHEL)"
    fi
    rdma link add "$RXE_DEV" type rxe netdev "$IFACE" || \
        die "Failed to create RXE device. Check dmesg for details."
    info "  $RXE_DEV created"
fi

# Step 4: Verify
echo ""
info "=== Verification ==="

echo ""
echo "RDMA links:"
rdma link show 2>/dev/null | sed 's/^/  /'

echo ""
echo "InfiniBand devices:"
if [[ -d /sys/class/infiniband ]]; then
    for dev in /sys/class/infiniband/*; do
        name=$(basename "$dev")
        node_type=$(cat "$dev/node_type" 2>/dev/null || echo "unknown")
        for port_dir in "$dev"/ports/*/; do
            port=$(basename "$port_dir")
            state=$(cat "${port_dir}state" 2>/dev/null || echo "unknown")
            printf "  %-12s  port=%s  type=%s  state=%s\n" "$name" "$port" "$node_type" "$state"
        done
    done
else
    echo "  (none)"
fi

echo ""
echo "Hardware counters (for ARGUS monitoring):"
if ls /sys/class/infiniband/*/ports/*/counters/* &>/dev/null; then
    for counter_file in /sys/class/infiniband/*/ports/*/counters/*; do
        val=$(cat "$counter_file" 2>/dev/null || echo "?")
        # Only show non-zero or important counters
        name=$(basename "$counter_file")
        case "$name" in
            symbol_error|link_downed|port_rcv_errors|port_xmit_discards|port_rcv_data|port_xmit_data)
                printf "  %-24s = %s\n" "$name" "$val"
                ;;
        esac
    done
else
    echo "  (no counters found)"
fi

echo ""
info "=== Soft-RoCE ready ==="
echo "You can now:"
echo "  - Run ARGUS:       cargo run -- --mode ebpf --ebpf-path <path> --tui"
echo "  - Baseline RDMA:   ib_send_lat -d $RXE_DEV  (in another terminal)"
echo "  - Inject faults:   sudo bash scripts/inject-faults.sh $IFACE jitter"

#!/usr/bin/env bash
# Start the ARGUS observability stack (Prometheus + Grafana + Alertmanager).
#
# Usage:
#   start-observability.sh                              # start with existing targets
#   start-observability.sh --discover 10.0.0.0/24       # scan subnet first
#   start-observability.sh --add 10.0.0.5 --add 10.0.0.6  # add specific nodes
#
# Targets are stored in argus-targets.json. Prometheus watches this file and
# picks up changes within 30s — no restart needed after adding nodes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$STACK_DIR/../.." && pwd)"
TARGETS_FILE="$STACK_DIR/argus-targets.json"
DISCOVER_BIN="$REPO_ROOT/scripts/argus-discover"
MANAGE_BIN="$REPO_ROOT/scripts/argus-manage-targets"

DISCOVER_SUBNET=""
ADD_HOSTS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --discover) DISCOVER_SUBNET="$2"; shift 2 ;;
        --add)      ADD_HOSTS+=("$2"); shift 2 ;;
        -h|--help)
            echo "Usage: start-observability.sh [--discover CIDR] [--add HOST]..."
            exit 0 ;;
        *)          echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Run subnet discovery if requested
if [[ -n "$DISCOVER_SUBNET" ]]; then
    echo "Discovering ARGUS nodes on ${DISCOVER_SUBNET}..."
    "$DISCOVER_BIN" --subnet "$DISCOVER_SUBNET" --output "$TARGETS_FILE"
fi

# Add individual hosts if requested
for host in "${ADD_HOSTS[@]+"${ADD_HOSTS[@]}"}"; do
    ARGUS_TARGETS_FILE="$TARGETS_FILE" "$MANAGE_BIN" add "$host"
done

# Ensure targets file exists (seed with localhost if empty)
if [[ ! -f "$TARGETS_FILE" ]]; then
    echo '[{"targets": ["host.docker.internal:9100"], "labels": {"job": "argus"}}]' > "$TARGETS_FILE"
    echo "Created ${TARGETS_FILE} with local node as default target."
fi

cd "$STACK_DIR"
echo "Starting ARGUS observability stack..."
docker compose up -d

echo ""
echo "Services:"
echo "  Grafana:      http://localhost:3000  (admin/admin)"
echo "  Prometheus:   http://localhost:9091"
echo "  Alertmanager: http://localhost:9093"
echo ""

ARGUS_TARGETS_FILE="$TARGETS_FILE" "$MANAGE_BIN" list

echo ""
echo "Manage nodes:"
echo "  Add:      scripts/argus-manage-targets add <host>"
echo "  Remove:   scripts/argus-manage-targets remove <host>"
echo "  Scan:     scripts/argus-discover --subnet <CIDR> --output deploy/observability/argus-targets.json"
echo "  Verify:   scripts/argus-manage-targets verify"
echo ""
echo "Prometheus reloads targets automatically within 30 seconds."

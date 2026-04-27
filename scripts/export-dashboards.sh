#!/usr/bin/env bash
# Export ARGUS Grafana dashboards for import into an external Grafana instance.
#
# Usage:
#   ./scripts/export-dashboards.sh                 # copies to dist/grafana-dashboards/
#   ./scripts/export-dashboards.sh --import URL     # import into a live Grafana via API
#
# The dashboards use ${DS_PROMETHEUS} datasource variables. When imported via
# Grafana's UI (Dashboards > Import), it will prompt you to select your
# Prometheus datasource. When imported via API, the script resolves the
# variable to the default Prometheus datasource.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$REPO_ROOT/deploy/observability/grafana/dashboards"
DIST_DIR="$REPO_ROOT/dist/grafana-dashboards"

import_url=""
api_key=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --import)
            import_url="$2"
            shift 2
            ;;
        --api-key)
            api_key="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [--import GRAFANA_URL] [--api-key TOKEN]" >&2
            exit 1
            ;;
    esac
done

INPUTS_BLOCK='{"name":"DS_PROMETHEUS","label":"Prometheus","description":"Prometheus datasource","type":"datasource","pluginId":"prometheus","pluginName":"Prometheus"}'

if [[ -z "$import_url" ]]; then
    mkdir -p "$DIST_DIR"
    for f in "$SRC_DIR"/*.json; do
        sed 's/"uid": "DS_PROMETHEUS"/"uid": "${DS_PROMETHEUS}"/g' "$f" \
          | jq --argjson inputs "[$INPUTS_BLOCK]" '. + {"__inputs": $inputs}' \
          > "$DIST_DIR/$(basename "$f")"
    done
    echo "Exported dashboards to $DIST_DIR/"
    echo "(converted for Grafana import: \${DS_PROMETHEUS} variable + __inputs block added)"
    echo ""
    echo "To import into Grafana:"
    echo "  1. Open Grafana > Dashboards > Import"
    echo "  2. Upload any JSON file from $DIST_DIR/"
    echo "  3. Select your Prometheus datasource when prompted"
    echo ""
    echo "Or import via API:"
    echo "  $0 --import http://grafana:3000 --api-key YOUR_API_KEY"
    exit 0
fi

auth_header=""
if [[ -n "$api_key" ]]; then
    auth_header="Authorization: Bearer $api_key"
else
    auth_header="Authorization: Basic $(echo -n admin:admin | base64)"
    echo "Warning: using default admin:admin credentials (pass --api-key for non-dev environments)" >&2
fi

for f in "$SRC_DIR"/*.json; do
    name=$(basename "$f" .json)
    echo -n "Importing $name... "

    payload=$(jq '{dashboard: ., overwrite: true, folderId: 0}' "$f")

    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${import_url}/api/dashboards/db" \
        -H "Content-Type: application/json" \
        -H "$auth_header" \
        -d "$payload")

    if [[ "$status" == "200" ]]; then
        echo "ok"
    else
        echo "failed (HTTP $status)"
    fi
done

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "Starting ARGUS observability stack..."
docker compose up -d

echo ""
echo "Services:"
echo "  Grafana:      http://localhost:3000"
echo "  Prometheus:   http://localhost:9091"
echo "  Alertmanager: http://localhost:9093"
echo ""
echo "To add ARGUS targets, edit prometheus.yml scrape_configs."
echo "Then: docker compose restart prometheus"

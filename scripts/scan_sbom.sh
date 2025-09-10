#!/usr/bin/env bash
set -euo pipefail
sbom=${1:-sbom.json}
echo "Scanning SBOM: $sbom"
trivy sbom "$sbom" -f json -o vulns.json || true
echo "Wrote vulns.json"

#!/usr/bin/env bash
set -euo pipefail
target=${1:-.}
echo "Generating SBOM for: $target"
syft dir:"${target}" -o cyclonedx-json > sbom.json
echo "Wrote sbom.json"

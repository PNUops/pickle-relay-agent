#!/usr/bin/env bash
# Static build into dist/ (deployed to the relay by the operator runbook).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o dist/relay-agent ./cmd/relay-agent
echo "built dist/relay-agent ($(go env GOOS)/$(go env GOARCH))"

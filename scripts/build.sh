#!/usr/bin/env bash
# Static build into dist/ (deployed to the relay by the operator runbook).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
# Stamp the reported agent version from git (falls back to "dev" outside a tag).
version="$(git describe --tags --always 2>/dev/null || echo dev)"
CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w -X github.com/pnuops/pickle-relay-agent/internal/version.Version=${version}" \
  -o dist/relay-agent ./cmd/relay-agent
echo "built dist/relay-agent ${version} ($(go env GOOS)/$(go env GOARCH))"

#!/bin/bash
set -e

# Build script for devkit with embedded egress proxy binaries

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
EMBEDDED_DIR="$ROOT_DIR/internal/embedded"

echo "Building devkit with embedded egress proxy..."

# Build egress proxy for Linux amd64
echo "  Building egressproxy for linux/amd64..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$EMBEDDED_DIR/egressproxy-linux-amd64" ./cmd/egressproxy

# Build egress proxy for Linux arm64
echo "  Building egressproxy for linux/arm64..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$EMBEDDED_DIR/egressproxy-linux-arm64" ./cmd/egressproxy

# Build devkit for the host platform
echo "  Building devkit..."
go build -o "$ROOT_DIR/devkit" ./cmd/devkit

echo "Done! Binary at: $ROOT_DIR/devkit"
echo ""
echo "To install:"
echo "  sudo cp devkit /usr/local/bin/"

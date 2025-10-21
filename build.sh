#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/bin"

mkdir -p "$OUTPUT_DIR"

echo "Building Password Checker for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -o "$OUTPUT_DIR/password-checker" ./cmd/password-checker

echo "Build complete: $OUTPUT_DIR/password-checker"

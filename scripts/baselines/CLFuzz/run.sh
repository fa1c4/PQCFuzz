#!/usr/bin/env bash
set -euo pipefail

BASELINE_DIR="$1"
BUILD_DIR="$2"
RUN_DIR="$3"
shift 3

mkdir -p "$RUN_DIR"

echo "[CLFuzz] run directory: $RUN_DIR"

if [ -x "$BUILD_DIR/clfuzz" ]; then
  "$BUILD_DIR/clfuzz" -artifact_prefix="$RUN_DIR/" "$@"
else
  echo "clfuzz binary not found in $BUILD_DIR." >&2
  echo "Run: scripts/run_baseline.sh CLFuzz build" >&2
  exit 1
fi

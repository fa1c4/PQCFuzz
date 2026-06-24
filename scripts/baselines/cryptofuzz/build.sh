#!/usr/bin/env bash
set -euo pipefail

BASELINE_DIR="$1"
BUILD_DIR="$2"
RUN_DIR="$3"
shift 3

mkdir -p "$BUILD_DIR" "$RUN_DIR"

BUILD_DIR_ABS="$(realpath "$BUILD_DIR")"

echo "[cryptofuzz] build directory: $BUILD_DIR"
echo "[cryptofuzz] run directory: $RUN_DIR"

make -C "$BASELINE_DIR" \
  BUILD_DIR="$BUILD_DIR_ABS" \
  "$@"

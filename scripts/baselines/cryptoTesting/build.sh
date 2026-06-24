#!/usr/bin/env bash
set -euo pipefail

BASELINE_DIR="$1"
BUILD_DIR="$2"
RUN_DIR="$3"
shift 3

mkdir -p "$BUILD_DIR" "$RUN_DIR"

BUILD_DIR_ABS="$(realpath "$BUILD_DIR")"
RUN_DIR_ABS="$(realpath "$RUN_DIR")"

echo "[cryptoTesting] build directory: $BUILD_DIR"
echo "[cryptoTesting] run directory: $RUN_DIR"

if [ -x "$BASELINE_DIR/build.sh" ]; then
  (
    cd "$BASELINE_DIR"
    PQCDF_BUILD_DIR="$BUILD_DIR_ABS" \
    PQCDF_RUN_DIR="$RUN_DIR_ABS" \
    ./build.sh "$@"
  )
else
  make -C "$BASELINE_DIR" "$@"
fi

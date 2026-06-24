#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/run_baseline.sh <baseline> <command> [extra args...]

Baselines:
  cryptofuzz
  CLFuzz
  cryptoTesting

Commands:
  build         Build the baseline into workspace/<baseline>/targets-build
  run           Run the baseline with outputs under workspace/<baseline>/targets-run
  clean         Remove workspace/<baseline>/targets-build and workspace/<baseline>/targets-run
  docker-build  Build the baseline Docker image
  docker-run    Start an interactive container for the baseline

Examples:
  scripts/run_baseline.sh cryptofuzz build
  scripts/run_baseline.sh CLFuzz run
  scripts/run_baseline.sh cryptoTesting docker-build
EOF
}

if [ "$#" -lt 2 ]; then
  usage
  exit 2
fi

BASELINE="$1"
COMMAND="$2"
shift 2

case "$BASELINE" in
  cryptofuzz)
    BASELINE_DIR="baselines/cryptofuzz"
    IMAGE_NAME="pqcdf-baseline-cryptofuzz"
    ;;
  CLFuzz)
    BASELINE_DIR="baselines/CLFuzz"
    IMAGE_NAME="pqcdf-baseline-clfuzz"
    ;;
  cryptoTesting)
    BASELINE_DIR="baselines/cryptoTesting"
    IMAGE_NAME="pqcdf-baseline-cryptotesting"
    ;;
  *)
    echo "Unknown baseline: $BASELINE" >&2
    usage
    exit 2
    ;;
esac

BUILD_DIR="workspace/${BASELINE}/targets-build"
RUN_DIR="workspace/${BASELINE}/targets-run"

mkdir -p "$BUILD_DIR" "$RUN_DIR"

case "$COMMAND" in
  build)
    if [ -x "scripts/baselines/${BASELINE}/build.sh" ]; then
      "scripts/baselines/${BASELINE}/build.sh" "$BASELINE_DIR" "$BUILD_DIR" "$RUN_DIR" "$@"
    else
      echo "Missing build wrapper: scripts/baselines/${BASELINE}/build.sh" >&2
      exit 1
    fi
    ;;

  run)
    if [ -x "scripts/baselines/${BASELINE}/run.sh" ]; then
      "scripts/baselines/${BASELINE}/run.sh" "$BASELINE_DIR" "$BUILD_DIR" "$RUN_DIR" "$@"
    else
      echo "Missing run wrapper: scripts/baselines/${BASELINE}/run.sh" >&2
      exit 1
    fi
    ;;

  clean)
    rm -rf "$BUILD_DIR" "$RUN_DIR"
    mkdir -p "$BUILD_DIR" "$RUN_DIR"
    touch "$BUILD_DIR/.gitkeep" "$RUN_DIR/.gitkeep"
    ;;

  docker-build)
    docker build \
      -t "$IMAGE_NAME" \
      -f "${BASELINE_DIR}/Dockerfile" \
      "$BASELINE_DIR"
    ;;

  docker-run)
    docker run --rm -it \
      -v "$(pwd)":/workspace/PQC-DF \
      -w /workspace/PQC-DF \
      "$IMAGE_NAME" \
      bash
    ;;

  *)
    echo "Unknown command: $COMMAND" >&2
    usage
    exit 2
    ;;
esac

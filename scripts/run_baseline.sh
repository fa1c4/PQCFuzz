#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/run_baseline.sh <baseline> <command> [extra args...]

Baselines:
  cryptofuzz
  CLFuzz
  libFuzzer
  cryptoTesting

Commands:
  build         Build the baseline into <workspace-root>/<baseline>/targets-build
  run           Run the baseline with outputs under <workspace-root>/<baseline>/targets-run
  clean         Remove <workspace-root>/<baseline>/targets-build and <workspace-root>/<baseline>/targets-run
  docker-build  Build the baseline Docker image
  docker-run    Start an interactive container for the baseline

Environment:
  PQCDF_WORKSPACE_ROOT  Override the workspace root. Default: workspace.

Examples:
  scripts/run_baseline.sh cryptofuzz build
  scripts/run_baseline.sh CLFuzz run
  scripts/run_baseline.sh libFuzzer run --version 0.14.0 --target all --mode smoke
  scripts/run_baseline.sh cryptoTesting docker-build
  scripts/run_baseline.sh cryptoTesting run --version 0.14.0

docker-build options:
  --base-image IMAGE  Override Dockerfile BASE_IMAGE when supported.
                      Also available via PQCDF_DOCKER_BASE_IMAGE.
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
  libFuzzer)
    BASELINE_DIR="baselines/libFuzzer"
    IMAGE_NAME="pqcdf-baseline-libfuzzer"
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

WORKSPACE_ROOT="${PQCDF_WORKSPACE_ROOT:-workspace}"
WORKSPACE_ROOT="${WORKSPACE_ROOT%/}"
if [ -z "$WORKSPACE_ROOT" ]; then
  WORKSPACE_ROOT="."
fi

BUILD_DIR="${WORKSPACE_ROOT}/${BASELINE}/targets-build"
RUN_DIR="${WORKSPACE_ROOT}/${BASELINE}/targets-run"

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
    if ! rm -rf "$BUILD_DIR" "$RUN_DIR" 2>/tmp/pqcdf-run-baseline-clean.err; then
      if [ "$BASELINE" = "cryptoTesting" ] &&
        command -v docker >/dev/null 2>&1 &&
        docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        mkdir -p "$BUILD_DIR" "$RUN_DIR"
        BUILD_DIR_ABS="$(realpath "$BUILD_DIR")"
        RUN_DIR_ABS="$(realpath "$RUN_DIR")"
        docker run --rm \
          -v "${BUILD_DIR_ABS}:/pqcdf-build" \
          -v "${RUN_DIR_ABS}:/pqcdf-run" \
          "$IMAGE_NAME" \
          bash -lc 'rm -rf /pqcdf-build/* /pqcdf-build/.[!.]* /pqcdf-build/..?* /pqcdf-run/* /pqcdf-run/.[!.]* /pqcdf-run/..?*'
      else
        echo "Failed to clean $BUILD_DIR and $RUN_DIR." >&2
        cat /tmp/pqcdf-run-baseline-clean.err >&2
        exit 1
      fi
    fi
    mkdir -p "$BUILD_DIR" "$RUN_DIR"
    touch "$BUILD_DIR/.gitkeep" "$RUN_DIR/.gitkeep"
    ;;

  docker-build)
    DOCKER_BUILD_ARGS=()
    if [ -n "${PQCDF_DOCKER_BASE_IMAGE:-}" ]; then
      DOCKER_BUILD_ARGS+=(--build-arg "BASE_IMAGE=${PQCDF_DOCKER_BASE_IMAGE}")
    fi
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --base-image)
          if [ "$#" -lt 2 ]; then
            echo "--base-image requires an image name" >&2
            exit 2
          fi
          DOCKER_BUILD_ARGS+=(--build-arg "BASE_IMAGE=$2")
          shift 2
          ;;
        --)
          shift
          DOCKER_BUILD_ARGS+=("$@")
          break
          ;;
        *)
          DOCKER_BUILD_ARGS+=("$1")
          shift
          ;;
      esac
    done

    docker build \
      "${DOCKER_BUILD_ARGS[@]}" \
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

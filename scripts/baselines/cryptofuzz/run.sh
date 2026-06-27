#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/run_baseline.sh cryptofuzz run [options] [extra libFuzzer args...]

Options:
  --version VERSION             Run against a supported liboqs version. Default: 0.14.0.
  --mode smoke|full             Run a short smoke campaign or a bounded full campaign. Default: smoke.
  --max-total-time SECONDS      libFuzzer -max_total_time value. Full default: 86400.
  --runs N                      libFuzzer -runs value. Smoke default: 1000.
  --jobs N                      libFuzzer -jobs value. Default: 1.
  --workers N                   libFuzzer -workers value. Default: 1.
  --seed N                      libFuzzer -seed value.
  -h, --help                    Show this help.

Supported versions:
  0.14.0
  0.8.0
  0.4.0
EOF
}

BASELINE_DIR="$1"
BUILD_DIR="$2"
RUN_DIR="$3"
shift 3

VERSION="0.14.0"
MODE="smoke"
MAX_TOTAL_TIME=""
RUNS=""
JOBS="1"
WORKERS="1"
SEED=""
EXTRA_ARGS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --version." >&2
        exit 2
      fi
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#--version=}"
      shift
      ;;
    --mode)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --mode." >&2
        exit 2
      fi
      MODE="$2"
      shift 2
      ;;
    --mode=*)
      MODE="${1#--mode=}"
      shift
      ;;
    --max-total-time)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --max-total-time." >&2
        exit 2
      fi
      MAX_TOTAL_TIME="$2"
      shift 2
      ;;
    --max-total-time=*)
      MAX_TOTAL_TIME="${1#--max-total-time=}"
      shift
      ;;
    --runs)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --runs." >&2
        exit 2
      fi
      RUNS="$2"
      shift 2
      ;;
    --runs=*)
      RUNS="${1#--runs=}"
      shift
      ;;
    --jobs)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --jobs." >&2
        exit 2
      fi
      JOBS="$2"
      shift 2
      ;;
    --jobs=*)
      JOBS="${1#--jobs=}"
      shift
      ;;
    --workers)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --workers." >&2
        exit 2
      fi
      WORKERS="$2"
      shift 2
      ;;
    --workers=*)
      WORKERS="${1#--workers=}"
      shift
      ;;
    --seed)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --seed." >&2
        exit 2
      fi
      SEED="$2"
      shift 2
      ;;
    --seed=*)
      SEED="${1#--seed=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      EXTRA_ARGS+=("$1")
      shift
      ;;
  esac
done

case "$VERSION" in
  0.14.0|0.8.0|0.4.0) ;;
  *)
    echo "Unsupported cryptofuzz liboqs version: $VERSION" >&2
    echo "Supported versions: 0.14.0, 0.8.0, 0.4.0" >&2
    exit 2
    ;;
esac

case "$MODE" in
  smoke|full) ;;
  *)
    echo "Unsupported cryptofuzz mode: $MODE" >&2
    echo "Supported modes: smoke, full" >&2
    exit 2
    ;;
esac

if [ -z "$RUNS" ] && [ "$MODE" = "smoke" ]; then
  RUNS="1000"
fi
if [ -z "$MAX_TOTAL_TIME" ] && [ "$MODE" = "full" ]; then
  MAX_TOTAL_TIME="86400"
fi

mkdir -p "$BUILD_DIR" "$RUN_DIR"

IMAGE_NAME="pqcdf-baseline-cryptofuzz"

if [ "${PQCDF_CRYPTOFUZZ_IN_DOCKER:-0}" != "1" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required to run cryptofuzz/liboqs through this wrapper." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed, but the Docker daemon is not available to this user." >&2
    exit 1
  fi
  if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Docker image not found: $IMAGE_NAME" >&2
    echo "Run: scripts/run_baseline.sh cryptofuzz docker-build" >&2
    exit 1
  fi

  HOST_UID="$(id -u)"
  HOST_GID="$(id -g)"
  FORWARDED_ARGS=(
    scripts/baselines/cryptofuzz/run.sh
    "$BASELINE_DIR"
    "$BUILD_DIR"
    "$RUN_DIR"
    --version "$VERSION"
    --mode "$MODE"
  )
  if [ -n "$MAX_TOTAL_TIME" ]; then
    FORWARDED_ARGS+=(--max-total-time "$MAX_TOTAL_TIME")
  fi
  if [ -n "$RUNS" ]; then
    FORWARDED_ARGS+=(--runs "$RUNS")
  fi
  FORWARDED_ARGS+=(--jobs "$JOBS" --workers "$WORKERS")
  if [ -n "$SEED" ]; then
    FORWARDED_ARGS+=(--seed "$SEED")
  fi
  FORWARDED_ARGS+=("${EXTRA_ARGS[@]}")

  docker run --rm \
    -e PQCDF_CRYPTOFUZZ_IN_DOCKER=1 \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    -e PQCDF_CHOWN_BUILD_DIR="$BUILD_DIR" \
    -e PQCDF_CHOWN_RUN_DIR="$RUN_DIR" \
    -v "$(pwd)":/workspace/PQC-DF \
    -w /workspace/PQC-DF \
    "$IMAGE_NAME" \
    bash -lc 'trap "chown -R ${HOST_UID}:${HOST_GID} \"${PQCDF_CHOWN_BUILD_DIR}\" \"${PQCDF_CHOWN_RUN_DIR}\" 2>/dev/null || true" EXIT; "$@"' \
    bash "${FORWARDED_ARGS[@]}"
  exit $?
fi

BUILD_DIR_ABS="$(realpath "$BUILD_DIR")"
RUN_DIR_ABS="$(realpath "$RUN_DIR")"
VERSION_BUILD_DIR="${BUILD_DIR_ABS}/liboqs-${VERSION}"
VERSION_RUN_DIR="${RUN_DIR_ABS}/liboqs-${VERSION}"
BINARY="${VERSION_BUILD_DIR}/cryptofuzz/cryptofuzz"
LOG_DIR="${VERSION_RUN_DIR}/logs"
CORPUS_DIR="${VERSION_RUN_DIR}/corpus"
CRASH_DIR="${VERSION_RUN_DIR}/crashes"
ARTIFACT_DIR="${VERSION_RUN_DIR}/artifacts"
SUMMARY_FILE="${VERSION_RUN_DIR}/summary.json"
LOG_FILE="${LOG_DIR}/${MODE}.log"

if [ ! -x "$BINARY" ]; then
  echo "cryptofuzz binary not found: $BINARY" >&2
  echo "Run: scripts/run_baseline.sh cryptofuzz build --version $VERSION" >&2
  exit 1
fi

mkdir -p "$LOG_DIR" "$CORPUS_DIR" "$CRASH_DIR" "$ARTIFACT_DIR"

ARGS=(
  "--operations=OQS_KEM_SelfTest,OQS_SIG_SelfTest"
  "--force-module=liboqs"
  "--min-modules=1"
  "-artifact_prefix=${CRASH_DIR}/"
  "-jobs=${JOBS}"
  "-workers=${WORKERS}"
)

if [ -n "$RUNS" ]; then
  ARGS+=("-runs=${RUNS}")
fi
if [ -n "$MAX_TOTAL_TIME" ]; then
  ARGS+=("-max_total_time=${MAX_TOTAL_TIME}")
fi
if [ -n "$SEED" ]; then
  ARGS+=("-seed=${SEED}")
fi
ARGS+=("${EXTRA_ARGS[@]}")
ARGS+=("$CORPUS_DIR")

echo "[cryptofuzz] run directory: $VERSION_RUN_DIR"
echo "[cryptofuzz] liboqs version: $VERSION"
echo "[cryptofuzz] mode: $MODE"
echo "[cryptofuzz] log file: $LOG_FILE"

START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
"$BINARY" "${ARGS[@]}" 2>&1 | tee "$LOG_FILE"
STATUS="${PIPESTATUS[0]}"
set -e
END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

CRYPTOFUZZ_SUMMARY_FILE="$SUMMARY_FILE" \
CRYPTOFUZZ_VERSION="$VERSION" \
CRYPTOFUZZ_MODE="$MODE" \
CRYPTOFUZZ_STATUS="$STATUS" \
CRYPTOFUZZ_START_TS="$START_TS" \
CRYPTOFUZZ_END_TS="$END_TS" \
CRYPTOFUZZ_BINARY="$BINARY" \
CRYPTOFUZZ_LOG_FILE="$LOG_FILE" \
CRYPTOFUZZ_CORPUS_DIR="$CORPUS_DIR" \
CRYPTOFUZZ_CRASH_DIR="$CRASH_DIR" \
CRYPTOFUZZ_ARTIFACT_DIR="$ARTIFACT_DIR" \
python3 - "${ARGS[@]}" <<'PY'
import json
import os
import sys

summary_path = os.environ["CRYPTOFUZZ_SUMMARY_FILE"]
crash_dir = os.environ["CRYPTOFUZZ_CRASH_DIR"]
corpus_dir = os.environ["CRYPTOFUZZ_CORPUS_DIR"]
artifact_dir = os.environ["CRYPTOFUZZ_ARTIFACT_DIR"]
log_file = os.environ["CRYPTOFUZZ_LOG_FILE"]

summary = {
    "baseline": "cryptofuzz",
    "target": "liboqs",
    "version": os.environ["CRYPTOFUZZ_VERSION"],
    "mode": os.environ["CRYPTOFUZZ_MODE"],
    "status": int(os.environ["CRYPTOFUZZ_STATUS"]),
    "started_at": os.environ["CRYPTOFUZZ_START_TS"],
    "ended_at": os.environ["CRYPTOFUZZ_END_TS"],
    "binary": os.environ["CRYPTOFUZZ_BINARY"],
    "log": log_file,
    "corpus_dir": corpus_dir,
    "crash_dir": crash_dir,
    "artifact_dir": artifact_dir,
    "args": sys.argv[1:],
    "crashes": sorted(
        name for name in os.listdir(crash_dir)
        if name.startswith(("crash-", "timeout-", "leak-", "oom-"))
    ) if os.path.isdir(crash_dir) else [],
}

with open(summary_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, sort_keys=True)
    f.write("\n")
PY

echo "[cryptofuzz] summary: $SUMMARY_FILE"

if [ "$STATUS" -ne 0 ]; then
  echo "[cryptofuzz] run failed with status $STATUS" >&2
  echo "[cryptofuzz] see log: $LOG_FILE" >&2
  exit "$STATUS"
fi

echo "[cryptofuzz] run completed"

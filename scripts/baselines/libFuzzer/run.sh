#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/run_baseline.sh libFuzzer run [options] [extra libFuzzer args...]

Options:
  --version VERSION             Run against a supported liboqs version. Default: 0.14.0.
  --target kem|sig|all          Run one harness or both harnesses. Default: all.
  --mode smoke|full             Run a short smoke campaign or a bounded full campaign. Default: smoke.
  --max-total-time SECONDS      libFuzzer -max_total_time value. Full default: 86400.
  --runs N                      libFuzzer -runs value. Smoke default: 1000.
  --jobs N                      libFuzzer -jobs value. Default: 1.
  --workers N                   libFuzzer -workers value. Default: 1.
  --seed N                      libFuzzer -seed value. Default: 1.
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
TARGET="all"
MODE="smoke"
MAX_TOTAL_TIME=""
RUNS=""
JOBS="1"
WORKERS="1"
SEED="1"
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
    --target)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --target." >&2
        exit 2
      fi
      TARGET="$2"
      shift 2
      ;;
    --target=*)
      TARGET="${1#--target=}"
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
    --)
      shift
      EXTRA_ARGS+=("$@")
      break
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
    echo "Unsupported libFuzzer liboqs version: $VERSION" >&2
    echo "Supported versions: 0.14.0, 0.8.0, 0.4.0" >&2
    exit 2
    ;;
esac

case "$TARGET" in
  kem|sig|all) ;;
  *)
    echo "Unsupported libFuzzer target: $TARGET" >&2
    echo "Supported targets: kem, sig, all" >&2
    exit 2
    ;;
esac

case "$MODE" in
  smoke|full) ;;
  *)
    echo "Unsupported libFuzzer mode: $MODE" >&2
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

IMAGE_NAME="pqcdf-baseline-libfuzzer"

if [ "${PQCDF_LIBFUZZER_IN_DOCKER:-0}" != "1" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required to run libFuzzer/liboqs through this wrapper." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed, but the Docker daemon is not available to this user." >&2
    exit 1
  fi
  if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Docker image not found: $IMAGE_NAME" >&2
    echo "Run: scripts/run_baseline.sh libFuzzer docker-build" >&2
    exit 1
  fi

  HOST_UID="$(id -u)"
  HOST_GID="$(id -g)"
  FORWARDED_ARGS=(
    scripts/baselines/libFuzzer/run.sh
    "$BASELINE_DIR"
    "$BUILD_DIR"
    "$RUN_DIR"
    --version "$VERSION"
    --target "$TARGET"
    --mode "$MODE"
  )
  if [ -n "$MAX_TOTAL_TIME" ]; then
    FORWARDED_ARGS+=(--max-total-time "$MAX_TOTAL_TIME")
  fi
  if [ -n "$RUNS" ]; then
    FORWARDED_ARGS+=(--runs "$RUNS")
  fi
  FORWARDED_ARGS+=(--jobs "$JOBS" --workers "$WORKERS" --seed "$SEED")
  FORWARDED_ARGS+=("${EXTRA_ARGS[@]}")

  docker run --rm \
    -e PQCDF_LIBFUZZER_IN_DOCKER=1 \
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
FUZZER_BUILD_DIR="${VERSION_BUILD_DIR}/libFuzzer"
AGGREGATE_SUMMARY_FILE="${VERSION_RUN_DIR}/summary.json"

if [ "$TARGET" = "all" ]; then
  TARGETS=(kem sig)
else
  TARGETS=("$TARGET")
fi

mkdir -p "$VERSION_RUN_DIR"

echo "[libFuzzer] run directory: $VERSION_RUN_DIR"
echo "[libFuzzer] liboqs version: $VERSION"
echo "[libFuzzer] target: $TARGET"
echo "[libFuzzer] mode: $MODE"

ROOT_START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OVERALL_STATUS=0
TARGET_SUMMARIES=()

write_target_summary() {
  local summary_file="$1"
  local target_name="$2"
  local status="$3"
  local start_ts="$4"
  local end_ts="$5"
  local binary="$6"
  local log_file="$7"
  local corpus_dir="$8"
  local crash_dir="$9"
  local artifact_dir="${10}"
  shift 10

  LIBFUZZER_SUMMARY_FILE="$summary_file" \
  LIBFUZZER_VERSION="$VERSION" \
  LIBFUZZER_TARGET="$target_name" \
  LIBFUZZER_MODE="$MODE" \
  LIBFUZZER_STATUS="$status" \
  LIBFUZZER_START_TS="$start_ts" \
  LIBFUZZER_END_TS="$end_ts" \
  LIBFUZZER_BINARY="$binary" \
  LIBFUZZER_LOG_FILE="$log_file" \
  LIBFUZZER_CORPUS_DIR="$corpus_dir" \
  LIBFUZZER_CRASH_DIR="$crash_dir" \
  LIBFUZZER_ARTIFACT_DIR="$artifact_dir" \
  python3 - "$@" <<'PY'
import json
import os
import sys

summary_path = os.environ["LIBFUZZER_SUMMARY_FILE"]
crash_dir = os.environ["LIBFUZZER_CRASH_DIR"]
artifact_dir = os.environ["LIBFUZZER_ARTIFACT_DIR"]
log_file = os.environ["LIBFUZZER_LOG_FILE"]
log_dir = os.path.dirname(log_file)

summary = {
    "baseline": "libFuzzer",
    "target": os.environ["LIBFUZZER_TARGET"],
    "version": os.environ["LIBFUZZER_VERSION"],
    "mode": os.environ["LIBFUZZER_MODE"],
    "status": int(os.environ["LIBFUZZER_STATUS"]),
    "started_at": os.environ["LIBFUZZER_START_TS"],
    "ended_at": os.environ["LIBFUZZER_END_TS"],
    "binary": os.environ["LIBFUZZER_BINARY"],
    "log": log_file,
    "corpus_dir": os.environ["LIBFUZZER_CORPUS_DIR"],
    "crash_dir": crash_dir,
    "artifact_dir": artifact_dir,
    "args": sys.argv[1:],
    "crashes": sorted(
        name for name in os.listdir(crash_dir)
        if name.startswith(("crash-", "timeout-", "leak-", "oom-"))
    ) if os.path.isdir(crash_dir) else [],
    "worker_logs": sorted(
        name for name in os.listdir(log_dir)
        if name.startswith("fuzz-") and name.endswith(".log")
    ) if os.path.isdir(log_dir) else [],
}

with open(summary_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

for TARGET_NAME in "${TARGETS[@]}"; do
  TARGET_RUN_DIR="${VERSION_RUN_DIR}/${TARGET_NAME}"
  LOG_DIR="${TARGET_RUN_DIR}/logs"
  CORPUS_DIR="${TARGET_RUN_DIR}/corpus"
  CRASH_DIR="${TARGET_RUN_DIR}/crashes"
  ARTIFACT_DIR="${TARGET_RUN_DIR}/artifacts"
  TARGET_SUMMARY_FILE="${TARGET_RUN_DIR}/summary.json"
  LOG_FILE="${LOG_DIR}/${MODE}.log"
  BINARY="${FUZZER_BUILD_DIR}/fuzz_${TARGET_NAME}"

  mkdir -p "$LOG_DIR" "$CORPUS_DIR" "$CRASH_DIR" "$ARTIFACT_DIR"

  ARGS=(
    "-artifact_prefix=${CRASH_DIR}/"
    "-jobs=${JOBS}"
    "-workers=${WORKERS}"
    "-seed=${SEED}"
  )
  if [ -n "$RUNS" ]; then
    ARGS+=("-runs=${RUNS}")
  fi
  if [ -n "$MAX_TOTAL_TIME" ]; then
    ARGS+=("-max_total_time=${MAX_TOTAL_TIME}")
  fi
  ARGS+=("${EXTRA_ARGS[@]}")
  ARGS+=("$CORPUS_DIR")

  echo "[libFuzzer] ${TARGET_NAME} log file: $LOG_FILE"
  START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  if [ ! -x "$BINARY" ]; then
    STATUS=127
    {
      echo "libFuzzer binary not found: $BINARY"
      echo "Run: scripts/run_baseline.sh libFuzzer build --version $VERSION"
    } 2>&1 | tee "$LOG_FILE"
  else
    set +e
    (cd "$LOG_DIR" && "$BINARY" "${ARGS[@]}") 2>&1 | tee "$LOG_FILE"
    STATUS="${PIPESTATUS[0]}"
    set -e
  fi

  END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  write_target_summary "$TARGET_SUMMARY_FILE" "$TARGET_NAME" "$STATUS" "$START_TS" "$END_TS" "$BINARY" "$LOG_FILE" "$CORPUS_DIR" "$CRASH_DIR" "$ARTIFACT_DIR" "${ARGS[@]}"
  TARGET_SUMMARIES+=("$TARGET_SUMMARY_FILE")
  echo "[libFuzzer] ${TARGET_NAME} summary: $TARGET_SUMMARY_FILE"

  if [ "$STATUS" -ne 0 ] && [ "$OVERALL_STATUS" -eq 0 ]; then
    OVERALL_STATUS="$STATUS"
  fi
done

ROOT_END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 - "$AGGREGATE_SUMMARY_FILE" "$VERSION" "$TARGET" "$MODE" "$OVERALL_STATUS" "$ROOT_START_TS" "$ROOT_END_TS" "${TARGET_SUMMARIES[@]}" <<'PY'
import json
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
runs = [json.loads(Path(path).read_text(encoding="utf-8")) for path in sys.argv[8:]]
summary = {
    "baseline": "libFuzzer",
    "version": sys.argv[2],
    "target": sys.argv[3],
    "mode": sys.argv[4],
    "status": int(sys.argv[5]),
    "started_at": sys.argv[6],
    "ended_at": sys.argv[7],
    "runs": runs,
}

with summary_path.open("w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, sort_keys=True)
    f.write("\n")
PY

echo "[libFuzzer] summary: $AGGREGATE_SUMMARY_FILE"

if [ "$OVERALL_STATUS" -ne 0 ]; then
  echo "[libFuzzer] one or more runs failed; see summaries under $VERSION_RUN_DIR" >&2
  exit "$OVERALL_STATUS"
fi

echo "[libFuzzer] run completed"

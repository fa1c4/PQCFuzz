#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/run_baseline.sh cryptoTesting run [options]

Options:
  --version VERSION             Reproduce cryptoTesting on a supported liboqs version.
  --mode functional|vanilla     Run functional cryptoTesting or its vanilla AFL baseline. Default: functional.
  --workers N|auto              Bound the driver pool (default: 1, or CRYPTO_TESTING_WORKERS).
  --geninput-timeout SECONDS    Independent GenInput setup timeout. Default: 10.
  --task-max-time SECONDS       Maximum AFL time for each scheduled functional task.
  --max-total-time SECONDS      End fuzzing cleanly after this many seconds.
  --skip-core-pattern-check     Skip the host AFL core_pattern preflight.
  -h, --help                    Show this help.

Supported versions:
  0.14.0                        Uses upstream target ches_liboqs.
  0.8.0                         Uses upstream target cur_liboqs.
  0.4.0                         Uses upstream target mid_liboqs.

Examples:
  scripts/run_baseline.sh cryptoTesting run --version 0.14.0
  scripts/run_baseline.sh cryptoTesting run --version 0.8.0
  scripts/run_baseline.sh cryptoTesting run --version 0.4.0
  scripts/run_baseline.sh cryptoTesting run --version 0.14.0 --mode vanilla --workers 1
EOF
}

BASELINE_DIR="$1"
BUILD_DIR="$2"
RUN_DIR="$3"
shift 3

VERSION="0.14.0"
MODE="functional"
SKIP_CORE_PATTERN_CHECK=0
WORKERS="${CRYPTO_TESTING_WORKERS:-1}"
GENINPUT_TIMEOUT="${CRYPTO_TESTING_GENINPUT_TIMEOUT:-10}"
MAX_TOTAL_TIME="${CRYPTO_TESTING_MAX_TOTAL_TIME:-}"
TASK_MAX_TIME="${CRYPTO_TESTING_TASK_MAX_TIME:-}"

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
    --geninput-timeout)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --geninput-timeout." >&2
        exit 2
      fi
      GENINPUT_TIMEOUT="$2"
      shift 2
      ;;
    --geninput-timeout=*)
      GENINPUT_TIMEOUT="${1#--geninput-timeout=}"
      shift
      ;;
    --task-max-time)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --task-max-time." >&2
        exit 2
      fi
      TASK_MAX_TIME="$2"
      shift 2
      ;;
    --task-max-time=*)
      TASK_MAX_TIME="${1#--task-max-time=}"
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
    --skip-core-pattern-check)
      SKIP_CORE_PATTERN_CHECK=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ "$MODE" != "functional" ] && [ "$MODE" != "vanilla" ]; then
  echo "Unsupported cryptoTesting mode: $MODE" >&2
  echo "Supported modes: functional, vanilla" >&2
  exit 2
fi

if [ "$WORKERS" != "auto" ] && ! [[ "$WORKERS" =~ ^[1-9][0-9]*$ ]]; then
  echo "--workers must be a positive integer or auto." >&2
  exit 2
fi
if ! [[ "$GENINPUT_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
  echo "--geninput-timeout must be a positive integer." >&2
  exit 2
fi
if [ -n "$MAX_TOTAL_TIME" ] && ! [[ "$MAX_TOTAL_TIME" =~ ^[1-9][0-9]*$ ]]; then
  echo "--max-total-time must be a positive integer." >&2
  exit 2
fi
if [ -n "$TASK_MAX_TIME" ] && ! [[ "$TASK_MAX_TIME" =~ ^[1-9][0-9]*$ ]]; then
  echo "--task-max-time must be a positive integer." >&2
  exit 2
fi

IMAGE_NAME="pqcdf-baseline-cryptotesting"

case "$VERSION" in
  0.14.0)
    LIBOQS_TARGET="ches_liboqs"
    ;;
  0.8.0)
    LIBOQS_TARGET="cur_liboqs"
    ;;
  0.4.0)
    LIBOQS_TARGET="mid_liboqs"
    ;;
  *)
    echo "Unsupported cryptoTesting liboqs version: $VERSION" >&2
    echo "Supported versions: 0.14.0, 0.8.0, 0.4.0" >&2
    exit 2
    ;;
esac

mkdir -p "$BUILD_DIR" "$RUN_DIR"

BUILD_DIR_ABS="$(realpath "$BUILD_DIR")"
RUN_DIR_ABS="$(realpath "$RUN_DIR")"
BUILD_TARGET_DIR="${BUILD_DIR_ABS}/${LIBOQS_TARGET}"
CAMPAIGN_NAME="cryptoTesting-${VERSION}-${MODE}"
REPORTS_DIR="${RUN_DIR_ABS}/reports/${CAMPAIGN_NAME}"
LOG_DIR="${RUN_DIR_ABS}/logs"
LOG_FILE="${LOG_DIR}/${LIBOQS_TARGET}.${MODE}.log"
RAW_OUTPUT_DIR="${RUN_DIR_ABS}/raw/cryptoTesting-${VERSION}/${MODE}"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

echo "[cryptoTesting] build directory: $BUILD_DIR"
echo "[cryptoTesting] run directory: $RUN_DIR"
echo "[cryptoTesting] liboqs version: $VERSION"
echo "[cryptoTesting] liboqs target: $LIBOQS_TARGET"
echo "[cryptoTesting] mode: $MODE"
echo "[cryptoTesting] requested workers: $WORKERS"
echo "[cryptoTesting] GenInput setup timeout: ${GENINPUT_TIMEOUT}s"
if [ -n "$MAX_TOTAL_TIME" ]; then
  echo "[cryptoTesting] fuzzing time limit: ${MAX_TOTAL_TIME}s"
fi
if [ -n "$TASK_MAX_TIME" ]; then
  echo "[cryptoTesting] per-task AFL time limit: ${TASK_MAX_TIME}s"
fi

if [ "$SKIP_CORE_PATTERN_CHECK" -eq 0 ]; then
  CORE_PATTERN="$(cat /proc/sys/kernel/core_pattern 2>/dev/null || true)"
  if [ "$CORE_PATTERN" != "core" ]; then
    echo "Host /proc/sys/kernel/core_pattern is '$CORE_PATTERN', expected 'core'." >&2
    echo "Run: sudo bash -c 'echo core >/proc/sys/kernel/core_pattern'" >&2
    echo "Or pass --skip-core-pattern-check if this is managed externally." >&2
    exit 1
  fi
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run cryptoTesting through this wrapper." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed, but the Docker daemon is not available to this user." >&2
  exit 1
fi

if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "Docker image not found: $IMAGE_NAME" >&2
  echo "Run: scripts/run_baseline.sh cryptoTesting docker-build" >&2
  exit 1
fi

case "$BUILD_TARGET_DIR" in
  "$BUILD_DIR_ABS"/*) ;;
  *)
    echo "Refusing to recreate unexpected build target: $BUILD_TARGET_DIR" >&2
    exit 1
    ;;
esac

if rm -rf "$BUILD_TARGET_DIR" 2>/dev/null; then
  mkdir -p "$BUILD_TARGET_DIR"
else
  echo "[cryptoTesting] host cleanup could not remove $BUILD_TARGET_DIR"
  echo "[cryptoTesting] retrying cleanup inside Docker"
  docker run --rm \
    -v "${BUILD_DIR_ABS}:/pqcdf-build" \
    "$IMAGE_NAME" \
    bash -lc "rm -rf /pqcdf-build/${LIBOQS_TARGET} && mkdir -p /pqcdf-build/${LIBOQS_TARGET}"
fi

mkdir -p "$REPORTS_DIR" "$LOG_DIR" "$RAW_OUTPUT_DIR"

echo "[cryptoTesting] reports directory: $REPORTS_DIR"
echo "[cryptoTesting] raw output directory: $RAW_OUTPUT_DIR"
echo "[cryptoTesting] log file: $LOG_FILE"

REPRODUCE_MODE_ARGS=()
if [ "$MODE" = "vanilla" ]; then
  REPRODUCE_MODE_ARGS+=(baseline)
fi
REPRODUCE_TIME_ARGS=()
if [ -n "$MAX_TOTAL_TIME" ]; then
  REPRODUCE_TIME_ARGS+=(--max-total-time "$MAX_TOTAL_TIME")
fi
if [ -n "$TASK_MAX_TIME" ]; then
  REPRODUCE_TIME_ARGS+=(--task-max-time "$TASK_MAX_TIME")
fi

set +e
docker run --rm \
  -v "${BUILD_TARGET_DIR}:/fuzzing/${LIBOQS_TARGET}" \
  -v "${REPORTS_DIR}:/fuzzing/reports" \
  -v "${LOG_DIR}:/pqcdf-logs" \
  -v "${RAW_OUTPUT_DIR}:/pqcdf-results" \
  -w /fuzzing \
  "$IMAGE_NAME" \
  bash -lc "trap 'chown -R ${HOST_UID}:${HOST_GID} /fuzzing/${LIBOQS_TARGET} /fuzzing/reports /pqcdf-logs /pqcdf-results 2>/dev/null || true' EXIT; git config --global --add safe.directory /fuzzing/${LIBOQS_TARGET}; cd /fuzzing && bash -e reproduce.sh ${LIBOQS_TARGET} ${REPRODUCE_MODE_ARGS[*]} --output-root /pqcdf-results --reports-dir /fuzzing/reports --workers ${WORKERS} --geninput-timeout ${GENINPUT_TIMEOUT} --version ${VERSION} ${REPRODUCE_TIME_ARGS[*]}" \
  2>&1 | tee "$LOG_FILE"
DOCKER_STATUS="${PIPESTATUS[0]}"
set -e

if [ "$DOCKER_STATUS" -ne 0 ]; then
  echo "[cryptoTesting] reproduction failed with status $DOCKER_STATUS" >&2
  echo "[cryptoTesting] see log: $LOG_FILE" >&2
  exit "$DOCKER_STATUS"
fi

if [ ! -f "${RAW_OUTPUT_DIR}/manifest.json" ]; then
  echo "[cryptoTesting] successful container exit did not produce a raw-output manifest" >&2
  exit 1
fi
if ! python3 - "${RAW_OUTPUT_DIR}/manifest.json" "${REPORTS_DIR}" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
reports_dir = Path(sys.argv[2])
try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid cryptoTesting manifest: {error}")
if not manifest.get("tasks_terminal") and not manifest.get("budget_exhausted"):
    raise SystemExit("cryptoTesting did not finish all scheduled tasks")
if manifest.get("tasks_terminal") and not any(reports_dir.glob("*.xlsx")):
    raise SystemExit("cryptoTesting completed without its required XLSX report")
PY
then
  exit 1
fi

if [ -n "$MAX_TOTAL_TIME" ] && python3 - "${RAW_OUTPUT_DIR}/manifest.json" <<'PY'
import json
import sys
from pathlib import Path

try:
    manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if manifest.get("budget_exhausted") else 1)
PY
then
  echo "[cryptoTesting] reproduction completed at the configured fuzzing-time budget"
else
  echo "[cryptoTesting] reproduction completed"
fi
echo "[cryptoTesting] reports: $REPORTS_DIR"
echo "[cryptoTesting] raw outputs: $RAW_OUTPUT_DIR"
echo "[cryptoTesting] log: $LOG_FILE"

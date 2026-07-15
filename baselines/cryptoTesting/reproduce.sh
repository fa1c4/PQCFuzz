#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash reproduce.sh <library> [baseline] [options]

The optional ``baseline`` token selects the vanilla AFL workflow.  Omitting it
selects cryptoTesting's functional property fuzzer.

Options:
  --output-root PATH       Required durable root for raw AFL artifacts.
  --reports-dir PATH       Directory for generated reports (default: reports).
  --workers N|auto         Worker count, passed to the Python driver.
  --geninput-timeout SEC   Independent setup timeout (default: 10).
  --task-max-time SEC      Maximum AFL time for each scheduled functional task.
  --version VERSION        Version recorded in the raw manifest.
  --max-total-time SEC     End the current fuzzing workload at this budget.
EOF
}

LIBRARY="${1:-}"
if [ -z "$LIBRARY" ]; then
  usage >&2
  exit 2
fi
shift

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
MANIFEST_WRITER="${SCRIPT_DIR}/crypto_testing_manifest.py"

MODE="functional"
if [ "${1:-}" = "baseline" ]; then
  MODE="vanilla"
  shift
fi

OUTPUT_ROOT="${CRYPTO_TESTING_OUTPUT_ROOT:-}"
REPORTS_DIR="${CRYPTO_TESTING_REPORTS_DIR:-reports}"
WORKERS="${CRYPTO_TESTING_WORKERS:-1}"
GENINPUT_TIMEOUT="${CRYPTO_TESTING_GENINPUT_TIMEOUT:-10}"
VERSION="${CRYPTO_TESTING_VERSION:-unknown}"
MAX_TOTAL_TIME="${CRYPTO_TESTING_MAX_TOTAL_TIME:-}"
TASK_MAX_TIME="${CRYPTO_TESTING_TASK_MAX_TIME:-}"
BUDGET_EXHAUSTED=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-root) OUTPUT_ROOT="$2"; shift 2 ;;
    --reports-dir) REPORTS_DIR="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --geninput-timeout) GENINPUT_TIMEOUT="$2"; shift 2 ;;
    --task-max-time) TASK_MAX_TIME="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --max-total-time) MAX_TOTAL_TIME="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$OUTPUT_ROOT" ]; then
  echo "--output-root (or CRYPTO_TESTING_OUTPUT_ROOT) is required." >&2
  exit 2
fi
case "$WORKERS" in
  auto|*[!0-9]*|'') [ "$WORKERS" = "auto" ] || { echo "--workers must be positive or auto" >&2; exit 2; } ;;
  *) [ "$WORKERS" -gt 0 ] || { echo "--workers must be positive" >&2; exit 2; } ;;
esac
case "$GENINPUT_TIMEOUT" in
  *[!0-9]*|'') echo "--geninput-timeout must be a positive integer" >&2; exit 2 ;;
  *) [ "$GENINPUT_TIMEOUT" -gt 0 ] || { echo "--geninput-timeout must be positive" >&2; exit 2; } ;;
esac
case "$MAX_TOTAL_TIME" in
  '') ;;
  *[!0-9]*|0) echo "--max-total-time must be a positive integer" >&2; exit 2 ;;
esac
case "$TASK_MAX_TIME" in
  '') ;;
  *[!0-9]*|0) echo "--task-max-time must be a positive integer" >&2; exit 2 ;;
esac

mkdir -p "$OUTPUT_ROOT" "$REPORTS_DIR"
export CRYPTO_TESTING_OUTPUT_ROOT="$OUTPUT_ROOT"
export CRYPTO_TESTING_WORKERS="$WORKERS"
export CRYPTO_TESTING_GENINPUT_TIMEOUT="$GENINPUT_TIMEOUT"
export CRYPTO_TESTING_VERSION="$VERSION"
export CRYPTO_TESTING_TASK_MAX_TIME="$TASK_MAX_TIME"

run_fuzz_driver() {
  if [ -n "$MAX_TOTAL_TIME" ]; then
    set +e
    timeout --signal=TERM --kill-after=30s "${MAX_TOTAL_TIME}s" "$@"
    local status="$?"
    set -e
    if [ "$status" -eq 124 ]; then
      BUDGET_EXHAUSTED=1
      export CRYPTO_TESTING_BUDGET_EXHAUSTED=1
      return 0
    fi
    return "$status"
  fi
  "$@"
}

finalize() {
  local status="$?"
  set +e
  python3 "$MANIFEST_WRITER" \
    --output-root "$OUTPUT_ROOT" --mode "$MODE" --version "$VERSION" --reports-dir "$REPORTS_DIR"
  local manifest_status="$?"
  if [ "$status" -eq 0 ] && [ "$manifest_status" -ne 0 ]; then
    status="$manifest_status"
  fi
  exit "$status"
}
trap finalize EXIT

if [ "$LIBRARY" = "supercop" ]; then
  make get_supercop
  if [ "$MODE" = "vanilla" ]; then
    make supercop_baseline
    python3 supercop_report_baseline.py
  else
    make supercop
    python3 supercop_report.py
  fi
  exit 0
fi

make "$LIBRARY"
if [ "$MODE" = "vanilla" ]; then
  run_fuzz_driver python3 fuzz_liboqs_baseline.py --liboqs "$LIBRARY" --logfile "${LIBRARY}.vanilla.log" \
    --output-root "$OUTPUT_ROOT" --workers "$WORKERS" --geninput-timeout "$GENINPUT_TIMEOUT" --version "$VERSION"
  if [ "$BUDGET_EXHAUSTED" -eq 0 ]; then
    python3 report_baseline.py --liboqs "$LIBRARY" --output-root "$OUTPUT_ROOT" --report-dir "$REPORTS_DIR"
  fi
else
  DRIVER_BUDGET_ARGS=()
  if [ -n "$MAX_TOTAL_TIME" ]; then
    DRIVER_BUDGET_ARGS+=(--max-total-time "$MAX_TOTAL_TIME")
  fi
  if [ -n "$TASK_MAX_TIME" ]; then
    DRIVER_BUDGET_ARGS+=(--task-max-time "$TASK_MAX_TIME")
  fi
  run_fuzz_driver python3 fuzz_liboqs.py --liboqs "$LIBRARY" --logfile "${LIBRARY}.functional.log" \
    --output-root "$OUTPUT_ROOT" --workers "$WORKERS" --geninput-timeout "$GENINPUT_TIMEOUT" --version "$VERSION" \
    "${DRIVER_BUDGET_ARGS[@]}"
  if [ "$BUDGET_EXHAUSTED" -eq 0 ]; then
    python3 report.py --liboqs "$LIBRARY" --output-root "$OUTPUT_ROOT" --report-dir "$REPORTS_DIR"
  fi
fi

# A report is evidence only when every group it reports has retained raw input.
if [ "$BUDGET_EXHAUSTED" -eq 0 ]; then
  python3 "$MANIFEST_WRITER" \
    --output-root "$OUTPUT_ROOT" --mode "$MODE" --version "$VERSION" --reports-dir "$REPORTS_DIR" \
    --require-report-evidence
fi

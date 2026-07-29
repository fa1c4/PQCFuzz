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
WORKERS="${CRYPTO_TESTING_WORKERS:-auto}"
GENINPUT_TIMEOUT="${CRYPTO_TESTING_GENINPUT_TIMEOUT:-10}"
VERSION="${CRYPTO_TESTING_VERSION:-unknown}"
MAX_TOTAL_TIME="${CRYPTO_TESTING_MAX_TOTAL_TIME:-}"
BUDGET_EXHAUSTED=0
MANIFEST_FINALIZATION_ATTEMPTED=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-root) OUTPUT_ROOT="$2"; shift 2 ;;
    --reports-dir) REPORTS_DIR="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --geninput-timeout) GENINPUT_TIMEOUT="$2"; shift 2 ;;
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

mkdir -p "$OUTPUT_ROOT" "$REPORTS_DIR"
export CRYPTO_TESTING_OUTPUT_ROOT="$OUTPUT_ROOT"
export CRYPTO_TESTING_WORKERS="$WORKERS"
export CRYPTO_TESTING_GENINPUT_TIMEOUT="$GENINPUT_TIMEOUT"
export CRYPTO_TESTING_VERSION="$VERSION"

run_fuzz_driver() {
  if [ -n "$MAX_TOTAL_TIME" ]; then
    local started_at
    local finished_at
    started_at="$(date +%s)"
    set +e
    # Pool workers can need longer than the original 30 seconds to flush their
    # durable task state after the parent receives SIGTERM.  Keep the fuzzing
    # budget strict, but leave a bounded grace period for that finalization.
    timeout --signal=TERM --kill-after=5m "${MAX_TOTAL_TIME}s" "$@"
    local status="$?"
    set -e
    finished_at="$(date +%s)"
    # GNU timeout exits 137, rather than 124, when its kill-after escalation
    # is needed.  Accept that only after this invocation has reached its
    # configured wall-clock budget; an early SIGKILL remains a real failure.
    if [ "$status" -eq 124 ] || { [ "$status" -eq 137 ] && [ "$((finished_at - started_at))" -ge "$MAX_TOTAL_TIME" ]; }; then
      BUDGET_EXHAUSTED=1
      export CRYPTO_TESTING_BUDGET_EXHAUSTED=1
      return 0
    fi
    return "$status"
  fi
  "$@"
}

write_manifest() {
  MANIFEST_FINALIZATION_ATTEMPTED=1
  python3 "$MANIFEST_WRITER" \
    --output-root "$OUTPUT_ROOT" --mode "$MODE" --version "$VERSION" --reports-dir "$REPORTS_DIR" "$@"
}

write_harness_error_summary() {
  local stage="$1"
  local exit_status="$2"

  python3 - "$OUTPUT_ROOT/summary.json" "$MODE" "$VERSION" "$stage" "$exit_status" <<'PY'
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

path, mode, version, stage, exit_status = sys.argv[1:]
directory = os.path.dirname(path)
os.makedirs(directory, exist_ok=True)
document = {
    "baseline": "cryptoTesting",
    "label": f"cryptoTesting-{mode}",
    "mode": mode,
    "version": version,
    "status": "harness-error",
    "normalized_outcome": "operation_error",
    "stop_reason": "manifest-finalization",
    "failure_stage": stage,
    "exit_status": int(exit_status),
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
fd, temporary = tempfile.mkstemp(prefix=".summary.", dir=directory)
with os.fdopen(fd, "w", encoding="utf-8") as destination:
    json.dump(document, destination, indent=2, sort_keys=True)
    destination.write("\n")
os.replace(temporary, path)
PY
}

finalize() {
  local status="$?"
  local manifest_status=0

  set +e
  if [ "$MANIFEST_FINALIZATION_ATTEMPTED" -eq 0 ]; then
    write_manifest
    manifest_status="$?"
  fi
  if [ "$status" -eq 0 ] && [ "$manifest_status" -ne 0 ]; then
    write_harness_error_summary "manifest-finalizer" "$manifest_status"
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
  # The reporter is deliberately tolerant of a campaign-wall-clock stop, so
  # keep the partial output searchable and let the manifest mark its coverage.
  python3 report_baseline.py --liboqs "$LIBRARY" --output-root "$OUTPUT_ROOT" --report-dir "$REPORTS_DIR"
else
  run_fuzz_driver python3 fuzz_liboqs.py --liboqs "$LIBRARY" --logfile "${LIBRARY}.functional.log" \
    --output-root "$OUTPUT_ROOT" --workers "$WORKERS" --geninput-timeout "$GENINPUT_TIMEOUT" --version "$VERSION"
  # report.py can classify the durable AFL trees after a campaign-wall-clock
  # stop.  The manifest will still mark their task coverage incomplete.
  python3 report.py --liboqs "$LIBRARY" --output-root "$OUTPUT_ROOT" --report-dir "$REPORTS_DIR"
fi

# A report is evidence only when every group it reports has retained raw input.
if [ "$BUDGET_EXHAUSTED" -eq 0 ]; then
  set +e
  write_manifest --require-report-evidence
  manifest_status="$?"
  set -e
  if [ "$manifest_status" -ne 0 ]; then
    write_harness_error_summary "manifest-validation" "$manifest_status"
    exit "$manifest_status"
  fi
fi

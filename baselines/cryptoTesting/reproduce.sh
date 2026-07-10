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
EOF
}

LIBRARY="${1:-}"
if [ -z "$LIBRARY" ]; then
  usage >&2
  exit 2
fi
shift

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

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-root) OUTPUT_ROOT="$2"; shift 2 ;;
    --reports-dir) REPORTS_DIR="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --geninput-timeout) GENINPUT_TIMEOUT="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
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

mkdir -p "$OUTPUT_ROOT" "$REPORTS_DIR"
export CRYPTO_TESTING_OUTPUT_ROOT="$OUTPUT_ROOT"
export CRYPTO_TESTING_WORKERS="$WORKERS"
export CRYPTO_TESTING_GENINPUT_TIMEOUT="$GENINPUT_TIMEOUT"
export CRYPTO_TESTING_VERSION="$VERSION"

finalize() {
  local status="$?"
  set +e
  python3 crypto_testing_manifest.py \
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
  python3 fuzz_liboqs_baseline.py --liboqs "$LIBRARY" --logfile "${LIBRARY}.vanilla.log" \
    --output-root "$OUTPUT_ROOT" --workers "$WORKERS" --geninput-timeout "$GENINPUT_TIMEOUT" --version "$VERSION"
  python3 report_baseline.py --liboqs "$LIBRARY" --output-root "$OUTPUT_ROOT" --report-dir "$REPORTS_DIR"
else
  python3 fuzz_liboqs.py --liboqs "$LIBRARY" --logfile "${LIBRARY}.functional.log" \
    --output-root "$OUTPUT_ROOT" --workers "$WORKERS" --geninput-timeout "$GENINPUT_TIMEOUT" --version "$VERSION"
  python3 report.py --liboqs "$LIBRARY" --output-root "$OUTPUT_ROOT" --report-dir "$REPORTS_DIR"
fi

# A report is evidence only when every group it reports has retained raw input.
python3 crypto_testing_manifest.py \
  --output-root "$OUTPUT_ROOT" --mode "$MODE" --version "$VERSION" --reports-dir "$REPORTS_DIR" \
  --require-report-evidence

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
  --cpu-allocation VALUE        Fairness metadata for CPU allocation. Default: detected CPU count.
  --max-exemplars-per-group N   Maximum structured finding exemplars per group. Default: 3.
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
CPU_ALLOCATION="${PQCDF_CRYPTOFUZZ_CPU_ALLOCATION:-}"
MAX_EXEMPLARS_PER_GROUP="${PQCDF_CRYPTOFUZZ_MAX_EXEMPLARS_PER_GROUP:-3}"
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
    --cpu-allocation)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --cpu-allocation." >&2
        exit 2
      fi
      CPU_ALLOCATION="$2"
      shift 2
      ;;
    --cpu-allocation=*)
      CPU_ALLOCATION="${1#--cpu-allocation=}"
      shift
      ;;
    --max-exemplars-per-group)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --max-exemplars-per-group." >&2
        exit 2
      fi
      MAX_EXEMPLARS_PER_GROUP="$2"
      shift 2
      ;;
    --max-exemplars-per-group=*)
      MAX_EXEMPLARS_PER_GROUP="${1#--max-exemplars-per-group=}"
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

if ! [[ "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "--jobs must be a positive integer." >&2
  exit 2
fi
if ! [[ "$WORKERS" =~ ^[1-9][0-9]*$ ]]; then
  echo "--workers must be a positive integer." >&2
  exit 2
fi
if ! [[ "$MAX_EXEMPLARS_PER_GROUP" =~ ^[1-9][0-9]*$ ]]; then
  echo "--max-exemplars-per-group must be a positive integer." >&2
  exit 2
fi

if [ -z "$RUNS" ] && [ "$MODE" = "smoke" ]; then
  RUNS="1000"
fi
if [ -z "$MAX_TOTAL_TIME" ] && [ "$MODE" = "full" ]; then
  MAX_TOTAL_TIME="86400"
fi

mkdir -p "$BUILD_DIR" "$RUN_DIR"

HOST_CPU_COUNT="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo unknown)"
if [ -z "$CPU_ALLOCATION" ]; then
  CPU_ALLOCATION="$HOST_CPU_COUNT"
fi

IMAGE_NAME="pqcdf-baseline-cryptofuzz"
WRAPPER_ROOT="${PQCDF_BASELINE_WRAPPER_ROOT:-scripts/baselines}"

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
    "${WRAPPER_ROOT}/cryptofuzz/run.sh"
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
  FORWARDED_ARGS+=(
    --jobs "$JOBS"
    --workers "$WORKERS"
    --cpu-allocation "$CPU_ALLOCATION"
    --max-exemplars-per-group "$MAX_EXEMPLARS_PER_GROUP"
  )
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

epoch_ns() {
  local value
  value="$(date +%s%N 2>/dev/null || true)"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$value"
  else
    python3 - <<'PY'
import time
print(time.time_ns())
PY
  fi
}

resolve_path() {
  realpath -m -- "$1"
}

is_within() {
  local root="$1"
  local candidate="$2"

  if [ "$root" = "/" ]; then
    [[ "$candidate" == /* ]]
    return
  fi

  case "$candidate" in
    "$root"|"${root}/"*) return 0 ;;
    *) return 1 ;;
  esac
}

require_campaign_path() {
  local label="$1"
  local candidate="$2"

  if ! is_within "$CAMPAIGN_ROOT" "$candidate"; then
    echo "Refusing to use ${label} outside campaign root: ${candidate}" >&2
    echo "Campaign root: ${CAMPAIGN_ROOT}" >&2
    exit 1
  fi
}

BUILD_DIR_ABS="$(realpath "$BUILD_DIR")"
RUN_DIR_ABS="$(realpath "$RUN_DIR")"
VERSION_BUILD_DIR="${BUILD_DIR_ABS}/liboqs-${VERSION}"
VERSION_RUN_DIR="$(resolve_path "${RUN_DIR_ABS}/liboqs-${VERSION}")"
if ! is_within "$RUN_DIR_ABS" "$VERSION_RUN_DIR"; then
  echo "Refusing to use campaign root outside run directory: ${VERSION_RUN_DIR}" >&2
  echo "Run directory: ${RUN_DIR_ABS}" >&2
  exit 1
fi
mkdir -p "$VERSION_RUN_DIR"
CAMPAIGN_ROOT="$(realpath "$VERSION_RUN_DIR")"
if ! is_within "$RUN_DIR_ABS" "$CAMPAIGN_ROOT"; then
  echo "Refusing to use resolved campaign root outside run directory: ${CAMPAIGN_ROOT}" >&2
  echo "Run directory: ${RUN_DIR_ABS}" >&2
  exit 1
fi
VERSION_RUN_DIR="$CAMPAIGN_ROOT"
BINARY="${VERSION_BUILD_DIR}/cryptofuzz/cryptofuzz"
LOG_DIR="$(resolve_path "${CAMPAIGN_ROOT}/logs")"
CORPUS_DIR="$(resolve_path "${CAMPAIGN_ROOT}/corpus")"
CRASH_DIR="$(resolve_path "${CAMPAIGN_ROOT}/crashes")"
ARTIFACT_DIR="$(resolve_path "${CAMPAIGN_ROOT}/artifacts")"
FINDINGS_DIR="$(resolve_path "${CAMPAIGN_ROOT}/findings")"
DIAGNOSTICS_DIR="$(resolve_path "${CAMPAIGN_ROOT}/diagnostics")"
METADATA_DIR="$(resolve_path "${CAMPAIGN_ROOT}/metadata")"
OUTCOMES_DIR="$(resolve_path "${CAMPAIGN_ROOT}/outcomes")"
SUMMARY_FILE="$(resolve_path "${CAMPAIGN_ROOT}/summary.json")"
LOG_FILE="$(resolve_path "${LOG_DIR}/${MODE}.log")"
TIME_FILE="$(resolve_path "${METADATA_DIR}/${MODE}.time")"

require_campaign_path "corpus directory" "$CORPUS_DIR"
require_campaign_path "crash directory" "$CRASH_DIR"
require_campaign_path "artifact directory" "$ARTIFACT_DIR"
require_campaign_path "finding directory" "$FINDINGS_DIR"
require_campaign_path "diagnostic directory" "$DIAGNOSTICS_DIR"
require_campaign_path "metadata directory" "$METADATA_DIR"
require_campaign_path "outcome directory" "$OUTCOMES_DIR"
require_campaign_path "log directory" "$LOG_DIR"
require_campaign_path "log file" "$LOG_FILE"
require_campaign_path "summary file" "$SUMMARY_FILE"
require_campaign_path "timing file" "$TIME_FILE"

BINARY_MISSING=0
if [ ! -x "$BINARY" ]; then
  BINARY_MISSING=1
fi

mkdir -p \
  "$LOG_DIR" \
  "$CORPUS_DIR" \
  "$CRASH_DIR" \
  "$ARTIFACT_DIR" \
  "$FINDINGS_DIR" \
  "$DIAGNOSTICS_DIR" \
  "$METADATA_DIR" \
  "$OUTCOMES_DIR"

# libFuzzer's pinned flag set has no -log_path option. Its -jobs worker logs
# are named fuzz-N.log relative to the current directory, so this directory is
# the isolation boundary for a campaign.
LOG_DIR="$(realpath "$LOG_DIR")"
CORPUS_DIR="$(realpath "$CORPUS_DIR")"
CRASH_DIR="$(realpath "$CRASH_DIR")"
ARTIFACT_DIR="$(realpath "$ARTIFACT_DIR")"
FINDINGS_DIR="$(realpath "$FINDINGS_DIR")"
DIAGNOSTICS_DIR="$(realpath "$DIAGNOSTICS_DIR")"
METADATA_DIR="$(realpath "$METADATA_DIR")"
OUTCOMES_DIR="$(realpath "$OUTCOMES_DIR")"
LOG_FILE="$(resolve_path "${LOG_DIR}/${MODE}.log")"
SUMMARY_FILE="$(resolve_path "${CAMPAIGN_ROOT}/summary.json")"
TIME_FILE="$(resolve_path "${METADATA_DIR}/${MODE}.time")"

require_campaign_path "resolved corpus directory" "$CORPUS_DIR"
require_campaign_path "resolved crash directory" "$CRASH_DIR"
require_campaign_path "resolved artifact directory" "$ARTIFACT_DIR"
require_campaign_path "resolved finding directory" "$FINDINGS_DIR"
require_campaign_path "resolved diagnostic directory" "$DIAGNOSTICS_DIR"
require_campaign_path "resolved outcome directory" "$OUTCOMES_DIR"
require_campaign_path "resolved log directory" "$LOG_DIR"
require_campaign_path "resolved log file" "$LOG_FILE"
require_campaign_path "resolved summary file" "$SUMMARY_FILE"
require_campaign_path "resolved timing file" "$TIME_FILE"

resolve_working_path() {
  local value="$1"

  if [[ "$value" = /* ]]; then
    resolve_path "$value"
  else
    resolve_path "${LOG_DIR}/${value}"
  fi
}

validate_extra_fuzzer_args() {
  local arg value candidate seed_path
  local -a seed_paths

  for arg in "$@"; do
    case "$arg" in
      -artifact_prefix=*|--artifact_prefix=*|-artifact_prefix|--artifact_prefix|\
      -exact_artifact_path=*|--exact_artifact_path=*|-exact_artifact_path|--exact_artifact_path|\
      -log_path=*|--log_path=*|-log_path|--log_path)
        echo "Extra libFuzzer argument '${arg}' overrides a runner-managed output path." >&2
        echo "The cryptofuzz runner owns artifact and log paths for campaign isolation." >&2
        exit 2
        ;;
      -features_dir=*|--features_dir=*|-mutation_graph_file=*|--mutation_graph_file=*|\
      -merge_control_file=*|--merge_control_file=*|-stop_file=*|--stop_file=*)
        value="${arg#*=}"
        candidate="$(resolve_working_path "$value")"
        require_campaign_path "extra libFuzzer path (${arg%%=*})" "$candidate"
        ;;
      -features_dir|--features_dir|-mutation_graph_file|--mutation_graph_file|\
      -merge_control_file|--merge_control_file|-stop_file|--stop_file)
        echo "Extra libFuzzer path arguments must use the '=PATH' form: '${arg}'" >&2
        exit 2
        ;;
      -seed_inputs=*|--seed_inputs=*)
        value="${arg#*=}"
        IFS=',' read -r -a seed_paths <<< "$value"
        for seed_path in "${seed_paths[@]}"; do
          if [[ "$seed_path" = @* ]]; then
            seed_path="${seed_path#@}"
          fi
          candidate="$(resolve_working_path "$seed_path")"
          require_campaign_path "extra seed corpus path" "$candidate"
        done
        ;;
      -seed_inputs|--seed_inputs)
        echo "Extra seed corpus arguments must use the '=PATH' form: '${arg}'" >&2
        exit 2
        ;;
      -*)
        ;;
      *)
        # Non-flag libFuzzer arguments are corpus paths and are resolved from
        # the campaign-local working directory.
        candidate="$(resolve_working_path "$arg")"
        require_campaign_path "extra corpus path" "$candidate"
        ;;
    esac
  done
}

validate_extra_fuzzer_args "${EXTRA_ARGS[@]}"

OPERATIONS="OQS_KEM_SelfTest,OQS_SIG_SelfTest"
ARGS=(
  "--operations=${OPERATIONS}"
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
echo "[cryptofuzz] working directory: $LOG_DIR"
echo "[cryptofuzz] log file: $LOG_FILE"
echo "[cryptofuzz] workers: $WORKERS; CPU allocation: $CPU_ALLOCATION"

START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
START_NS="$(epoch_ns)"
set +e
if [ "$BINARY_MISSING" -eq 1 ]; then
  {
    echo "cryptofuzz binary not found: $BINARY"
    echo "Run: scripts/run_baseline.sh cryptofuzz build --version $VERSION"
  } 2>&1 | tee "$LOG_FILE"
  STATUS=1
elif [ -x /usr/bin/time ]; then
  (
    cd "$LOG_DIR" || exit 125
    PQCDF_CRYPTOFUZZ_FINDINGS_DIR="$FINDINGS_DIR" \
    PQCDF_CRYPTOFUZZ_DIAGNOSTICS_DIR="$DIAGNOSTICS_DIR" \
    PQCDF_CRYPTOFUZZ_METADATA_DIR="$METADATA_DIR" \
    PQCDF_CRYPTOFUZZ_OUTCOMES_DIR="$OUTCOMES_DIR" \
    PQCDF_CRYPTOFUZZ_LOG_FILE="$LOG_FILE" \
    PQCDF_CRYPTOFUZZ_MAX_EXEMPLARS_PER_GROUP="$MAX_EXEMPLARS_PER_GROUP" \
    PQCDF_CRYPTOFUZZ_LIBOQS_VERSION="$VERSION" \
    /usr/bin/time -o "$TIME_FILE" -f '%U %S' "$BINARY" "${ARGS[@]}"
  ) 2>&1 | tee "$LOG_FILE"
  STATUS="${PIPESTATUS[0]}"
else
  (
    cd "$LOG_DIR" || exit 125
    PQCDF_CRYPTOFUZZ_FINDINGS_DIR="$FINDINGS_DIR" \
    PQCDF_CRYPTOFUZZ_DIAGNOSTICS_DIR="$DIAGNOSTICS_DIR" \
    PQCDF_CRYPTOFUZZ_METADATA_DIR="$METADATA_DIR" \
    PQCDF_CRYPTOFUZZ_OUTCOMES_DIR="$OUTCOMES_DIR" \
    PQCDF_CRYPTOFUZZ_LOG_FILE="$LOG_FILE" \
    PQCDF_CRYPTOFUZZ_MAX_EXEMPLARS_PER_GROUP="$MAX_EXEMPLARS_PER_GROUP" \
    PQCDF_CRYPTOFUZZ_LIBOQS_VERSION="$VERSION" \
    "$BINARY" "${ARGS[@]}"
  ) 2>&1 | tee "$LOG_FILE"
  STATUS="${PIPESTATUS[0]}"
fi
set -e
END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
END_NS="$(epoch_ns)"

CRYPTOFUZZ_SUMMARY_FILE="$SUMMARY_FILE" \
CRYPTOFUZZ_CAMPAIGN_ROOT="$CAMPAIGN_ROOT" \
CRYPTOFUZZ_VERSION="$VERSION" \
CRYPTOFUZZ_MODE="$MODE" \
CRYPTOFUZZ_STATUS="$STATUS" \
CRYPTOFUZZ_BINARY_MISSING="$BINARY_MISSING" \
CRYPTOFUZZ_START_TS="$START_TS" \
CRYPTOFUZZ_END_TS="$END_TS" \
CRYPTOFUZZ_START_NS="$START_NS" \
CRYPTOFUZZ_END_NS="$END_NS" \
CRYPTOFUZZ_BINARY="$BINARY" \
CRYPTOFUZZ_LOG_FILE="$LOG_FILE" \
CRYPTOFUZZ_LOG_DIR="$LOG_DIR" \
CRYPTOFUZZ_CORPUS_DIR="$CORPUS_DIR" \
CRYPTOFUZZ_CRASH_DIR="$CRASH_DIR" \
CRYPTOFUZZ_ARTIFACT_DIR="$ARTIFACT_DIR" \
CRYPTOFUZZ_FINDINGS_DIR="$FINDINGS_DIR" \
CRYPTOFUZZ_DIAGNOSTICS_DIR="$DIAGNOSTICS_DIR" \
CRYPTOFUZZ_METADATA_DIR="$METADATA_DIR" \
CRYPTOFUZZ_OUTCOMES_DIR="$OUTCOMES_DIR" \
CRYPTOFUZZ_TIME_FILE="$TIME_FILE" \
CRYPTOFUZZ_JOBS="$JOBS" \
CRYPTOFUZZ_WORKERS="$WORKERS" \
CRYPTOFUZZ_CPU_ALLOCATION="$CPU_ALLOCATION" \
CRYPTOFUZZ_HOST_CPU_COUNT="$HOST_CPU_COUNT" \
CRYPTOFUZZ_MAX_EXEMPLARS_PER_GROUP="$MAX_EXEMPLARS_PER_GROUP" \
CRYPTOFUZZ_OPERATIONS="$OPERATIONS" \
python3 - "${ARGS[@]}" <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path


def atomic_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_path = tempfile.mkstemp(prefix=".summary.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(temporary_path, path)
    except BaseException:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def relative_files(root, directory, predicate):
    if not directory.is_dir():
        return []
    paths = []
    for path in directory.rglob("*"):
        if not path.is_file() or not predicate(path):
            continue
        try:
            resolved = path.resolve()
            relative = resolved.relative_to(root)
        except ValueError:
            # Never let a symlink outside the campaign become evidence for it.
            continue
        paths.append(str(relative))
    return sorted(paths)


def json_records(root, relative_paths):
    records = []
    for relative_path in relative_paths:
        try:
            with (root / relative_path).open(encoding="utf-8") as f:
                record = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def timing(path):
    try:
        user_seconds, system_seconds = map(float, path.read_text(encoding="utf-8").strip().split()[:2])
    except (OSError, ValueError):
        return None, None, None
    return user_seconds, system_seconds, user_seconds + system_seconds


summary_path = Path(os.environ["CRYPTOFUZZ_SUMMARY_FILE"])
campaign_root = Path(os.environ["CRYPTOFUZZ_CAMPAIGN_ROOT"]).resolve()
log_dir = Path(os.environ["CRYPTOFUZZ_LOG_DIR"]).resolve()
crash_dir = Path(os.environ["CRYPTOFUZZ_CRASH_DIR"]).resolve()
findings_dir = Path(os.environ["CRYPTOFUZZ_FINDINGS_DIR"]).resolve()
diagnostics_dir = Path(os.environ["CRYPTOFUZZ_DIAGNOSTICS_DIR"]).resolve()
metadata_dir = Path(os.environ["CRYPTOFUZZ_METADATA_DIR"]).resolve()
outcomes_dir = Path(os.environ["CRYPTOFUZZ_OUTCOMES_DIR"]).resolve()
time_file = Path(os.environ["CRYPTOFUZZ_TIME_FILE"])

semantic_findings = relative_files(campaign_root, findings_dir, lambda path: path.suffix == ".json")
operation_diagnostics = relative_files(campaign_root, diagnostics_dir, lambda path: path.suffix == ".json")
sanitizer_crashes = relative_files(
    campaign_root,
    crash_dir,
    lambda path: path.name.startswith(("crash-", "leak-", "oom-")),
)
hangs = relative_files(campaign_root, crash_dir, lambda path: path.name.startswith("timeout-"))
worker_logs = relative_files(
    campaign_root,
    log_dir,
    lambda path: path.name.startswith("fuzz-") and path.name.endswith(".log"),
)
metadata_files = relative_files(campaign_root, metadata_dir, lambda path: path.suffix == ".json")
structured_outcomes = relative_files(campaign_root, outcomes_dir, lambda path: path.suffix == ".json")
records = json_records(campaign_root, semantic_findings)
diagnostic_records = json_records(campaign_root, operation_diagnostics)
outcome_records = json_records(campaign_root, structured_outcomes)
metadata_records = json_records(campaign_root, metadata_files)
all_records = records + diagnostic_records + outcome_records

def string_values(records, keys):
    values = set()
    for record in records:
        for key in keys:
            value = record.get(key)
            if isinstance(value, str):
                values.add(value)
            elif isinstance(value, list):
                values.update(item for item in value if isinstance(item, str))
    return values

algorithm_list = sorted(string_values(
    all_records + metadata_records,
    (
        "algorithm", "enabled_algorithms", "enabled_kem_algorithms", "enabled_sig_algorithms",
        "algorithm_list", "algorithms",
    ),
))
property_list = sorted(string_values(
    all_records + metadata_records,
    ("property_id", "property_ids", "kem_property_ids", "sig_property_ids", "property_list", "properties"),
))
module_versions = sorted(string_values(all_records + metadata_records, ("module_version",)))
semantic_relations = sorted(string_values(records, ("semantic_relation", "relation")))
replays = [record.get("replay") for record in records if isinstance(record.get("replay"), dict)]
replay_required_count = sum(bool(replay.get("required")) for replay in replays)
replay_reproduced_count = sum(replay.get("result") == "reproduced" for replay in replays)

def pairs_for(metadata, primitive, algorithms_key, properties_key):
    algorithms = string_values([metadata], (algorithms_key,))
    properties = string_values([metadata], (properties_key,))
    return {f"{primitive}|{algorithm}|{property_id}" for algorithm in algorithms for property_id in properties}

supported_pairs = set()
for metadata in metadata_records:
    supported_pairs |= pairs_for(metadata, "kem", "enabled_kem_algorithms", "kem_property_ids")
    supported_pairs |= pairs_for(metadata, "sig", "enabled_sig_algorithms", "sig_property_ids")
covered_pairs = {
    f"{record['primitive']}|{record['algorithm']}|{record['property_id']}"
    for record in outcome_records
    if record.get("classification") in ("property_passed", "skipped")
    and all(isinstance(record.get(key), str) and record.get(key) for key in ("primitive", "algorithm", "property_id"))
}
if not supported_pairs:
    coverage_status = "unknown"
    unexercised_pairs = []
else:
    unexercised_pairs = sorted(supported_pairs - covered_pairs)
    coverage_status = "complete" if not unexercised_pairs else "incomplete"

raw_exit_status = int(os.environ["CRYPTOFUZZ_STATUS"])
try:
    log_text = Path(os.environ["CRYPTOFUZZ_LOG_FILE"]).read_text(encoding="utf-8", errors="replace")
except OSError:
    log_text = ""
has_sanitizer_log = any(marker in log_text for marker in (
    "AddressSanitizer", "UndefinedBehaviorSanitizer", "MemorySanitizer", "LeakSanitizer",
    "ERROR: libFuzzer: deadly signal", "runtime error:",
))

if os.environ["CRYPTOFUZZ_BINARY_MISSING"] == "1" or raw_exit_status == 127:
    outcome = "infrastructure-failed"
    stop_reason = "missing-binary"
elif raw_exit_status != 0:
    if sanitizer_crashes or raw_exit_status >= 128 or has_sanitizer_log:
        outcome = "target-crash"
        stop_reason = "sanitizer-or-signal"
    elif hangs or raw_exit_status == 70:
        outcome = "timed-out"
        stop_reason = "target-timeout"
    else:
        outcome = "harness-error"
        stop_reason = "nonzero-fuzzer-exit"
elif semantic_findings:
    outcome = "completed-with-findings"
    stop_reason = "runs-limit" if any(arg.startswith("-runs=") for arg in sys.argv[1:]) else (
        "max-total-time" if any(arg.startswith("-max_total_time=") for arg in sys.argv[1:]) else "fuzzer-completed"
    )
else:
    outcome = "completed"
    stop_reason = "runs-limit" if any(arg.startswith("-runs=") for arg in sys.argv[1:]) else (
        "max-total-time" if any(arg.startswith("-max_total_time=") for arg in sys.argv[1:]) else "fuzzer-completed"
    )

if coverage_status == "incomplete" and outcome in ("completed", "completed-with-findings"):
    outcome = "completed-with-coverage-gap"
    stop_reason = "semantic-coverage-incomplete"

normalized_outcome = {
    "completed": "ok",
    "completed-with-findings": "invariant_violation",
    "completed-with-coverage-gap": "coverage_incomplete",
    "timed-out": "process_hang",
    "target-crash": "process_crash",
    "harness-error": "operation_error",
    "infrastructure-failed": "operation_error",
}.get(outcome, "operation_error")
user_seconds, system_seconds, cpu_seconds = timing(time_file)
try:
    wall_seconds = max(
        0.0,
        (int(os.environ["CRYPTOFUZZ_END_NS"]) - int(os.environ["CRYPTOFUZZ_START_NS"])) / 1_000_000_000,
    )
except ValueError:
    wall_seconds = None

summary = {
    "baseline": "cryptofuzz",
    "target": "liboqs",
    "version": os.environ["CRYPTOFUZZ_VERSION"],
    "liboqs_version": os.environ["CRYPTOFUZZ_VERSION"],
    "module_version": module_versions[0] if len(module_versions) == 1 else os.environ["CRYPTOFUZZ_VERSION"],
    "module_versions": module_versions,
    "mode": os.environ["CRYPTOFUZZ_MODE"],
    "status": outcome,
    "outcome": outcome,
    "normalized_outcome": normalized_outcome,
    "exit_status": raw_exit_status,
    "effective_exit_status": raw_exit_status,
    "stop_reason": stop_reason,
    "started_at": os.environ["CRYPTOFUZZ_START_TS"],
    "ended_at": os.environ["CRYPTOFUZZ_END_TS"],
    "wall_time_seconds": wall_seconds,
    "cpu_time_seconds": cpu_seconds,
    "cpu_user_seconds": user_seconds,
    "cpu_system_seconds": system_seconds,
    "worker_count": as_int(os.environ["CRYPTOFUZZ_WORKERS"]),
    "jobs": as_int(os.environ["CRYPTOFUZZ_JOBS"]),
    "cpu_allocation": os.environ["CRYPTOFUZZ_CPU_ALLOCATION"],
    "host_cpu_count": as_int(os.environ["CRYPTOFUZZ_HOST_CPU_COUNT"]),
    "max_exemplars_per_group": as_int(os.environ["CRYPTOFUZZ_MAX_EXEMPLARS_PER_GROUP"]),
    "operations": [value for value in os.environ["CRYPTOFUZZ_OPERATIONS"].split(",") if value],
    "algorithm_list": algorithm_list,
    "property_list": property_list,
    "coverage_status": coverage_status,
    "supported_pair_count": len(supported_pairs),
    "covered_pair_count": len(covered_pairs),
    "covered_pair_list": sorted(covered_pairs),
    "unexercised_pair_list": unexercised_pairs,
    "campaign_root": str(campaign_root),
    "working_directory": str(log_dir),
    "resolved_working_directory": str(log_dir),
    "resolved_paths": {
        "campaign_root": str(campaign_root),
        "working_directory": str(log_dir),
        "log_dir": str(log_dir),
        "log_file": os.environ["CRYPTOFUZZ_LOG_FILE"],
        "corpus_dir": os.environ["CRYPTOFUZZ_CORPUS_DIR"],
        "crash_dir": os.environ["CRYPTOFUZZ_CRASH_DIR"],
        "artifact_dir": os.environ["CRYPTOFUZZ_ARTIFACT_DIR"],
        "findings_dir": os.environ["CRYPTOFUZZ_FINDINGS_DIR"],
        "diagnostics_dir": os.environ["CRYPTOFUZZ_DIAGNOSTICS_DIR"],
        "metadata_dir": os.environ["CRYPTOFUZZ_METADATA_DIR"],
        "outcomes_dir": os.environ["CRYPTOFUZZ_OUTCOMES_DIR"],
        "timing_file": os.environ["CRYPTOFUZZ_TIME_FILE"],
        "summary_file": str(summary_path),
    },
    "binary": os.environ["CRYPTOFUZZ_BINARY"],
    "log": os.environ["CRYPTOFUZZ_LOG_FILE"],
    "log_dir": str(log_dir),
    "log_paths": [os.environ["CRYPTOFUZZ_LOG_FILE"]] + [str(campaign_root / path) for path in worker_logs],
    "resolved_log_paths": [os.environ["CRYPTOFUZZ_LOG_FILE"]] + [str(campaign_root / path) for path in worker_logs],
    "worker_logs": worker_logs,
    "worker_log_paths": [str(campaign_root / path) for path in worker_logs],
    "stdout_log": os.environ["CRYPTOFUZZ_LOG_FILE"],
    "stderr_log": os.environ["CRYPTOFUZZ_LOG_FILE"],
    "corpus_dir": os.environ["CRYPTOFUZZ_CORPUS_DIR"],
    "crash_dir": os.environ["CRYPTOFUZZ_CRASH_DIR"],
    "artifact_dir": os.environ["CRYPTOFUZZ_ARTIFACT_DIR"],
    "findings_dir": os.environ["CRYPTOFUZZ_FINDINGS_DIR"],
    "diagnostics_dir": os.environ["CRYPTOFUZZ_DIAGNOSTICS_DIR"],
    "metadata_dir": os.environ["CRYPTOFUZZ_METADATA_DIR"],
    "outcomes_dir": os.environ["CRYPTOFUZZ_OUTCOMES_DIR"],
    "metadata_files": metadata_files,
    "structured_outcome_count": len(structured_outcomes),
    "structured_outcomes": structured_outcomes,
    "semantic_finding_count": len(semantic_findings),
    "structured_finding_count": len(semantic_findings),
    "semantic_findings": semantic_findings,
    "structured_findings": semantic_findings,
    "findings": semantic_findings,
    "semantic_relations": semantic_relations,
    "replay_required_count": replay_required_count,
    "replay_reproduced_count": replay_reproduced_count,
    "operation_diagnostic_count": len(operation_diagnostics),
    "operation_diagnostics": operation_diagnostics,
    "diagnostics": operation_diagnostics,
    "sanitizer_crash_count": len(sanitizer_crashes),
    "sanitizer_crashes": sanitizer_crashes,
    "sanitizer_artifact_count": len(sanitizer_crashes) + len(hangs),
    "sanitizer_artifacts": sanitizer_crashes + hangs,
    "crashes": sanitizer_crashes + hangs,
    "hang_count": len(hangs),
    "hangs": hangs,
    "args": sys.argv[1:],
}

atomic_write(summary_path, summary)
PY

echo "[cryptofuzz] summary: $SUMMARY_FILE"

if [ "$STATUS" -ne 0 ]; then
  echo "[cryptofuzz] run failed with status $STATUS" >&2
  echo "[cryptofuzz] see log: $LOG_FILE" >&2
  exit "$STATUS"
fi

echo "[cryptofuzz] run completed"

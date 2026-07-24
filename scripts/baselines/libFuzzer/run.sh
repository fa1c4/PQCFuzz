#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/run_baseline.sh libFuzzer run --profile memory-safety|semantic [options] [extra libFuzzer args...]

Options:
  --profile memory-safety|semantic
                                Required. Select the memory-safety or semantic campaign.
  --version VERSION             Run against a supported liboqs version. Default: 0.14.0.
  --target kem|sig|all          Run one harness or both harnesses. Default: all.
  --mode smoke|full             Run a short smoke campaign or a bounded full campaign. Default: smoke.
  --max-total-time SECONDS      libFuzzer -max_total_time value. Full default: 86400.
  --runs N                      libFuzzer -runs value. Smoke default: 1000.
  --jobs N                      libFuzzer -jobs value. Default: 1.
  --workers N                   libFuzzer -workers value. Default: 1.
  --seed N                      libFuzzer -seed value. Default: 1.
  --max-exemplars-per-group N   Maximum structured semantic exemplars per group. Default: 3.
  --cpu-allocation VALUE        Fairness metadata for the CPU allocation. Default: detected CPU count.
  -h, --help                    Show this help.

Profiles:
  memory-safety                 Sanitized valid API lifecycles; semantic findings are disabled.
  semantic                      The documented algorithm/property semantic matrix.

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
PROFILE=""
MAX_TOTAL_TIME=""
RUNS=""
JOBS="1"
WORKERS="1"
SEED="1"
MAX_EXEMPLARS_PER_GROUP="${PQCDF_LIBFUZZER_MAX_EXEMPLARS_PER_GROUP:-3}"
CPU_ALLOCATION="${PQCDF_LIBFUZZER_CPU_ALLOCATION:-}"
EXTRA_ARGS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --profile." >&2
        exit 2
      fi
      PROFILE="$2"
      shift 2
      ;;
    --profile=*)
      PROFILE="${1#--profile=}"
      shift
      ;;
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

if [ -z "$PROFILE" ]; then
  echo "--profile is required (memory-safety or semantic)." >&2
  usage >&2
  exit 2
fi
case "$PROFILE" in
  memory-safety|semantic) ;;
  *)
    echo "Unsupported libFuzzer profile: $PROFILE" >&2
    echo "Supported profiles: memory-safety, semantic" >&2
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

IMAGE_NAME="pqcdf-baseline-libfuzzer"
WRAPPER_ROOT="${PQCDF_BASELINE_WRAPPER_ROOT:-scripts/baselines}"

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
    "${WRAPPER_ROOT}/libFuzzer/run.sh"
    "$BASELINE_DIR"
    "$BUILD_DIR"
    "$RUN_DIR"
    --profile "$PROFILE"
    --version "$VERSION"
    --target "$TARGET"
    --mode "$MODE"
    --jobs "$JOBS"
    --workers "$WORKERS"
    --seed "$SEED"
    --max-exemplars-per-group "$MAX_EXEMPLARS_PER_GROUP"
    --cpu-allocation "$CPU_ALLOCATION"
  )
  if [ -n "$MAX_TOTAL_TIME" ]; then
    FORWARDED_ARGS+=(--max-total-time "$MAX_TOTAL_TIME")
  fi
  if [ -n "$RUNS" ]; then
    FORWARDED_ARGS+=(--runs "$RUNS")
  fi
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

count_files_named() {
  local directory="$1"
  local pattern="$2"
  if [ ! -d "$directory" ]; then
    echo 0
    return
  fi
  find "$directory" -type f -name "$pattern" -print | wc -l | tr -d '[:space:]'
}

seed_default_envelope() {
  local corpus_dir="$1"
  local target_name="$2"
  if [ -d "$corpus_dir" ] && find "$corpus_dir" -type f -print -quit | grep -q .; then
    return
  fi
  python3 - "$corpus_dir/seed-envelope-v1.bin" "$target_name" <<'PY'
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
target = sys.argv[2]
primitive, property_id, message = (1, 2, b"") if target == "kem" else (2, 2, b"M")
rng_tape = b"PQCDF-RNG"
header = struct.pack(
    "<BBBBIQHHIBBH",
    1,                 # format version
    primitive,
    property_id,       # kem_decaps_c / sig_verify_sig
    0,                 # XOR mutation plan
    0,                 # enabled algorithm index
    0x123456789ABCDEF0,
    len(rng_tape),
    len(message),
    0,                 # mutation offset
    1,                 # mutation mask
    1,                 # mutation width
    0,                 # reserved
)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(header + rng_tape + message)
PY
}

has_file_named() {
  local directory="$1"
  shift
  local pattern
  if [ ! -d "$directory" ]; then
    return 1
  fi
  for pattern in "$@"; do
    if find "$directory" -type f -name "$pattern" -print -quit | grep -q .; then
      return 0
    fi
  done
  return 1
}

has_sanitizer_log() {
  local log_file="$1"
  [ -f "$log_file" ] && grep -Eqi \
    'AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|LeakSanitizer|ERROR: libFuzzer: deadly signal|runtime error:' \
    "$log_file"
}

classify_target_result() {
  local raw_exit_status="$1"
  local semantic_finding_count="$2"
  local crash_dir="$3"
  local log_file="$4"

  TARGET_STATUS=""
  TARGET_STOP_REASON=""
  TARGET_EFFECTIVE_EXIT_STATUS="$raw_exit_status"

  local has_crash=0
  local has_timeout=0
  if has_file_named "$crash_dir" 'crash-*' 'leak-*' 'oom-*'; then
    has_crash=1
  fi
  if has_file_named "$crash_dir" 'timeout-*'; then
    has_timeout=1
  fi

  if [ "$raw_exit_status" -eq 127 ]; then
    TARGET_STATUS="infrastructure-failed"
    TARGET_STOP_REASON="missing-binary"
  elif [ "$has_crash" -eq 1 ] || { [ "$raw_exit_status" -ne 0 ] && has_sanitizer_log "$log_file"; }; then
    TARGET_STATUS="target-crash"
    TARGET_STOP_REASON="sanitizer-artifact"
  elif [ "$has_timeout" -eq 1 ] || [ "$raw_exit_status" -eq 124 ]; then
    TARGET_STATUS="timed-out"
    TARGET_STOP_REASON="target-timeout"
  elif [ "$raw_exit_status" -ne 0 ]; then
    TARGET_STATUS="harness-error"
    TARGET_STOP_REASON="nonzero-fuzzer-exit"
  elif [ "$semantic_finding_count" -gt 0 ]; then
    TARGET_STATUS="completed-with-findings"
    if [ -n "$RUNS" ]; then
      TARGET_STOP_REASON="runs-limit"
    elif [ -n "$MAX_TOTAL_TIME" ]; then
      TARGET_STOP_REASON="max-total-time"
    else
      TARGET_STOP_REASON="fuzzer-completed"
    fi
  else
    TARGET_STATUS="completed"
    if [ -n "$RUNS" ]; then
      TARGET_STOP_REASON="runs-limit"
    elif [ -n "$MAX_TOTAL_TIME" ]; then
      TARGET_STOP_REASON="max-total-time"
    else
      TARGET_STOP_REASON="fuzzer-completed"
    fi
  fi

  if [ "$TARGET_EFFECTIVE_EXIT_STATUS" -eq 0 ] && \
    { [ "$TARGET_STATUS" = "target-crash" ] || [ "$TARGET_STATUS" = "harness-error" ] || \
      [ "$TARGET_STATUS" = "infrastructure-failed" ] || \
      { [ "$TARGET_STATUS" = "timed-out" ] && [ "$TARGET_STOP_REASON" != "max-total-time" ]; }; }; then
    TARGET_EFFECTIVE_EXIT_STATUS=1
  fi
}

write_target_summary() {
  local summary_file="$1"
  local detail_file="$2"
  local target_name="$3"
  local target_root="$4"
  local status="$5"
  local stop_reason="$6"
  local raw_exit_status="$7"
  local effective_exit_status="$8"
  local start_ts="$9"
  local end_ts="${10}"
  local start_ns="${11}"
  local end_ns="${12}"
  local binary="${13}"
  local log_file="${14}"
  local corpus_dir="${15}"
  local corpus_seed_count="${16}"
  local crash_dir="${17}"
  local artifact_dir="${18}"
  local findings_dir="${19}"
  local diagnostics_dir="${20}"
  local metadata_file="${21}"
  local time_file="${22}"
  local outcomes_dir="${23}"
  shift 23

  LIBFUZZER_SUMMARY_FILE="$summary_file" \
  LIBFUZZER_PROFILE_DETAIL_FILE="$detail_file" \
  LIBFUZZER_VERSION="$VERSION" \
  LIBFUZZER_TARGET="$target_name" \
  LIBFUZZER_TARGET_ROOT="$target_root" \
  LIBFUZZER_MODE="$MODE" \
  LIBFUZZER_PROFILE="$PROFILE" \
  LIBFUZZER_STATUS="$status" \
  LIBFUZZER_STOP_REASON="$stop_reason" \
  LIBFUZZER_RAW_EXIT_STATUS="$raw_exit_status" \
  LIBFUZZER_EFFECTIVE_EXIT_STATUS="$effective_exit_status" \
  LIBFUZZER_START_TS="$start_ts" \
  LIBFUZZER_END_TS="$end_ts" \
  LIBFUZZER_START_NS="$start_ns" \
  LIBFUZZER_END_NS="$end_ns" \
  LIBFUZZER_BINARY="$binary" \
  LIBFUZZER_LOG_FILE="$log_file" \
  LIBFUZZER_CORPUS_DIR="$corpus_dir" \
  LIBFUZZER_CORPUS_SEED_COUNT="$corpus_seed_count" \
  LIBFUZZER_CRASH_DIR="$crash_dir" \
  LIBFUZZER_ARTIFACT_DIR="$artifact_dir" \
  LIBFUZZER_FINDINGS_DIR="$findings_dir" \
  LIBFUZZER_DIAGNOSTICS_DIR="$diagnostics_dir" \
  LIBFUZZER_OUTCOMES_DIR="$outcomes_dir" \
  LIBFUZZER_METADATA_FILE="$metadata_file" \
  LIBFUZZER_TIME_FILE="$time_file" \
  LIBFUZZER_JOBS="$JOBS" \
  LIBFUZZER_WORKERS="$WORKERS" \
  LIBFUZZER_CPU_ALLOCATION="$CPU_ALLOCATION" \
  LIBFUZZER_HOST_CPU_COUNT="$HOST_CPU_COUNT" \
  LIBFUZZER_MAX_EXEMPLARS_PER_GROUP="$MAX_EXEMPLARS_PER_GROUP" \
  python3 - "$@" <<'PY'
import json
import os
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


def load_object(path):
    try:
        with path.open(encoding="utf-8") as f:
            value = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def relative_files(root, directory, predicate):
    if not directory.is_dir():
        return []
    return sorted(
        str(path.relative_to(root))
        for path in directory.rglob("*")
        if path.is_file() and predicate(path)
    )


def json_records(paths):
    records = []
    for path in paths:
        try:
            with path.open(encoding="utf-8") as f:
                record = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def string_list(value):
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def timing(path):
    try:
        values = path.read_text(encoding="utf-8").strip().split()
        user_seconds, system_seconds = float(values[0]), float(values[1])
    except (OSError, ValueError, IndexError):
        return None, None, None
    return user_seconds, system_seconds, user_seconds + system_seconds


summary_path = Path(os.environ["LIBFUZZER_SUMMARY_FILE"])
detail_path = Path(os.environ["LIBFUZZER_PROFILE_DETAIL_FILE"])
target_root = Path(os.environ["LIBFUZZER_TARGET_ROOT"])
findings_dir = Path(os.environ["LIBFUZZER_FINDINGS_DIR"])
diagnostics_dir = Path(os.environ["LIBFUZZER_DIAGNOSTICS_DIR"])
outcomes_dir = Path(os.environ["LIBFUZZER_OUTCOMES_DIR"])
crash_dir = Path(os.environ["LIBFUZZER_CRASH_DIR"])
corpus_dir = Path(os.environ["LIBFUZZER_CORPUS_DIR"])
metadata_path = Path(os.environ["LIBFUZZER_METADATA_FILE"])

semantic_paths = [
    path for path in findings_dir.rglob("*.json")
    if path.is_file()
] if findings_dir.is_dir() else []
semantic_paths.sort()
diagnostic_paths = [
    path for path in diagnostics_dir.rglob("*.json")
    if path.is_file()
] if diagnostics_dir.is_dir() else []
diagnostic_paths.sort()
outcome_paths = [
    path for path in outcomes_dir.rglob("*.json")
    if path.is_file()
] if outcomes_dir.is_dir() else []
outcome_paths.sort()
sanitizer_prefixes = ("crash-", "timeout-", "leak-", "oom-")
sanitizer_paths = relative_files(
    target_root,
    crash_dir,
    lambda path: path.name.startswith(sanitizer_prefixes),
)
semantic_findings = [str(path.relative_to(target_root)) for path in semantic_paths]
operation_diagnostics = [str(path.relative_to(target_root)) for path in diagnostic_paths]
structured_outcomes = [str(path.relative_to(target_root)) for path in outcome_paths]
records = json_records(semantic_paths)
diagnostic_records = json_records(diagnostic_paths)
outcome_records = json_records(outcome_paths)
metadata = load_object(metadata_path)

algorithm_list = string_list(
    metadata.get("enabled_algorithms", metadata.get("algorithm_list", metadata.get("algorithms")))
)
property_list = string_list(
    metadata.get("property_ids", metadata.get("property_list", metadata.get("properties")))
)
if not algorithm_list:
    algorithm_list = sorted({record["algorithm"] for record in records if isinstance(record.get("algorithm"), str)})
if not property_list:
    property_list = sorted({record["property_id"] for record in records if isinstance(record.get("property_id"), str)})
else:
    algorithm_list = sorted(set(algorithm_list))
    property_list = sorted(set(property_list))

supported_pairs = {
    f"{algorithm}|{property_id}"
    for algorithm in algorithm_list for property_id in property_list
}
covered_pairs = {
    f"{record['algorithm']}|{record['property_id']}"
    for record in records + diagnostic_records + outcome_records
    if isinstance(record.get("algorithm"), str) and isinstance(record.get("property_id"), str)
    and record.get("classification") in ("property_exercised", "skipped")
}
if os.environ["LIBFUZZER_PROFILE"] != "semantic":
    coverage_status = "not-applicable"
    unexercised_pairs = []
elif not supported_pairs:
    coverage_status = "unknown"
    unexercised_pairs = []
else:
    unexercised_pairs = sorted(supported_pairs - covered_pairs)
    coverage_status = "complete" if not unexercised_pairs else "incomplete"

user_seconds, system_seconds, cpu_seconds = timing(Path(os.environ["LIBFUZZER_TIME_FILE"]))
try:
    wall_seconds = max(
        0.0,
        (int(os.environ["LIBFUZZER_END_NS"]) - int(os.environ["LIBFUZZER_START_NS"])) / 1_000_000_000,
    )
except ValueError:
    wall_seconds = None

corpus_file_count = len([
    path for path in corpus_dir.rglob("*") if path.is_file()
]) if corpus_dir.is_dir() else 0

normalized_outcome = {
    "completed": "ok",
    "completed-with-findings": "invariant_violation",
    "timed-out": "process_hang",
    "target-crash": "process_crash",
    "harness-error": "operation_error",
    "infrastructure-failed": "operation_error",
    "completed-with-coverage-gap": "coverage_incomplete",
}.get(os.environ["LIBFUZZER_STATUS"], "operation_error")

summary_status = os.environ["LIBFUZZER_STATUS"]
if coverage_status == "incomplete" and summary_status in ("completed", "completed-with-findings"):
    summary_status = "completed-with-coverage-gap"
    normalized_outcome = "coverage_incomplete"

summary = {
    "baseline": "libFuzzer",
    "target": os.environ["LIBFUZZER_TARGET"],
    "version": os.environ["LIBFUZZER_VERSION"],
    "profile": os.environ["LIBFUZZER_PROFILE"],
    "mode": os.environ["LIBFUZZER_MODE"],
    "status": summary_status,
    "normalized_outcome": normalized_outcome,
    "exit_status": as_int(os.environ["LIBFUZZER_RAW_EXIT_STATUS"]),
    "effective_exit_status": as_int(os.environ["LIBFUZZER_EFFECTIVE_EXIT_STATUS"]),
    "stop_reason": os.environ["LIBFUZZER_STOP_REASON"],
    "started_at": os.environ["LIBFUZZER_START_TS"],
    "ended_at": os.environ["LIBFUZZER_END_TS"],
    "wall_time_seconds": wall_seconds,
    "cpu_time_seconds": cpu_seconds,
    "cpu_user_seconds": user_seconds,
    "cpu_system_seconds": system_seconds,
    "worker_count": as_int(os.environ["LIBFUZZER_WORKERS"]),
    "jobs": as_int(os.environ["LIBFUZZER_JOBS"]),
    "cpu_allocation": os.environ["LIBFUZZER_CPU_ALLOCATION"],
    "host_cpu_count": as_int(os.environ["LIBFUZZER_HOST_CPU_COUNT"]),
    "max_exemplars_per_group": as_int(os.environ["LIBFUZZER_MAX_EXEMPLARS_PER_GROUP"]),
    "algorithm_list": algorithm_list,
    "property_list": property_list,
    "coverage_status": coverage_status,
    "supported_pair_count": len(supported_pairs),
    "covered_pair_count": len(covered_pairs),
    "covered_pair_list": sorted(covered_pairs),
    "unexercised_pair_list": unexercised_pairs,
    "corpus_seed_count": as_int(os.environ["LIBFUZZER_CORPUS_SEED_COUNT"]),
    "corpus_file_count": corpus_file_count,
    "semantic_finding_count": len(semantic_findings),
    "semantic_findings": semantic_findings,
    "operation_diagnostic_count": len(operation_diagnostics),
    "operation_diagnostics": operation_diagnostics,
    "sanitizer_artifact_count": len(sanitizer_paths),
    "sanitizer_artifacts": sanitizer_paths,
    # Compatibility with the pre-profile summary and consumers that use this name.
    "crashes": sanitizer_paths,
    "binary": os.environ["LIBFUZZER_BINARY"],
    "log": os.environ["LIBFUZZER_LOG_FILE"],
    "corpus_dir": os.environ["LIBFUZZER_CORPUS_DIR"],
    "crash_dir": os.environ["LIBFUZZER_CRASH_DIR"],
    "artifact_dir": os.environ["LIBFUZZER_ARTIFACT_DIR"],
    "findings_dir": os.environ["LIBFUZZER_FINDINGS_DIR"],
    "diagnostics_dir": os.environ["LIBFUZZER_DIAGNOSTICS_DIR"],
    "outcomes_dir": os.environ["LIBFUZZER_OUTCOMES_DIR"],
    "metadata_file": os.environ["LIBFUZZER_METADATA_FILE"],
    "structured_outcome_count": len(structured_outcomes),
    "structured_outcomes": structured_outcomes,
    "args": list(__import__("sys").argv[1:]),
    "worker_logs": relative_files(
        target_root,
        Path(os.environ["LIBFUZZER_LOG_FILE"]).parent,
        lambda path: path.name.startswith("fuzz-") and path.name.endswith(".log"),
    ),
}

atomic_write(detail_path, summary)

index = load_object(summary_path)
profiles = index.get("profiles")
if not isinstance(profiles, dict):
    profiles = {}
profile_summaries = index.get("profile_summaries")
if not isinstance(profile_summaries, dict):
    profile_summaries = {}
for obsolete_key in (
    "profile", "status", "normalized_outcome", "exit_status", "effective_exit_status", "stop_reason",
    "semantic_finding_count", "sanitizer_artifact_count", "operation_diagnostic_count",
):
    index.pop(obsolete_key, None)
profiles[summary["profile"]] = summary
profile_summaries[summary["profile"]] = detail_path.name
index.update({
    "baseline": "libFuzzer",
    "target": summary["target"],
    "version": summary["version"],
    "profiles": profiles,
    "profile_summaries": profile_summaries,
    "latest_profile": summary["profile"],
    "updated_at": summary["ended_at"],
})
atomic_write(summary_path, index)
PY
}

update_aggregate_summary() {
  local summary_file="$1"
  local requested_target="$2"

  LIBFUZZER_AGGREGATE_FILE="$summary_file" \
  LIBFUZZER_VERSION="$VERSION" \
  LIBFUZZER_PROFILE="$PROFILE" \
  LIBFUZZER_MODE="$MODE" \
  LIBFUZZER_REQUESTED_TARGET="$requested_target" \
  LIBFUZZER_ROOT_START_TS="$ROOT_START_TS" \
  LIBFUZZER_ROOT_END_TS="$ROOT_END_TS" \
  python3 - <<'PY'
import json
import os
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


def load_object(path):
    try:
        with path.open(encoding="utf-8") as f:
            value = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


summary_path = Path(os.environ["LIBFUZZER_AGGREGATE_FILE"])
profile = os.environ["LIBFUZZER_PROFILE"]
targets = {}
for target_name in ("kem", "sig"):
    detail_path = summary_path.parent / target_name / f"summary.{profile}.json"
    detail = load_object(detail_path)
    if detail.get("profile") == profile and detail.get("target") == target_name:
        targets[target_name] = detail

# A version aggregate represents a matched KEM/SIG pair.  Single-target runs
# deliberately leave only their target detail behind; the later sibling run
# will build the aggregate from both profile-specific records.  This avoids a
# partial result being mistaken for a complete baseline comparison.
if len(targets) != 2:
    raise SystemExit(0)

target_statuses = {target: record.get("status") for target, record in targets.items()}
target_stop_reasons = {target: record.get("stop_reason") for target, record in targets.items()}
failure_statuses = ("target-crash", "harness-error", "infrastructure-failed", "timed-out")
if any(status == "target-crash" for status in target_statuses.values()):
    aggregate_status = "target-crash"
elif any(status == "harness-error" for status in target_statuses.values()):
    aggregate_status = "harness-error"
elif any(status == "infrastructure-failed" for status in target_statuses.values()):
    aggregate_status = "infrastructure-failed"
elif any(status == "timed-out" for status in target_statuses.values()):
    aggregate_status = "timed-out"
elif any(status == "completed-with-coverage-gap" for status in target_statuses.values()):
    aggregate_status = "completed-with-coverage-gap"
elif any(status == "completed-with-findings" for status in target_statuses.values()):
    aggregate_status = "completed-with-findings"
else:
    aggregate_status = "completed"

aggregate = {
    "baseline": "libFuzzer",
    "version": os.environ["LIBFUZZER_VERSION"],
    "profile": profile,
    "mode": os.environ["LIBFUZZER_MODE"],
    "requested_target": os.environ["LIBFUZZER_REQUESTED_TARGET"],
    "status": aggregate_status,
    "normalized_outcome": {
        "completed": "ok",
        "completed-with-findings": "invariant_violation",
        "completed-with-coverage-gap": "coverage_incomplete",
        "timed-out": "process_hang",
        "target-crash": "process_crash",
        "harness-error": "operation_error",
        "infrastructure-failed": "operation_error",
    }.get(aggregate_status, "operation_error"),
    "started_at": os.environ["LIBFUZZER_ROOT_START_TS"],
    "ended_at": os.environ["LIBFUZZER_ROOT_END_TS"],
    "targets": targets,
    "target_statuses": target_statuses,
    "target_stop_reasons": target_stop_reasons,
    "targets_completed": sorted(targets),
    "targets_pending": [],
    "complete": True,
    "semantic_finding_count": sum(as_int(record.get("semantic_finding_count")) for record in targets.values()),
    "sanitizer_artifact_count": sum(as_int(record.get("sanitizer_artifact_count")) for record in targets.values()),
    "operation_diagnostic_count": sum(as_int(record.get("operation_diagnostic_count")) for record in targets.values()),
    "coverage_status": "complete" if all(record.get("coverage_status") == "complete" for record in targets.values()) else "incomplete",
    "supported_pair_count": sum(as_int(record.get("supported_pair_count")) for record in targets.values()),
    "covered_pair_count": sum(as_int(record.get("covered_pair_count")) for record in targets.values()),
    "unexercised_pair_list": sorted({
        pair for record in targets.values() for pair in record.get("unexercised_pair_list", [])
        if isinstance(pair, str)
    }),
    "exit_status": next(
        (as_int(record.get("exit_status")) for record in targets.values() if as_int(record.get("exit_status")) != 0),
        0,
    ),
    "effective_exit_status": next(
        (as_int(record.get("effective_exit_status")) for record in targets.values() if as_int(record.get("effective_exit_status")) != 0),
        0,
    ),
}

detail_path = summary_path.with_name(f"summary.{profile}.json")
atomic_write(detail_path, aggregate)

index = load_object(summary_path)
profiles = index.get("profiles")
if not isinstance(profiles, dict):
    profiles = {}
profile_summaries = index.get("profile_summaries")
if not isinstance(profile_summaries, dict):
    profile_summaries = {}
for obsolete_key in (
    "profile", "status", "normalized_outcome", "semantic_finding_count", "sanitizer_artifact_count",
    "operation_diagnostic_count", "exit_status", "effective_exit_status",
):
    index.pop(obsolete_key, None)
profiles[profile] = aggregate
profile_summaries[profile] = detail_path.name
index.update({
    "baseline": "libFuzzer",
    "version": os.environ["LIBFUZZER_VERSION"],
    "profiles": profiles,
    "profile_summaries": profile_summaries,
    "latest_profile": profile,
    "updated_at": os.environ["LIBFUZZER_ROOT_END_TS"],
})
atomic_write(summary_path, index)
PY
}

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
echo "[libFuzzer] profile: $PROFILE"
echo "[libFuzzer] target: $TARGET"
echo "[libFuzzer] mode: $MODE"
echo "[libFuzzer] workers: $WORKERS; CPU allocation: $CPU_ALLOCATION"

ROOT_START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OVERALL_STATUS=0

for TARGET_NAME in "${TARGETS[@]}"; do
  TARGET_RUN_DIR="${VERSION_RUN_DIR}/${TARGET_NAME}"
  LOG_DIR="${TARGET_RUN_DIR}/logs/${PROFILE}"
  CORPUS_DIR="${TARGET_RUN_DIR}/corpus/${PROFILE}"
  CRASH_DIR="${TARGET_RUN_DIR}/crashes/${PROFILE}"
  ARTIFACT_DIR="${TARGET_RUN_DIR}/artifacts/${PROFILE}"
  FINDINGS_DIR="${TARGET_RUN_DIR}/findings/${PROFILE}"
  DIAGNOSTICS_DIR="${TARGET_RUN_DIR}/diagnostics/${PROFILE}"
  OUTCOMES_DIR="${TARGET_RUN_DIR}/outcomes/${PROFILE}"
  METADATA_DIR="${TARGET_RUN_DIR}/metadata"
  METADATA_FILE="${METADATA_DIR}/${PROFILE}.json"
  TIME_FILE="${METADATA_DIR}/${PROFILE}.time"
  TARGET_SUMMARY_FILE="${TARGET_RUN_DIR}/summary.json"
  TARGET_PROFILE_SUMMARY_FILE="${TARGET_RUN_DIR}/summary.${PROFILE}.json"
  LOG_FILE="${LOG_DIR}/${MODE}.log"
  BINARY="${FUZZER_BUILD_DIR}/fuzz_${TARGET_NAME}"

  mkdir -p "$LOG_DIR" "$CORPUS_DIR" "$CRASH_DIR" "$ARTIFACT_DIR" "$FINDINGS_DIR" "$DIAGNOSTICS_DIR" "$OUTCOMES_DIR" "$METADATA_DIR"
  seed_default_envelope "$CORPUS_DIR" "$TARGET_NAME"
  CORPUS_SEED_COUNT="$(count_files_named "$CORPUS_DIR" '*')"

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
  START_NS="$(epoch_ns)"

  if [ ! -x "$BINARY" ]; then
    RAW_EXIT_STATUS=127
    {
      echo "libFuzzer binary not found: $BINARY"
      echo "Run: scripts/run_baseline.sh libFuzzer build --version $VERSION"
    } 2>&1 | tee "$LOG_FILE"
  else
    set +e
    if [ -x /usr/bin/time ]; then
      (
        cd "$LOG_DIR" || exit 125
        PQCDF_LIBFUZZER_PROFILE="$PROFILE" \
        PQCDF_LIBFUZZER_FINDINGS_DIR="$FINDINGS_DIR" \
        PQCDF_LIBFUZZER_DIAGNOSTICS_DIR="$DIAGNOSTICS_DIR" \
        PQCDF_LIBFUZZER_OUTCOMES_DIR="$OUTCOMES_DIR" \
        PQCDF_LIBFUZZER_METADATA_FILE="$METADATA_FILE" \
        PQCDF_LIBFUZZER_MAX_EXEMPLARS_PER_GROUP="$MAX_EXEMPLARS_PER_GROUP" \
        PQCDF_LIBFUZZER_TARGET="$TARGET_NAME" \
        PQCDF_LIBFUZZER_VERSION="$VERSION" \
        /usr/bin/time -f '%U %S' -o "$TIME_FILE" "$BINARY" "${ARGS[@]}"
      ) 2>&1 | tee "$LOG_FILE"
    else
      (
        cd "$LOG_DIR" || exit 125
        PQCDF_LIBFUZZER_PROFILE="$PROFILE" \
        PQCDF_LIBFUZZER_FINDINGS_DIR="$FINDINGS_DIR" \
        PQCDF_LIBFUZZER_DIAGNOSTICS_DIR="$DIAGNOSTICS_DIR" \
        PQCDF_LIBFUZZER_OUTCOMES_DIR="$OUTCOMES_DIR" \
        PQCDF_LIBFUZZER_METADATA_FILE="$METADATA_FILE" \
        PQCDF_LIBFUZZER_MAX_EXEMPLARS_PER_GROUP="$MAX_EXEMPLARS_PER_GROUP" \
        PQCDF_LIBFUZZER_TARGET="$TARGET_NAME" \
        PQCDF_LIBFUZZER_VERSION="$VERSION" \
        "$BINARY" "${ARGS[@]}"
      ) 2>&1 | tee "$LOG_FILE"
    fi
    RAW_EXIT_STATUS="${PIPESTATUS[0]}"
    set -e
  fi

  END_NS="$(epoch_ns)"
  END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  SEMANTIC_FINDING_COUNT="$(count_files_named "$FINDINGS_DIR" '*.json')"
  classify_target_result "$RAW_EXIT_STATUS" "$SEMANTIC_FINDING_COUNT" "$CRASH_DIR" "$LOG_FILE"

  write_target_summary \
    "$TARGET_SUMMARY_FILE" \
    "$TARGET_PROFILE_SUMMARY_FILE" \
    "$TARGET_NAME" \
    "$TARGET_RUN_DIR" \
    "$TARGET_STATUS" \
    "$TARGET_STOP_REASON" \
    "$RAW_EXIT_STATUS" \
    "$TARGET_EFFECTIVE_EXIT_STATUS" \
    "$START_TS" \
    "$END_TS" \
    "$START_NS" \
    "$END_NS" \
    "$BINARY" \
    "$LOG_FILE" \
    "$CORPUS_DIR" \
    "$CORPUS_SEED_COUNT" \
    "$CRASH_DIR" \
    "$ARTIFACT_DIR" \
    "$FINDINGS_DIR" \
    "$DIAGNOSTICS_DIR" \
    "$METADATA_FILE" \
    "$TIME_FILE" \
    "$OUTCOMES_DIR" \
    "${ARGS[@]}"
  echo "[libFuzzer] ${TARGET_NAME} ${PROFILE} summary: $TARGET_PROFILE_SUMMARY_FILE"

  if [ "$TARGET_EFFECTIVE_EXIT_STATUS" -ne 0 ] && [ "$OVERALL_STATUS" -eq 0 ]; then
    OVERALL_STATUS="$TARGET_EFFECTIVE_EXIT_STATUS"
  fi
done

ROOT_END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PROFILE_TARGET_SUMMARY_COUNT=0
for TARGET_NAME in kem sig; do
  if [ -f "${VERSION_RUN_DIR}/${TARGET_NAME}/summary.${PROFILE}.json" ]; then
    PROFILE_TARGET_SUMMARY_COUNT=$((PROFILE_TARGET_SUMMARY_COUNT + 1))
  fi
done
if [ "$PROFILE_TARGET_SUMMARY_COUNT" -eq 2 ]; then
  update_aggregate_summary "$AGGREGATE_SUMMARY_FILE" "$TARGET"
  echo "[libFuzzer] summary index: $AGGREGATE_SUMMARY_FILE"
else
  echo "[libFuzzer] aggregate awaits the ${PROFILE} sibling target summary"
fi

if [ "$OVERALL_STATUS" -ne 0 ]; then
  echo "[libFuzzer] one or more runs failed; see summaries under $VERSION_RUN_DIR" >&2
  exit "$OVERALL_STATUS"
fi

echo "[libFuzzer] run completed"

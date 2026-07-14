#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/run_baseline.sh CLFuzz run [options] [extra libFuzzer args...]

Options:
  --version VERSION             Run against a supported liboqs version. Default: 0.14.0.
  --mode smoke|full|replay      Run a short/full campaign or one deterministic replay. Default: smoke.
  --profile NAME                Isolated campaign profile. Default: selected mode.
  --max-total-time SECONDS      libFuzzer -max_total_time value. Full default: 86400.
  --runs N                      libFuzzer -runs value. Smoke default: 1000.
  --jobs N                      libFuzzer -jobs value. Default: 1.
  --workers N                   libFuzzer -workers value. Default: 1.
  --seed N                      libFuzzer -seed value.
  --cpu-allocation VALUE        Fairness metadata for CPU allocation. Default: detected CPU count.
  --max-exemplars-per-group N   Maximum structured finding exemplars per group. Default: 3.
  --replay-input PATH           Required with --mode replay; raw CLFuzz input to replay.
  --replay-algorithm NAME       Enabled liboqs algorithm to pin during replay.
  --replay-property ID          KEM/SIG property to pin during replay.
  --replay-mutation-semantics VALUE
                               current-xor-v1 (default) or legacy-or-one-v1.
  --replay-attempts N           Exact-input replay attempts (minimum/default: 3).
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
PROFILE="${PQCDF_CLFUZZ_PROFILE:-}"
MAX_TOTAL_TIME=""
RUNS=""
JOBS="1"
WORKERS="1"
SEED=""
CPU_ALLOCATION="${PQCDF_CLFUZZ_CPU_ALLOCATION:-}"
MAX_EXEMPLARS_PER_GROUP="${PQCDF_CLFUZZ_MAX_EXEMPLARS_PER_GROUP:-3}"
REPLAY_INPUT=""
REPLAY_ALGORITHM=""
REPLAY_PROPERTY=""
REPLAY_MUTATION_SEMANTICS="current-xor-v1"
REPLAY_ATTEMPTS="3"
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
    --replay-input)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --replay-input." >&2
        exit 2
      fi
      REPLAY_INPUT="$2"
      shift 2
      ;;
    --replay-input=*)
      REPLAY_INPUT="${1#--replay-input=}"
      shift
      ;;
    --replay-algorithm)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --replay-algorithm." >&2
        exit 2
      fi
      REPLAY_ALGORITHM="$2"
      shift 2
      ;;
    --replay-algorithm=*)
      REPLAY_ALGORITHM="${1#--replay-algorithm=}"
      shift
      ;;
    --replay-property)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --replay-property." >&2
        exit 2
      fi
      REPLAY_PROPERTY="$2"
      shift 2
      ;;
    --replay-property=*)
      REPLAY_PROPERTY="${1#--replay-property=}"
      shift
      ;;
    --replay-mutation-semantics)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --replay-mutation-semantics." >&2
        exit 2
      fi
      REPLAY_MUTATION_SEMANTICS="$2"
      shift 2
      ;;
    --replay-mutation-semantics=*)
      REPLAY_MUTATION_SEMANTICS="${1#--replay-mutation-semantics=}"
      shift
      ;;
    --replay-attempts)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --replay-attempts." >&2
        exit 2
      fi
      REPLAY_ATTEMPTS="$2"
      shift 2
      ;;
    --replay-attempts=*)
      REPLAY_ATTEMPTS="${1#--replay-attempts=}"
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
    echo "Unsupported CLFuzz liboqs version: $VERSION" >&2
    echo "Supported versions: 0.14.0, 0.8.0, 0.4.0" >&2
    exit 2
    ;;
esac

case "$MODE" in
  smoke|full|replay) ;;
  *)
    echo "Unsupported CLFuzz mode: $MODE" >&2
    echo "Supported modes: smoke, full, replay" >&2
    exit 2
    ;;
esac

if [ -z "$PROFILE" ]; then
  PROFILE="$MODE"
fi
if ! [[ "$PROFILE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "--profile must contain only letters, digits, '.', '_' or '-' and cannot start with punctuation." >&2
  exit 2
fi

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
if ! [[ "$REPLAY_ATTEMPTS" =~ ^[0-9]+$ ]] || [ "$REPLAY_ATTEMPTS" -lt 3 ] || \
   [ "$REPLAY_ATTEMPTS" -gt 20 ]; then
  echo "--replay-attempts must be an integer from 3 through 20." >&2
  exit 2
fi
if [ "$MODE" = "replay" ]; then
  if [ -z "$REPLAY_INPUT" ] || [ -z "$REPLAY_ALGORITHM" ] || [ -z "$REPLAY_PROPERTY" ]; then
    echo "--mode replay requires --replay-input, --replay-algorithm, and --replay-property." >&2
    exit 2
  fi
  if [ "$REPLAY_MUTATION_SEMANTICS" != "current-xor-v1" ] && \
     [ "$REPLAY_MUTATION_SEMANTICS" != "legacy-or-one-v1" ]; then
    echo "--replay-mutation-semantics must be current-xor-v1 or legacy-or-one-v1." >&2
    exit 2
  fi
  if [ "$JOBS" != "1" ] || [ "$WORKERS" != "1" ] || [ -n "$RUNS" ] || [ -n "$MAX_TOTAL_TIME" ]; then
    echo "--mode replay requires one worker/job and does not accept --runs or --max-total-time." >&2
    exit 2
  fi
fi

if [ -z "$RUNS" ] && [ "$MODE" = "smoke" ]; then
  RUNS="1000"
fi
if [ -z "$MAX_TOTAL_TIME" ] && [ "$MODE" = "full" ]; then
  MAX_TOTAL_TIME="86400"
fi

mkdir -p "$BUILD_DIR" "$RUN_DIR"

IMAGE_NAME="pqcdf-baseline-clfuzz"
WRAPPER_ROOT="${PQCDF_BASELINE_WRAPPER_ROOT:-scripts/baselines}"

if [ "${PQCDF_CLFUZZ_IN_DOCKER:-0}" != "1" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required to run CLFuzz/liboqs through this wrapper." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed, but the Docker daemon is not available to this user." >&2
    exit 1
  fi
  if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Docker image not found: $IMAGE_NAME" >&2
    echo "Run: scripts/run_baseline.sh CLFuzz docker-build" >&2
    exit 1
  fi

  HOST_UID="$(id -u)"
  HOST_GID="$(id -g)"
  FORWARDED_ARGS=(
    "${WRAPPER_ROOT}/CLFuzz/run.sh"
    "$BASELINE_DIR"
    "$BUILD_DIR"
    "$RUN_DIR"
    --version "$VERSION"
    --mode "$MODE"
    --profile "$PROFILE"
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
  if [ "$MODE" = "replay" ]; then
    FORWARDED_ARGS+=(
      --replay-input "$REPLAY_INPUT"
      --replay-algorithm "$REPLAY_ALGORITHM"
      --replay-property "$REPLAY_PROPERTY"
      --replay-mutation-semantics "$REPLAY_MUTATION_SEMANTICS"
      --replay-attempts "$REPLAY_ATTEMPTS"
    )
  fi
  FORWARDED_ARGS+=("${EXTRA_ARGS[@]}")

  docker run --rm \
    -e PQCDF_CLFUZZ_IN_DOCKER=1 \
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

validate_extra_fuzzer_args() {
  local arg
  for arg in "$@"; do
    case "$arg" in
      -artifact_prefix=*|--artifact_prefix=*|-artifact_prefix|--artifact_prefix|\
      -exact_artifact_path=*|--exact_artifact_path=*|-exact_artifact_path|--exact_artifact_path|\
      -log_path=*|--log_path=*|-log_path|--log_path)
        echo "Extra libFuzzer argument '${arg}' overrides a runner-managed output path." >&2
        exit 2
        ;;
      -features_dir=*|--features_dir=*|-features_dir|--features_dir|\
      -mutation_graph_file=*|--mutation_graph_file=*|-mutation_graph_file|--mutation_graph_file|\
      -merge_control_file=*|--merge_control_file=*|-merge_control_file|--merge_control_file|\
      -stop_file=*|--stop_file=*|-stop_file|--stop_file|\
      -jobs=*|--jobs=*|-jobs|--jobs|-workers=*|--workers=*|-workers|--workers|\
      -runs=*|--runs=*|-runs|--runs|-max_total_time=*|--max_total_time=*|\
      -max_total_time|--max_total_time)
        echo "Extra libFuzzer argument '${arg}' overrides a runner-managed campaign setting." >&2
        exit 2
        ;;
    esac
  done
}

HOST_CPU_COUNT="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo unknown)"
if [ -z "$CPU_ALLOCATION" ]; then
  CPU_ALLOCATION="$HOST_CPU_COUNT"
fi

BUILD_DIR_ABS="$(realpath "$BUILD_DIR")"
RUN_DIR_ABS="$(realpath "$RUN_DIR")"
VERSION_BUILD_DIR="${BUILD_DIR_ABS}/liboqs-${VERSION}"
VERSION_RUN_DIR="$(resolve_path "${RUN_DIR_ABS}/liboqs-${VERSION}")"
if ! is_within "$RUN_DIR_ABS" "$VERSION_RUN_DIR"; then
  echo "Refusing to use version root outside run directory: ${VERSION_RUN_DIR}" >&2
  exit 1
fi
CAMPAIGN_ROOT="$(resolve_path "${VERSION_RUN_DIR}/${PROFILE}")"
if ! is_within "$VERSION_RUN_DIR" "$CAMPAIGN_ROOT"; then
  echo "Refusing to use profile root outside version root: ${CAMPAIGN_ROOT}" >&2
  exit 1
fi
mkdir -p "$CAMPAIGN_ROOT"
CAMPAIGN_ROOT="$(realpath "$CAMPAIGN_ROOT")"
if ! is_within "$RUN_DIR_ABS" "$CAMPAIGN_ROOT"; then
  echo "Refusing to use resolved campaign root outside run directory: ${CAMPAIGN_ROOT}" >&2
  exit 1
fi
CAMPAIGN_LOCK="${CAMPAIGN_ROOT}/.run.lock"
if ! mkdir "$CAMPAIGN_LOCK" 2>/dev/null; then
  echo "CLFuzz campaign profile is already running or has a stale lock: ${CAMPAIGN_LOCK}" >&2
  exit 1
fi
trap 'rmdir -- "$CAMPAIGN_LOCK" 2>/dev/null || true' EXIT
BINARY="${VERSION_BUILD_DIR}/clfuzz/clfuzz"
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

for spec in \
  "corpus directory:$CORPUS_DIR" \
  "crash directory:$CRASH_DIR" \
  "artifact directory:$ARTIFACT_DIR" \
  "finding directory:$FINDINGS_DIR" \
  "diagnostic directory:$DIAGNOSTICS_DIR" \
  "metadata directory:$METADATA_DIR" \
  "outcome directory:$OUTCOMES_DIR" \
  "log directory:$LOG_DIR" \
  "log file:$LOG_FILE" \
  "summary file:$SUMMARY_FILE" \
  "timing file:$TIME_FILE"; do
  require_campaign_path "${spec%%:*}" "${spec#*:}"
done

mkdir -p "$LOG_DIR" "$CORPUS_DIR" "$CRASH_DIR" "$ARTIFACT_DIR" \
  "$FINDINGS_DIR" "$DIAGNOSTICS_DIR" "$METADATA_DIR" "$OUTCOMES_DIR"
LOG_DIR="$(realpath "$LOG_DIR")"
CORPUS_DIR="$(realpath "$CORPUS_DIR")"
CRASH_DIR="$(realpath "$CRASH_DIR")"
ARTIFACT_DIR="$(realpath "$ARTIFACT_DIR")"
FINDINGS_DIR="$(realpath "$FINDINGS_DIR")"
DIAGNOSTICS_DIR="$(realpath "$DIAGNOSTICS_DIR")"
METADATA_DIR="$(realpath "$METADATA_DIR")"
OUTCOMES_DIR="$(realpath "$OUTCOMES_DIR")"
LOG_FILE="$(resolve_path "${LOG_DIR}/${MODE}.log")"
TIME_FILE="$(resolve_path "${METADATA_DIR}/${MODE}.time")"

for spec in \
  "resolved corpus directory:$CORPUS_DIR" \
  "resolved crash directory:$CRASH_DIR" \
  "resolved artifact directory:$ARTIFACT_DIR" \
  "resolved finding directory:$FINDINGS_DIR" \
  "resolved diagnostic directory:$DIAGNOSTICS_DIR" \
  "resolved metadata directory:$METADATA_DIR" \
  "resolved outcome directory:$OUTCOMES_DIR" \
  "resolved log directory:$LOG_DIR" \
  "resolved log file:$LOG_FILE" \
  "resolved timing file:$TIME_FILE"; do
  require_campaign_path "${spec%%:*}" "${spec#*:}"
done

validate_extra_fuzzer_args "${EXTRA_ARGS[@]}"

BINARY_MISSING=0
if [ ! -x "$BINARY" ]; then
  BINARY_MISSING=1
fi

REPLAY_INPUT_COPY=""
REPLAY_INPUT_SHA256=""
if [ "$MODE" = "replay" ]; then
  if [ ! -f "$REPLAY_INPUT" ]; then
    echo "Replay input does not exist or is not a regular file: $REPLAY_INPUT" >&2
    exit 2
  fi
  REPLAY_INPUT_SHA256="$(sha256sum "$REPLAY_INPUT" | awk '{print $1}')"
  REPLAY_INPUT_COPY="${FINDINGS_DIR}/replay-inputs/${REPLAY_INPUT_SHA256}.bin"
  mkdir -p "$(dirname "$REPLAY_INPUT_COPY")"
  cp -- "$REPLAY_INPUT" "$REPLAY_INPUT_COPY"
  REPLAY_INPUT_COPY="$(realpath "$REPLAY_INPUT_COPY")"
  require_campaign_path "replay input copy" "$REPLAY_INPUT_COPY"
fi

OPERATIONS="OQS_KEM_SelfTest,OQS_SIG_SelfTest"
ARGS=(
  "--operations=${OPERATIONS}"
  "--force-module=liboqs"
  "--min-modules=1"
  "-artifact_prefix=${CRASH_DIR}/"
  "-jobs=${JOBS}"
  "-workers=${WORKERS}"
)
if [ "$MODE" != "replay" ] && [ -n "$RUNS" ]; then
  ARGS+=("-runs=${RUNS}")
fi
if [ "$MODE" != "replay" ] && [ -n "$MAX_TOTAL_TIME" ]; then
  ARGS+=("-max_total_time=${MAX_TOTAL_TIME}")
fi
if [ -n "$SEED" ]; then
  ARGS+=("-seed=${SEED}")
fi
ARGS+=("${EXTRA_ARGS[@]}")
if [ "$MODE" = "replay" ]; then
  ARGS+=("-runs=1" "$REPLAY_INPUT_COPY")
else
  ARGS+=("$CORPUS_DIR")
fi

MODULE_ENV=(
  "PQCDF_LIBOQS_BASELINE=CLFuzz"
  "PQCDF_LIBOQS_FINDINGS_DIR=${FINDINGS_DIR}"
  "PQCDF_LIBOQS_DIAGNOSTICS_DIR=${DIAGNOSTICS_DIR}"
  "PQCDF_LIBOQS_METADATA_DIR=${METADATA_DIR}"
  "PQCDF_LIBOQS_OUTCOMES_DIR=${OUTCOMES_DIR}"
  "PQCDF_LIBOQS_LOG_FILE=${LOG_FILE}"
  "PQCDF_LIBOQS_MAX_EXEMPLARS_PER_GROUP=${MAX_EXEMPLARS_PER_GROUP}"
  "PQCDF_LIBOQS_VERSION=${VERSION}"
  "PQCDF_LIBOQS_MODULE_VERSION=pqcdf-clfuzz-liboqs-oracle-v2"
)
if [ "$MODE" = "replay" ]; then
  MODULE_ENV+=(
    "PQCDF_LIBOQS_REPLAY_MODE=raw-input-v1"
    "PQCDF_LIBOQS_REPLAY_ALGORITHM=${REPLAY_ALGORITHM}"
    "PQCDF_LIBOQS_REPLAY_PROPERTY=${REPLAY_PROPERTY}"
    "PQCDF_LIBOQS_MUTATION_SEMANTICS=${REPLAY_MUTATION_SEMANTICS}"
    "PQCDF_LIBOQS_REPLAY_ATTEMPTS=${REPLAY_ATTEMPTS}"
    "PQCDF_LIBOQS_REPLAY_INPUT_SHA256=${REPLAY_INPUT_SHA256}"
    "PQCDF_LIBOQS_REPLAY_INPUT_RELATIVE_PATH=replay-inputs/${REPLAY_INPUT_SHA256}.bin"
  )
else
  MODULE_ENV+=(
    "PQCDF_LIBOQS_REPLAY_MODE="
    "PQCDF_LIBOQS_REPLAY_ALGORITHM="
    "PQCDF_LIBOQS_REPLAY_PROPERTY="
    "PQCDF_LIBOQS_MUTATION_SEMANTICS="
    "PQCDF_LIBOQS_REPLAY_ATTEMPTS="
    "PQCDF_LIBOQS_REPLAY_INPUT_SHA256="
    "PQCDF_LIBOQS_REPLAY_INPUT_RELATIVE_PATH="
  )
fi

echo "[CLFuzz] run directory: $CAMPAIGN_ROOT"
echo "[CLFuzz] liboqs version: $VERSION"
echo "[CLFuzz] mode: $MODE"
echo "[CLFuzz] profile: $PROFILE"
echo "[CLFuzz] working directory: $LOG_DIR"
echo "[CLFuzz] log file: $LOG_FILE"
echo "[CLFuzz] workers: $WORKERS; CPU allocation: $CPU_ALLOCATION"

START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
START_NS="$(epoch_ns)"
set +e
if [ "$BINARY_MISSING" -eq 1 ]; then
  {
    echo "CLFuzz binary not found: $BINARY"
    echo "Run: scripts/run_baseline.sh CLFuzz build --version $VERSION"
  } 2>&1 | tee "$LOG_FILE"
  STATUS=1
elif [ -x /usr/bin/time ]; then
  (
    cd "$LOG_DIR" || exit 125
    /usr/bin/time -o "$TIME_FILE" -f '%U %S' env "${MODULE_ENV[@]}" "$BINARY" "${ARGS[@]}"
  ) 2>&1 | tee "$LOG_FILE"
  STATUS="${PIPESTATUS[0]}"
else
  (
    cd "$LOG_DIR" || exit 125
    env "${MODULE_ENV[@]}" "$BINARY" "${ARGS[@]}"
  ) 2>&1 | tee "$LOG_FILE"
  STATUS="${PIPESTATUS[0]}"
fi
set -e
END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
END_NS="$(epoch_ns)"

# libFuzzer normally exits nonzero for fatal target artifacts.  Treat an
# artifact or sanitizer report as terminal even if a wrapper returned zero, so
# a healthy semantic-finding campaign cannot mask a target crash.
EFFECTIVE_STATUS="$STATUS"
if [ "$STATUS" -eq 0 ]; then
  if find "$CRASH_DIR" -type f \( -name 'crash-*' -o -name 'leak-*' -o -name 'oom-*' \) -print -quit | grep -q .; then
    EFFECTIVE_STATUS=77
  elif find "$CRASH_DIR" -type f -name 'timeout-*' -print -quit | grep -q .; then
    EFFECTIVE_STATUS=70
  elif grep -Eq 'AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|LeakSanitizer|ERROR: libFuzzer: deadly signal|runtime error:' "$LOG_FILE"; then
    EFFECTIVE_STATUS=77
  fi
fi

CLFUZZ_SUMMARY_FILE="$SUMMARY_FILE" \
CLFUZZ_CAMPAIGN_ROOT="$CAMPAIGN_ROOT" \
CLFUZZ_VERSION="$VERSION" \
CLFUZZ_MODE="$MODE" \
CLFUZZ_PROFILE="$PROFILE" \
CLFUZZ_STATUS="$STATUS" \
CLFUZZ_EFFECTIVE_STATUS="$EFFECTIVE_STATUS" \
CLFUZZ_BINARY_MISSING="$BINARY_MISSING" \
CLFUZZ_START_TS="$START_TS" \
CLFUZZ_END_TS="$END_TS" \
CLFUZZ_START_NS="$START_NS" \
CLFUZZ_END_NS="$END_NS" \
CLFUZZ_BINARY="$BINARY" \
CLFUZZ_BUILD_METADATA="${VERSION_BUILD_DIR}/sanitizer-profile.json" \
CLFUZZ_LOG_FILE="$LOG_FILE" \
CLFUZZ_LOG_DIR="$LOG_DIR" \
CLFUZZ_CORPUS_DIR="$CORPUS_DIR" \
CLFUZZ_CRASH_DIR="$CRASH_DIR" \
CLFUZZ_ARTIFACT_DIR="$ARTIFACT_DIR" \
CLFUZZ_FINDINGS_DIR="$FINDINGS_DIR" \
CLFUZZ_DIAGNOSTICS_DIR="$DIAGNOSTICS_DIR" \
CLFUZZ_METADATA_DIR="$METADATA_DIR" \
CLFUZZ_OUTCOMES_DIR="$OUTCOMES_DIR" \
CLFUZZ_TIME_FILE="$TIME_FILE" \
CLFUZZ_JOBS="$JOBS" \
CLFUZZ_WORKERS="$WORKERS" \
CLFUZZ_CPU_ALLOCATION="$CPU_ALLOCATION" \
CLFUZZ_HOST_CPU_COUNT="$HOST_CPU_COUNT" \
CLFUZZ_MAX_EXEMPLARS_PER_GROUP="$MAX_EXEMPLARS_PER_GROUP" \
CLFUZZ_OPERATIONS="$OPERATIONS" \
CLFUZZ_REPLAY_INPUT_SHA256="$REPLAY_INPUT_SHA256" \
CLFUZZ_REPLAY_INPUT_COPY="$REPLAY_INPUT_COPY" \
CLFUZZ_REPLAY_ALGORITHM="$REPLAY_ALGORITHM" \
CLFUZZ_REPLAY_PROPERTY="$REPLAY_PROPERTY" \
CLFUZZ_REPLAY_MUTATION_SEMANTICS="$REPLAY_MUTATION_SEMANTICS" \
CLFUZZ_REPLAY_ATTEMPTS="$REPLAY_ATTEMPTS" \
python3 - "${ARGS[@]}" <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path


def atomic_write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".summary.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def relative_files(root: Path, directory: Path, predicate) -> list[str]:
    if not directory.is_dir():
        return []
    values = []
    for path in directory.rglob("*"):
        if not path.is_file() or not predicate(path):
            continue
        try:
            values.append(str(path.resolve().relative_to(root)))
        except ValueError:
            continue
    return sorted(values)


def json_records(root: Path, paths: list[str]) -> list[dict]:
    records = []
    for relative in paths:
        try:
            with (root / relative).open(encoding="utf-8") as handle:
                value = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def string_values(records: list[dict], keys: tuple[str, ...]) -> list[str]:
    values = set()
    for record in records:
        for key in keys:
            value = record.get(key)
            if isinstance(value, str):
                values.add(value)
            elif isinstance(value, list):
                values.update(item for item in value if isinstance(item, str))
    return sorted(values)


def timing(path: Path):
    try:
        user_seconds, system_seconds = map(float, path.read_text(encoding="utf-8").split()[:2])
    except (OSError, ValueError):
        return None, None, None
    return user_seconds, system_seconds, user_seconds + system_seconds


def integer(value: str):
    try:
        return int(value)
    except ValueError:
        return value


root = Path(os.environ["CLFUZZ_CAMPAIGN_ROOT"]).resolve()
summary_path = Path(os.environ["CLFUZZ_SUMMARY_FILE"])
log_dir = Path(os.environ["CLFUZZ_LOG_DIR"]).resolve()
crash_dir = Path(os.environ["CLFUZZ_CRASH_DIR"]).resolve()
findings_dir = Path(os.environ["CLFUZZ_FINDINGS_DIR"]).resolve()
diagnostics_dir = Path(os.environ["CLFUZZ_DIAGNOSTICS_DIR"]).resolve()
metadata_dir = Path(os.environ["CLFUZZ_METADATA_DIR"]).resolve()
outcomes_dir = Path(os.environ["CLFUZZ_OUTCOMES_DIR"]).resolve()

semantic_findings = relative_files(root, findings_dir, lambda path: path.suffix == ".json")
operation_diagnostics = relative_files(root, diagnostics_dir, lambda path: path.suffix == ".json")
structured_outcomes = relative_files(root, outcomes_dir, lambda path: path.suffix == ".json")
sanitizer_crashes = relative_files(root, crash_dir, lambda path: path.name.startswith(("crash-", "leak-", "oom-")))
hangs = relative_files(root, crash_dir, lambda path: path.name.startswith("timeout-"))
worker_logs = relative_files(root, log_dir, lambda path: path.name.startswith("fuzz-") and path.name.endswith(".log"))
metadata_files = relative_files(root, metadata_dir, lambda path: path.suffix == ".json")
records = json_records(root, semantic_findings)
diagnostic_records = json_records(root, operation_diagnostics)
outcome_records = json_records(root, structured_outcomes)
metadata_records = json_records(root, metadata_files)
all_records = records + diagnostic_records + outcome_records
algorithms = string_values(all_records + metadata_records, (
    "algorithm", "enabled_algorithms", "enabled_kem_algorithms", "enabled_sig_algorithms",
))
properties = string_values(all_records + metadata_records, (
    "property_id", "property_ids", "kem_property_ids", "sig_property_ids",
))
exercised_algorithms = string_values(all_records, ("algorithm",))
exercised_properties = string_values(all_records, ("property_id",))
supported_algorithms = string_values(metadata_records, (
    "enabled_algorithms", "enabled_kem_algorithms", "enabled_sig_algorithms",
))
supported_properties = string_values(metadata_records, ("property_ids", "kem_property_ids", "sig_property_ids"))
module_versions = string_values(all_records + metadata_records, ("module_version",))
relations = string_values(records, ("semantic_relation", "relation"))
replays = [value.get("replay") for value in records if isinstance(value.get("replay"), dict)]
replay_required = sum(bool(value.get("required")) for value in replays)
replay_reproduced = sum(value.get("result") == "reproduced" for value in replays)

raw_status = integer(os.environ["CLFUZZ_STATUS"])
effective_status = integer(os.environ["CLFUZZ_EFFECTIVE_STATUS"])
try:
    log_text = Path(os.environ["CLFUZZ_LOG_FILE"]).read_text(encoding="utf-8", errors="replace")
except OSError:
    log_text = ""
try:
    build_metadata = json.loads(Path(os.environ["CLFUZZ_BUILD_METADATA"]).read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    build_metadata = {}
sanitizer_signal = any(marker in log_text for marker in (
    "AddressSanitizer", "UndefinedBehaviorSanitizer", "MemorySanitizer", "LeakSanitizer",
    "ERROR: libFuzzer: deadly signal", "runtime error:",
))
if os.environ["CLFUZZ_BINARY_MISSING"] == "1" or raw_status == 127:
    outcome, stop_reason = "infrastructure-failed", "missing-binary"
elif effective_status != 0:
    if sanitizer_crashes or effective_status >= 128:
        outcome, stop_reason = "target-crash", "sanitizer-or-signal"
    elif hangs or effective_status == 70:
        outcome, stop_reason = "timed-out", "target-timeout"
    elif sanitizer_signal:
        outcome, stop_reason = "sanitizer-report", "recoverable-sanitizer-report"
    else:
        outcome, stop_reason = "harness-error", "nonzero-fuzzer-exit"
else:
    outcome = "completed-with-findings" if semantic_findings else "completed"
    if os.environ["CLFUZZ_MODE"] == "replay":
        stop_reason = "replay-completed"
    elif any(arg.startswith("-runs=") for arg in sys.argv[1:]):
        stop_reason = "runs-limit"
    elif any(arg.startswith("-max_total_time=") for arg in sys.argv[1:]):
        stop_reason = "max-total-time"
    else:
        stop_reason = "fuzzer-completed"

normalized = {
    "completed": "ok",
    "completed-with-findings": "invariant_violation",
    "timed-out": "process_hang",
    "target-crash": "process_crash",
    "sanitizer-report": "sanitizer_report",
    "harness-error": "operation_error",
    "infrastructure-failed": "operation_error",
}[outcome]
user_seconds, system_seconds, cpu_seconds = timing(Path(os.environ["CLFUZZ_TIME_FILE"]))
try:
    wall_seconds = max(0.0, (int(os.environ["CLFUZZ_END_NS"]) - int(os.environ["CLFUZZ_START_NS"])) / 1e9)
except ValueError:
    wall_seconds = None

summary = {
    "baseline": "CLFuzz",
    "target": "liboqs",
    "version": os.environ["CLFUZZ_VERSION"],
    "liboqs_version": os.environ["CLFUZZ_VERSION"],
    "mode": os.environ["CLFUZZ_MODE"],
    "profile": os.environ["CLFUZZ_PROFILE"],
    "status": outcome,
    "outcome": outcome,
    "normalized_outcome": normalized,
    "exit_status": raw_status,
    "effective_exit_status": effective_status,
    "stop_reason": stop_reason,
    "started_at": os.environ["CLFUZZ_START_TS"],
    "ended_at": os.environ["CLFUZZ_END_TS"],
    "wall_time_seconds": wall_seconds,
    "cpu_time_seconds": cpu_seconds,
    "cpu_user_seconds": user_seconds,
    "cpu_system_seconds": system_seconds,
    "worker_count": integer(os.environ["CLFUZZ_WORKERS"]),
    "jobs": integer(os.environ["CLFUZZ_JOBS"]),
    "cpu_allocation": os.environ["CLFUZZ_CPU_ALLOCATION"],
    "host_cpu_count": integer(os.environ["CLFUZZ_HOST_CPU_COUNT"]),
    "max_exemplars_per_group": integer(os.environ["CLFUZZ_MAX_EXEMPLARS_PER_GROUP"]),
    "operations": [value for value in os.environ["CLFUZZ_OPERATIONS"].split(",") if value],
    "module_version": module_versions[0] if len(module_versions) == 1 else "pqcdf-clfuzz-liboqs-oracle-v2",
    "module_versions": module_versions,
    "sanitizer_profile": build_metadata.get("profile") if isinstance(build_metadata, dict) else None,
    "algorithm_list": algorithms,
    "property_list": properties,
    "exercised_algorithm_list": exercised_algorithms,
    "exercised_property_list": exercised_properties,
    "supported_algorithm_list": supported_algorithms,
    "supported_property_list": supported_properties,
    "campaign_root": str(root),
    "working_directory": str(log_dir),
    "resolved_working_directory": str(log_dir),
    "resolved_paths": {
        "campaign_root": str(root), "working_directory": str(log_dir), "log_dir": str(log_dir),
        "log_file": os.environ["CLFUZZ_LOG_FILE"], "corpus_dir": os.environ["CLFUZZ_CORPUS_DIR"],
        "crash_dir": os.environ["CLFUZZ_CRASH_DIR"], "artifact_dir": os.environ["CLFUZZ_ARTIFACT_DIR"],
        "findings_dir": os.environ["CLFUZZ_FINDINGS_DIR"], "diagnostics_dir": os.environ["CLFUZZ_DIAGNOSTICS_DIR"],
    "metadata_dir": os.environ["CLFUZZ_METADATA_DIR"], "outcomes_dir": os.environ["CLFUZZ_OUTCOMES_DIR"],
        "timing_file": os.environ["CLFUZZ_TIME_FILE"],
        "summary_file": str(summary_path),
    },
    "binary": os.environ["CLFUZZ_BINARY"],
    "log": os.environ["CLFUZZ_LOG_FILE"],
    "log_dir": str(log_dir),
    "worker_logs": worker_logs,
    "worker_log_paths": [str(root / value) for value in worker_logs],
    "log_paths": [os.environ["CLFUZZ_LOG_FILE"]] + [str(root / value) for value in worker_logs],
    "stdout_log": os.environ["CLFUZZ_LOG_FILE"],
    "stderr_log": os.environ["CLFUZZ_LOG_FILE"],
    "corpus_dir": os.environ["CLFUZZ_CORPUS_DIR"], "crash_dir": os.environ["CLFUZZ_CRASH_DIR"],
    "artifact_dir": os.environ["CLFUZZ_ARTIFACT_DIR"], "findings_dir": os.environ["CLFUZZ_FINDINGS_DIR"],
    "diagnostics_dir": os.environ["CLFUZZ_DIAGNOSTICS_DIR"], "metadata_dir": os.environ["CLFUZZ_METADATA_DIR"],
    "outcomes_dir": os.environ["CLFUZZ_OUTCOMES_DIR"],
    "metadata_files": metadata_files,
    "structured_outcome_count": len(structured_outcomes), "structured_outcomes": structured_outcomes,
    "property_pass_count": sum(record.get("classification") == "property_passed" for record in outcome_records),
    "skipped_outcome_count": sum(record.get("classification") == "skipped" for record in outcome_records),
    "semantic_finding_count": len(semantic_findings), "structured_finding_count": len(semantic_findings),
    "semantic_findings": semantic_findings, "structured_findings": semantic_findings, "findings": semantic_findings,
    "semantic_relations": relations, "replay_required_count": replay_required,
    "replay_reproduced_count": replay_reproduced,
    "operation_diagnostic_count": len(operation_diagnostics), "operation_diagnostics": operation_diagnostics,
    "diagnostics": operation_diagnostics,
    "sanitizer_crash_count": len(sanitizer_crashes), "sanitizer_crashes": sanitizer_crashes,
    "recoverable_sanitizer_report_count": log_text.count("runtime error:"),
    "sanitizer_artifact_count": len(sanitizer_crashes) + len(hangs),
    "sanitizer_artifacts": sanitizer_crashes + hangs, "crashes": sanitizer_crashes + hangs,
    "hang_count": len(hangs), "hangs": hangs, "args": sys.argv[1:],
}
if os.environ["CLFUZZ_MODE"] == "replay":
    summary["replay"] = {
        "input_sha256": os.environ["CLFUZZ_REPLAY_INPUT_SHA256"],
        "input_path": os.environ["CLFUZZ_REPLAY_INPUT_COPY"],
        "algorithm": os.environ["CLFUZZ_REPLAY_ALGORITHM"],
        "property_id": os.environ["CLFUZZ_REPLAY_PROPERTY"],
        "mutation_semantics": os.environ["CLFUZZ_REPLAY_MUTATION_SEMANTICS"],
        "attempts": integer(os.environ["CLFUZZ_REPLAY_ATTEMPTS"]),
    }
atomic_write(summary_path, summary)
PY

echo "[CLFuzz] summary: $SUMMARY_FILE"
if [ "$EFFECTIVE_STATUS" -ne 0 ]; then
  echo "[CLFuzz] run failed with status $EFFECTIVE_STATUS" >&2
  echo "[CLFuzz] see log: $LOG_FILE" >&2
  exit "$EFFECTIVE_STATUS"
fi
echo "[CLFuzz] run completed"

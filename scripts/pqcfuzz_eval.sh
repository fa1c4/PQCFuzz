#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/pqcfuzz_eval.sh [options]

Options:
  --fuzzing-time DURATION       Wall-clock budget for each campaign. Default: 24h.
                                Accepts seconds or s/m/h/d suffixes, e.g. 86400, 60m, 24h.
  --progress-interval SECONDS   Seconds between progress reports. Default: 3600.
  --session-prefix NAME         Prefix for tmux session names. Default: pqcfuzz.
  --output-root PATH            Relative output root. Default: workspace/pqcfuzz_eval.
  --versions CSV                Comma-separated liboqs versions. Default: 0.14.0,0.8.0,0.4.0.
  --oracle-suite fips|metamorphic
                                Oracle suite. Default: metamorphic.
  --oracle-set all|security     Metamorphic oracle subset. Default: all.
  --relation-mode single-target|self-reference|cross-implementation
                                Relation mode. Default: single-target.
  --target-runtime liboqs       Target runtime. Default: liboqs.
  --sanitizers CSV              Sanitizers: address, undefined, memory, or none.
                                Comma-separated; memory cannot be combined with address.
                                Default: address,undefined.
  --leak-check auto|on|off      Run a one-input LeakSanitizer pass after each target.
                                Default: auto (on when address is enabled).
  --input-timeout-seconds N     Per-input timeout. Default: 30.
  --rss-mb N                    RSS limit. Default: 2048.
  --report-formats CSV          Report formats. Default: json,tsv.
  --report-timeout DURATION     Maximum time for finding report generation. Default: 10m.
  --finding-save-mode grouped|all
                                Finding artifact retention. Default: grouped.
  --max-finding-exemplars-per-group N
                                Replayable exemplars kept per finding group. Default: 1.
  --preflight-only              Build each campaign and validate every comparable target's
                                seeded oracle corpus without starting a fuzzing campaign.
  --fuzz-effectiveness-min-evaluable-rate R
                                Minimum per-oracle fuzz-time evaluability rate. Default: 0.95.
  --base-image IMAGE            Docker base image. Default: ubuntu:22.04.
  --dry-run                     Print campaigns and commands without starting tmux.
  -h, --help                    Show this help.

This launches one tmux campaign per liboqs version. The default workflow is the
PQ crypto semantic sanitizer: metamorphic single-target oracles plus ASan/UBSan.

Outputs are written under:
  workspace/pqcfuzz_eval/
EOF
}

die() {
  echo "error: $*" >&2
  exit 2
}

parse_duration_seconds() {
  local raw="$1"
  local value multiplier

  raw="${raw,,}"

  if [[ "$raw" =~ ^([0-9]+)[[:space:]]*$ ]]; then
    value="${BASH_REMATCH[1]}"
    multiplier=1
  elif [[ "$raw" =~ ^([0-9]+)[[:space:]]*(s|sec|secs|second|seconds)[[:space:]]*$ ]]; then
    value="${BASH_REMATCH[1]}"
    multiplier=1
  elif [[ "$raw" =~ ^([0-9]+)[[:space:]]*(m|min|mins|minute|minutes)[[:space:]]*$ ]]; then
    value="${BASH_REMATCH[1]}"
    multiplier=60
  elif [[ "$raw" =~ ^([0-9]+)[[:space:]]*(h|hr|hrs|hour|hours)[[:space:]]*$ ]]; then
    value="${BASH_REMATCH[1]}"
    multiplier=3600
  elif [[ "$raw" =~ ^([0-9]+)[[:space:]]*(d|day|days)[[:space:]]*$ ]]; then
    value="${BASH_REMATCH[1]}"
    multiplier=86400
  else
    die "invalid duration '$1'"
  fi

  if [ "$value" -le 0 ]; then
    die "duration must be positive"
  fi

  echo $((value * multiplier))
}

validate_session_prefix() {
  local prefix="$1"
  if [[ ! "$prefix" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
    die "--session-prefix must match [A-Za-z0-9][A-Za-z0-9_.-]*"
  fi
}

validate_output_root() {
  local path="$1"
  if [ -z "$path" ] || [[ "$path" = /* ]] || [[ "$path" == *".."* ]]; then
    die "--output-root must be a nonempty relative path without '..'"
  fi
}

format_elapsed() {
  local seconds="$1"
  local hours minutes
  hours=$((seconds / 3600))
  minutes=$(((seconds % 3600) / 60))
  seconds=$((seconds % 60))
  printf "%02d:%02d:%02d" "$hours" "$minutes" "$seconds"
}

safe_version() {
  local version="$1"
  version="${version//./_}"
  version="${version//-/_}"
  echo "$version"
}

parse_versions() {
  local raw="$1"
  local item version
  local -a parsed=()

  IFS=',' read -r -a items <<<"$raw"
  for item in "${items[@]}"; do
    version="$(printf '%s' "$item" | tr -d '[:space:]')"
    if [ -z "$version" ]; then
      continue
    fi
    case "$version" in
      0.14.0|0.8.0|0.4.0) ;;
      *)
        die "unsupported liboqs version '$version' (supported: 0.14.0, 0.8.0, 0.4.0)"
        ;;
    esac
    parsed+=("$version")
  done

  if [ "${#parsed[@]}" -eq 0 ]; then
    die "--versions must contain at least one supported version"
  fi

  printf '%s\n' "${parsed[@]}"
}

normalize_sanitizers() {
  local raw="$1" item normalized="" seen_address=0 seen_undefined=0 seen_memory=0 seen_none=0
  local -a items=()
  IFS=',' read -r -a items <<<"$raw"
  if [ "${#items[@]}" -eq 0 ]; then
    return 1
  fi
  for item in "${items[@]}"; do
    item="$(printf '%s' "$item" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    case "$item" in
      address)
        if [ "$seen_address" -eq 0 ]; then normalized+="${normalized:+,}address"; seen_address=1; fi
        ;;
      undefined)
        if [ "$seen_undefined" -eq 0 ]; then normalized+="${normalized:+,}undefined"; seen_undefined=1; fi
        ;;
      memory)
        if [ "$seen_memory" -eq 0 ]; then normalized+="${normalized:+,}memory"; seen_memory=1; fi
        ;;
      none)
        seen_none=1
        ;;
      *) return 1 ;;
    esac
  done
  if [ "$seen_none" -eq 1 ]; then
    if [ -n "$normalized" ]; then return 1; fi
    printf 'none\n'
    return
  fi
  if [ -z "$normalized" ] || { [ "$seen_memory" -eq 1 ] && [ "$seen_address" -eq 1 ]; }; then
    return 1
  fi
  printf '%s\n' "$normalized"
}

sanitizer_enabled() {
  local sanitizer="$1"
  [ "$SANITIZERS" != "none" ] && [[ ",$SANITIZERS," == *",${sanitizer},"* ]]
}

write_dockerfile() {
  mkdir -p "$DOCKER_DIR"
  cat > "$DOCKERFILE" <<EOF
ARG BASE_IMAGE=${BASE_IMAGE}
FROM \${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \\
    build-essential \\
    clang \\
    llvm \\
    cmake \\
    ninja-build \\
    git \\
    python3 \\
    ca-certificates \\
    pkg-config \\
    libssl-dev \\
    coreutils \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/PQC-DF
EOF
}

print_campaign_commands() {
  local version="$1"
  local seconds="$2"
  local workspace="$3"

  echo "docker build --build-arg BASE_IMAGE=$BASE_IMAGE -t pqcfuzz-eval -f $DOCKERFILE_REL $DOCKER_DIR_REL"
  echo "docker run pqcfuzz-eval: clone/update liboqs $version into $workspace/build/liboqs-${version}/liboqs-src"
  echo "docker run pqcfuzz-eval: build static liboqs.a for $version"
  echo "docker run pqcfuzz-eval: generate self-reference compatibility adapter"
  echo "docker run pqcfuzz-eval: oracle_suite: ${ORACLE_SUITE}"
  echo "docker run pqcfuzz-eval: oracle_set: ${ORACLE_SET}"
  echo "docker run pqcfuzz-eval: relation_mode: ${RELATION_MODE}"
  echo "docker run pqcfuzz-eval: target_runtime: ${TARGET_RUNTIME}"
  echo "docker run pqcfuzz-eval: sanitizers: ${SANITIZERS}"
  echo "docker run pqcfuzz-eval: leak_check: ${LEAK_CHECK}"
  echo "docker run pqcfuzz-eval: finding_save_mode: ${FINDING_SAVE_MODE}"
  echo "docker run pqcfuzz-eval: max_finding_exemplars_per_group: ${MAX_FINDING_EXEMPLARS_PER_GROUP}"
  echo "docker run pqcfuzz-eval: fuzz_effectiveness_min_evaluable_rate: ${FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE}"
  echo "docker run pqcfuzz-eval: build one fixed binary per ML-KEM/ML-DSA algorithm"
  echo "docker run pqcfuzz-eval: seed every enabled oracle with a valid structured input"
  echo "docker run pqcfuzz-eval: distribute the ${seconds}s campaign budget across active targets"
  if [ "$version" = "0.14.0" ]; then
    echo "docker run pqcfuzz-eval: schedule 6 active canonical targets"
  elif [ "$version" = "0.4.0" ]; then
    echo "docker run pqcfuzz-eval: schedule 2 canonical ML-KEM targets; record Kyber512 and historical ML-DSA as not applicable"
  else
    echo "docker run pqcfuzz-eval: schedule 3 canonical ML-KEM targets; record historical ML-DSA as not applicable"
  fi
  if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
    echo "docker run pqcfuzz-eval: preflight-only; execute each comparable target's complete seeded oracle corpus"
  fi
  echo "campaign fuzzing budget: ${seconds}s"
}

archive_existing_eval_root() {
  if [ ! -e "$EVAL_ROOT" ]; then
    return
  fi

  if [ -d "$EVAL_ROOT" ] && [ -z "$(find "$EVAL_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    return
  fi

  local archive_date archive_root archive_rel suffix
  archive_date="$(date +%Y%m%d)"
  archive_rel="workspace/pqcfuzz_eval_${archive_date}"
  archive_root="${ROOT_DIR}/${archive_rel}"
  suffix=1

  while [ -e "$archive_root" ]; do
    archive_rel="workspace/pqcfuzz_eval_${archive_date}_${suffix}"
    archive_root="${ROOT_DIR}/${archive_rel}"
    suffix=$((suffix + 1))
  done

  mkdir -p "$(dirname "$archive_root")"
  mv "$EVAL_ROOT" "$archive_root"
  echo "[pqcfuzz-eval] archived previous results: $EVAL_ROOT -> $archive_root"
}

write_launcher() {
  local launcher_file="$1"
  local version="$2"
  local campaign="$3"
  local session_name="$4"
  local workspace_root_rel="$5"
  local workspace_root_abs="$6"
  local log_file_rel="$7"
  local log_file_abs="$8"
  local status_file_rel="$9"
  local status_file_abs="${10}"
  local seconds="${11}"

  {
    printf '#!/usr/bin/env bash\n'
    printf 'set +e +u +o pipefail\n\n'
    printf 'HOST_ROOT_DIR=%q\n' "$ROOT_DIR"
    printf 'CONTAINER_ROOT_DIR=%q\n' "/workspace/PQC-DF"
    printf 'if [ "${PQCFUZZ_EVAL_IN_DOCKER:-0}" = "1" ]; then ROOT_DIR="$CONTAINER_ROOT_DIR"; else ROOT_DIR="$HOST_ROOT_DIR"; fi\n'
    printf 'cd "$ROOT_DIR" || exit 1\n\n'
    printf 'IMAGE_NAME=%q\n' "pqcfuzz-eval"
    printf 'BASE_IMAGE=%q\n' "$BASE_IMAGE"
    printf 'DOCKER_DIR_REL=%q\n' "$DOCKER_DIR_REL"
    printf 'DOCKERFILE_REL=%q\n' "$DOCKERFILE_REL"
    printf 'EVAL_ROOT_REL=%q\n' "$EVAL_ROOT_REL"
    printf 'LAUNCHER_FILE_REL=%q\n' "${launcher_file#$ROOT_DIR/}"
    printf 'VERSION=%q\n' "$version"
    printf 'CAMPAIGN=%q\n' "$campaign"
    printf 'SESSION_NAME=%q\n' "$session_name"
    printf 'WORKSPACE_ROOT_REL=%q\n' "$workspace_root_rel"
    printf 'WORKSPACE_ROOT_ABS_HOST=%q\n' "$workspace_root_abs"
    printf 'LOG_FILE_REL=%q\n' "$log_file_rel"
    printf 'LOG_FILE_ABS_HOST=%q\n' "$log_file_abs"
    printf 'STATUS_FILE_REL=%q\n' "$status_file_rel"
    printf 'STATUS_FILE_ABS_HOST=%q\n' "$status_file_abs"
    printf 'FUZZING_SECONDS=%q\n\n' "$seconds"
    printf 'ORACLE_SUITE=%q\n' "$ORACLE_SUITE"
    printf 'ORACLE_SET=%q\n' "$ORACLE_SET"
    printf 'RELATION_MODE=%q\n' "$RELATION_MODE"
    printf 'TARGET_RUNTIME=%q\n' "$TARGET_RUNTIME"
    printf 'SANITIZERS=%q\n' "$SANITIZERS"
    printf 'LEAK_CHECK=%q\n' "$LEAK_CHECK"
    printf 'INPUT_TIMEOUT_SECONDS=%q\n' "$INPUT_TIMEOUT_SECONDS"
    printf 'RSS_MB=%q\n' "$RSS_MB"
    printf 'FINDING_SAVE_MODE=%q\n' "$FINDING_SAVE_MODE"
    printf 'MAX_FINDING_EXEMPLARS_PER_GROUP=%q\n' "$MAX_FINDING_EXEMPLARS_PER_GROUP"
    printf 'FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE=%q\n\n' "$FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE"
    printf 'PREFLIGHT_ONLY=%q\n\n' "$PREFLIGHT_ONLY"
    cat <<'EOF'
if [ "${PQCFUZZ_EVAL_IN_DOCKER:-0}" = "1" ]; then
  WORKSPACE_ROOT_ABS="${ROOT_DIR}/${WORKSPACE_ROOT_REL}"
else
  WORKSPACE_ROOT_ABS="$WORKSPACE_ROOT_ABS_HOST"
fi

mkdir -p "$(dirname "$LOG_FILE_REL")" "$(dirname "$STATUS_FILE_REL")" "$WORKSPACE_ROOT_REL"
if [ "${PQCFUZZ_EVAL_IN_DOCKER:-0}" = "1" ]; then
  exec >> "$LOG_FILE_REL" 2>&1
else
  : > "$LOG_FILE_REL"
  exec > >(tee -a "$LOG_FILE_REL") 2>&1
fi

if [ -n "${EVAL_START_EPOCH:-}" ]; then
  START_EPOCH="$EVAL_START_EPOCH"
else
  START_EPOCH="$(date +%s)"
fi
if [ -n "${EVAL_STARTED_AT:-}" ]; then
  STARTED_AT="$EVAL_STARTED_AT"
else
  STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

DOCKER_BUILD_STATUS="${DOCKER_BUILD_STATUS:-}"
DOCKER_RUN_STATUS="${DOCKER_RUN_STATUS:-}"
LIBOQS_BUILD_STATUS="${LIBOQS_BUILD_STATUS:-}"
PQCFUZZ_BUILD_STATUS="${PQCFUZZ_BUILD_STATUS:-}"
FUZZ_STATUS="${FUZZ_STATUS:-}"
KEM_STATUS="${KEM_STATUS:-}"
SIG_STATUS="${SIG_STATUS:-}"
FINAL_STATUS="${FINAL_STATUS:-}"
RESULT="${RESULT:-}"
ENDED_AT="${ENDED_AT:-}"
FAILURE_REASON="${FAILURE_REASON:-}"
ORACLE_SUITE="${ORACLE_SUITE:-metamorphic}"
ORACLE_SET="${ORACLE_SET:-all}"
RELATION_MODE="${RELATION_MODE:-single-target}"
TARGET_RUNTIME="${TARGET_RUNTIME:-liboqs}"
SANITIZERS="${SANITIZERS:-address,undefined}"
LEAK_CHECK="${LEAK_CHECK:-auto}"
INPUT_TIMEOUT_SECONDS="${INPUT_TIMEOUT_SECONDS:-30}"
RSS_MB="${RSS_MB:-2048}"
FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE="${FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE:-0.95}"
PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"
SKIPPED_FAMILIES_JSON='["SLH-DSA"]'

has_sanitizer() {
  local sanitizer="$1"
  [ "$SANITIZERS" != "none" ] && [[ ",$SANITIZERS," == *",${sanitizer},"* ]]
}

configure_sanitizer_flags() {
  if [ "$SANITIZERS" = "none" ]; then
    LIBOQS_SANITIZER_FLAGS=""
    FUZZER_SANITIZER_FLAGS="-fsanitize=fuzzer"
  else
    LIBOQS_SANITIZER_FLAGS="-fsanitize=fuzzer-no-link,${SANITIZERS}"
    FUZZER_SANITIZER_FLAGS="-fsanitize=fuzzer,${SANITIZERS}"
  fi
}

resolve_llvm_symbolizer() {
  LLVM_SYMBOLIZER_PATH="$(command -v llvm-symbolizer 2>/dev/null || true)"
  if [ -z "$LLVM_SYMBOLIZER_PATH" ]; then
    local candidate
    for candidate in /usr/bin/llvm-symbolizer-*; do
      if [ -x "$candidate" ]; then
        LLVM_SYMBOLIZER_PATH="$candidate"
        break
      fi
    done
  fi
  if [ -z "$LLVM_SYMBOLIZER_PATH" ] && [ "$SANITIZERS" != "none" ]; then
    echo "llvm-symbolizer is required for symbolized sanitizer diagnostics" >&2
    return 1
  fi
  return 0
}

configure_sanitizer_flags

write_status() {
  local phase="$1"
  local state="$2"

  EVAL_STATUS_FILE="$STATUS_FILE_REL" \
  EVAL_CAMPAIGN="$CAMPAIGN" \
  EVAL_VERSION="$VERSION" \
  EVAL_SESSION_NAME="$SESSION_NAME" \
  EVAL_WORKSPACE_ROOT="$WORKSPACE_ROOT_REL" \
  EVAL_WORKSPACE_ROOT_ABS="$WORKSPACE_ROOT_ABS_HOST" \
  EVAL_LOG_FILE="$LOG_FILE_ABS_HOST" \
  EVAL_PHASE="$phase" \
  EVAL_STATE="$state" \
  EVAL_STARTED_AT="$STARTED_AT" \
  EVAL_START_EPOCH="$START_EPOCH" \
  EVAL_ENDED_AT="$ENDED_AT" \
  EVAL_DOCKER_BUILD_STATUS="$DOCKER_BUILD_STATUS" \
  EVAL_DOCKER_RUN_STATUS="$DOCKER_RUN_STATUS" \
  EVAL_LIBOQS_BUILD_STATUS="$LIBOQS_BUILD_STATUS" \
  EVAL_PQCFUZZ_BUILD_STATUS="$PQCFUZZ_BUILD_STATUS" \
  EVAL_FUZZ_STATUS="$FUZZ_STATUS" \
  EVAL_KEM_STATUS="$KEM_STATUS" \
  EVAL_SIG_STATUS="$SIG_STATUS" \
  EVAL_FINAL_STATUS="$FINAL_STATUS" \
  EVAL_RESULT="$RESULT" \
  EVAL_FAILURE_REASON="$FAILURE_REASON" \
  EVAL_ORACLE_SUITE="$ORACLE_SUITE" \
  EVAL_ORACLE_SET="$ORACLE_SET" \
  EVAL_RELATION_MODE="$RELATION_MODE" \
  EVAL_TARGET_RUNTIME="$TARGET_RUNTIME" \
  EVAL_SANITIZERS="$SANITIZERS" \
  EVAL_LEAK_CHECK="$LEAK_CHECK" \
  EVAL_PREFLIGHT_ONLY="$PREFLIGHT_ONLY" \
  EVAL_FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE="$FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE" \
  EVAL_SKIPPED_FAMILIES_JSON="$SKIPPED_FAMILIES_JSON" \
  python3 - <<'PY'
import json
import os
import tempfile
import time
from datetime import datetime, timezone

def int_or_none(value):
    if value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return value

path = os.environ["EVAL_STATUS_FILE"]
os.makedirs(os.path.dirname(path), exist_ok=True)
start_epoch = int(os.environ["EVAL_START_EPOCH"])
now = int(time.time())

doc = {}
if os.path.exists(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except json.JSONDecodeError:
        doc = {}

doc.update({
    "campaign": os.environ["EVAL_CAMPAIGN"],
    "version": os.environ["EVAL_VERSION"],
    "session_name": os.environ["EVAL_SESSION_NAME"],
    "workspace_root": os.environ["EVAL_WORKSPACE_ROOT"],
    "workspace_root_abs": os.environ["EVAL_WORKSPACE_ROOT_ABS"],
    "log": os.environ["EVAL_LOG_FILE"],
    "phase": os.environ["EVAL_PHASE"],
    "state": os.environ["EVAL_STATE"],
    "started_at": os.environ["EVAL_STARTED_AT"],
    "start_epoch": start_epoch,
    "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "elapsed_seconds": now - start_epoch,
    "docker_build_status": int_or_none(os.environ["EVAL_DOCKER_BUILD_STATUS"]),
    "docker_run_status": int_or_none(os.environ["EVAL_DOCKER_RUN_STATUS"]),
    "liboqs_build_status": int_or_none(os.environ["EVAL_LIBOQS_BUILD_STATUS"]),
    "pqcfuzz_build_status": int_or_none(os.environ["EVAL_PQCFUZZ_BUILD_STATUS"]),
    "fuzz_status": int_or_none(os.environ["EVAL_FUZZ_STATUS"]),
    "kem_status": int_or_none(os.environ["EVAL_KEM_STATUS"]),
    "sig_status": int_or_none(os.environ["EVAL_SIG_STATUS"]),
    "final_status": int_or_none(os.environ["EVAL_FINAL_STATUS"]),
    "result": os.environ["EVAL_RESULT"] or None,
    "failure_reason": os.environ["EVAL_FAILURE_REASON"] or None,
    "oracle_suite": os.environ["EVAL_ORACLE_SUITE"],
    "oracle_set": os.environ["EVAL_ORACLE_SET"],
    "relation_mode": os.environ["EVAL_RELATION_MODE"],
    "target_runtime": os.environ["EVAL_TARGET_RUNTIME"],
    "sanitizers": os.environ["EVAL_SANITIZERS"],
    "leak_check": os.environ["EVAL_LEAK_CHECK"],
    "preflight_only": os.environ["EVAL_PREFLIGHT_ONLY"] == "1",
    "fuzz_effectiveness_min_evaluable_rate": float(os.environ["EVAL_FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE"]),
    "skipped_families": json.loads(os.environ["EVAL_SKIPPED_FAMILIES_JSON"]),
})
if os.environ["EVAL_ENDED_AT"]:
    doc["ended_at"] = os.environ["EVAL_ENDED_AT"]

fd, tmp = tempfile.mkstemp(prefix=".status.", dir=os.path.dirname(path))
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
os.replace(tmp, path)
PY
  if [ "${PQCFUZZ_EVAL_IN_DOCKER:-0}" = "1" ] && [ -n "${HOST_UID:-}" ] && [ -n "${HOST_GID:-}" ]; then
    chown "${HOST_UID}:${HOST_GID}" "$STATUS_FILE_REL" 2>/dev/null || true
  fi
}

finish_campaign() {
  RESULT="$1"
  FINAL_STATUS="$2"
  if [ "$#" -ge 3 ]; then
    FAILURE_REASON="$3"
  fi
  ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  write_status "finished" "finished"
  echo
  echo "[pqcfuzz-eval] ended: $ENDED_AT"
  echo "[pqcfuzz-eval] elapsed: $(( $(date +%s) - START_EPOCH ))s"
  echo "[pqcfuzz-eval] result: $RESULT"
  if [ -n "$FAILURE_REASON" ]; then
    echo "[pqcfuzz-eval] failure reason: $FAILURE_REASON"
  fi
  echo "[pqcfuzz-eval] final status: $FINAL_STATUS"
  exit "$FINAL_STATUS"
}

run_step() {
  echo "[pqcfuzz-eval] command: $*"
  "$@"
  return $?
}

status_file_finished() {
  python3 - "$STATUS_FILE_REL" <<'PY'
import json
import sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        doc = json.load(f)
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if doc.get("state") == "finished" else 1)
PY
}

write_compat_adapter() {
  local adapter_src="$1"
  mkdir -p "$(dirname "$adapter_src")"
  cat > "$adapter_src" <<'CPP'
#include "adapters/liboqs/kem_adapter.h"
#include "adapters/liboqs/sig_adapter.h"
#include "adapters/pqclean/kem_adapter.h"
#include "adapters/pqclean/sig_adapter.h"

#include <oqs/kem.h>
#include <oqs/oqs.h>
#include <oqs/sig.h>

#include <cstring>

namespace {

struct KemSpec {
  const char *preferred;
  const char *fallback;
  size_t pk_len;
  size_t sk_len;
  size_t ct_len;
  size_t ss_len;
};

struct SigSpec {
  const char *preferred;
  const char *fallback;
  size_t pk_len;
  size_t sk_len;
  size_t sig_len;
};

#if defined(OQS_ENABLE_SIG_ML_DSA)
constexpr int kMlDsaSupportsContext = 1;
#else
constexpr int kMlDsaSupportsContext = 0;
#endif

void EnsureOqsInit() {
  static bool initialized = false;
  if (!initialized) {
    OQS_init();
    initialized = true;
  }
}

pqcfuzz_status ToStatus(OQS_STATUS status) {
  return status == OQS_SUCCESS ? PQCFUZZ_OK : PQCFUZZ_REJECT;
}

OQS_KEM *OpenKem(const KemSpec &spec) {
  EnsureOqsInit();
  const char *candidates[] = {spec.preferred, spec.fallback};
  for (const char *candidate : candidates) {
    if (candidate == nullptr || candidate[0] == '\0') {
      continue;
    }
    OQS_KEM *kem = OQS_KEM_new(candidate);
    if (kem == nullptr) {
      continue;
    }
    if (kem->length_public_key == spec.pk_len && kem->length_secret_key == spec.sk_len &&
        kem->length_ciphertext == spec.ct_len && kem->length_shared_secret == spec.ss_len) {
      return kem;
    }
    OQS_KEM_free(kem);
  }
  return nullptr;
}

OQS_SIG *OpenSig(const SigSpec &spec) {
  EnsureOqsInit();
  const char *candidates[] = {spec.preferred, spec.fallback};
  for (const char *candidate : candidates) {
    if (candidate == nullptr || candidate[0] == '\0') {
      continue;
    }
    OQS_SIG *sig = OQS_SIG_new(candidate);
    if (sig == nullptr) {
      continue;
    }
    if (sig->length_public_key == spec.pk_len && sig->length_secret_key == spec.sk_len &&
        sig->length_signature == spec.sig_len) {
      return sig;
    }
    OQS_SIG_free(sig);
  }
  return nullptr;
}

pqcfuzz_status KemKeygen(const KemSpec &spec, uint8_t *pk, uint8_t *sk) {
  OQS_KEM *kem = OpenKem(spec);
  if (kem == nullptr) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  OQS_STATUS status = OQS_KEM_keypair(kem, pk, sk);
  OQS_KEM_free(kem);
  return ToStatus(status);
}

pqcfuzz_status KemEncaps(const KemSpec &spec, uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
  OQS_KEM *kem = OpenKem(spec);
  if (kem == nullptr) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  OQS_STATUS status = OQS_KEM_encaps(kem, ct, ss, pk);
  OQS_KEM_free(kem);
  return ToStatus(status);
}

pqcfuzz_status KemDecaps(const KemSpec &spec, uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  OQS_KEM *kem = OpenKem(spec);
  if (kem == nullptr) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  OQS_STATUS status = OQS_KEM_decaps(kem, ss, ct, sk);
  OQS_KEM_free(kem);
  return ToStatus(status);
}

pqcfuzz_status SigKeygen(const SigSpec &spec, uint8_t *pk, uint8_t *sk) {
  OQS_SIG *sig = OpenSig(spec);
  if (sig == nullptr) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  OQS_STATUS status = OQS_SIG_keypair(sig, pk, sk);
  OQS_SIG_free(sig);
  return ToStatus(status);
}

pqcfuzz_status SigSign(
    const SigSpec &spec,
    uint8_t *signature,
    size_t *signature_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *secret_key,
    const uint8_t *context,
    size_t context_len) {
  OQS_SIG *sig = OpenSig(spec);
  if (sig == nullptr) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  OQS_STATUS status;
  if (context_len != 0) {
#if defined(OQS_ENABLE_SIG_ML_DSA)
    if (!sig->sig_with_ctx_support || sig->sign_with_ctx_str == nullptr) {
      OQS_SIG_free(sig);
      return PQCFUZZ_API_UNSUPPORTED;
    }
    status = OQS_SIG_sign_with_ctx_str(
        sig, signature, signature_len, message, message_len, context, context_len, secret_key);
#else
    OQS_SIG_free(sig);
    return PQCFUZZ_API_UNSUPPORTED;
#endif
  } else {
    status = OQS_SIG_sign(sig, signature, signature_len, message, message_len, secret_key);
  }
  OQS_SIG_free(sig);
  return ToStatus(status);
}

pqcfuzz_status SigVerify(
    const SigSpec &spec,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *public_key,
    const uint8_t *context,
    size_t context_len) {
  OQS_SIG *sig = OpenSig(spec);
  if (sig == nullptr) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  OQS_STATUS status;
  if (context_len != 0) {
#if defined(OQS_ENABLE_SIG_ML_DSA)
    if (!sig->sig_with_ctx_support || sig->verify_with_ctx_str == nullptr) {
      OQS_SIG_free(sig);
      return PQCFUZZ_API_UNSUPPORTED;
    }
    status = OQS_SIG_verify_with_ctx_str(
        sig, message, message_len, signature, signature_len, context, context_len, public_key);
#else
    OQS_SIG_free(sig);
    return PQCFUZZ_API_UNSUPPORTED;
#endif
  } else {
    status = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
  }
  OQS_SIG_free(sig);
  return ToStatus(status);
}

pqcfuzz_status UnsupportedKemKeygen(uint8_t *, uint8_t *) { return PQCFUZZ_API_UNSUPPORTED; }
pqcfuzz_status UnsupportedKemEncaps(uint8_t *, uint8_t *, const uint8_t *) { return PQCFUZZ_API_UNSUPPORTED; }
pqcfuzz_status UnsupportedKemDecaps(uint8_t *, const uint8_t *, const uint8_t *) { return PQCFUZZ_API_UNSUPPORTED; }
pqcfuzz_status UnsupportedSigKeygen(uint8_t *, uint8_t *) { return PQCFUZZ_API_UNSUPPORTED; }
pqcfuzz_status UnsupportedSign(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_API_UNSUPPORTED;
}
pqcfuzz_status UnsupportedVerify(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_API_UNSUPPORTED;
}
pqcfuzz_status UnsupportedSignSeeded(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t) {
  return PQCFUZZ_API_UNSUPPORTED;
}

const KemSpec kKem512Spec = {"ML-KEM-512", "Kyber512", 800, 1632, 768, 32};
const KemSpec kKem768Spec = {"ML-KEM-768", "Kyber768", 1184, 2400, 1088, 32};
const KemSpec kKem1024Spec = {"ML-KEM-1024", "Kyber1024", 1568, 3168, 1568, 32};

pqcfuzz_status Kem512Keygen(uint8_t *pk, uint8_t *sk) { return KemKeygen(kKem512Spec, pk, sk); }
pqcfuzz_status Kem512Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) { return KemEncaps(kKem512Spec, ct, ss, pk); }
pqcfuzz_status Kem512Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) { return KemDecaps(kKem512Spec, ss, ct, sk); }
pqcfuzz_status Kem768Keygen(uint8_t *pk, uint8_t *sk) { return KemKeygen(kKem768Spec, pk, sk); }
pqcfuzz_status Kem768Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) { return KemEncaps(kKem768Spec, ct, ss, pk); }
pqcfuzz_status Kem768Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) { return KemDecaps(kKem768Spec, ss, ct, sk); }
pqcfuzz_status Kem1024Keygen(uint8_t *pk, uint8_t *sk) { return KemKeygen(kKem1024Spec, pk, sk); }
pqcfuzz_status Kem1024Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) { return KemEncaps(kKem1024Spec, ct, ss, pk); }
pqcfuzz_status Kem1024Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) { return KemDecaps(kKem1024Spec, ss, ct, sk); }

const pqcfuzz_kem_adapter kLeftKem512 = {"liboqs", "liboqs_mlkem512_wrapper_generic", "ML-KEM-512", 800, 1632, 768, 32, Kem512Keygen, Kem512Encaps, Kem512Decaps};
const pqcfuzz_kem_adapter kLeftKem768 = {"liboqs", "liboqs_mlkem768_wrapper_generic", "ML-KEM-768", 1184, 2400, 1088, 32, Kem768Keygen, Kem768Encaps, Kem768Decaps};
const pqcfuzz_kem_adapter kLeftKem1024 = {"liboqs", "liboqs_mlkem1024_wrapper_generic", "ML-KEM-1024", 1568, 3168, 1568, 32, Kem1024Keygen, Kem1024Encaps, Kem1024Decaps};
const pqcfuzz_kem_adapter kRightKem512 = {"liboqs_self_reference", "selfref_mlkem512_via_liboqs", "ML-KEM-512", 800, 1632, 768, 32, Kem512Keygen, Kem512Encaps, Kem512Decaps};
const pqcfuzz_kem_adapter kRightKem768 = {"liboqs_self_reference", "selfref_mlkem768_via_liboqs", "ML-KEM-768", 1184, 2400, 1088, 32, Kem768Keygen, Kem768Encaps, Kem768Decaps};
const pqcfuzz_kem_adapter kRightKem1024 = {"liboqs_self_reference", "selfref_mlkem1024_via_liboqs", "ML-KEM-1024", 1568, 3168, 1568, 32, Kem1024Keygen, Kem1024Encaps, Kem1024Decaps};

const SigSpec kDsa44Spec = {"ML-DSA-44", "Dilithium2", 1312, 2560, 2420};
const SigSpec kDsa65Spec = {"ML-DSA-65", "Dilithium3", 1952, 4032, 3309};
const SigSpec kDsa87Spec = {"ML-DSA-87", "Dilithium5", 2592, 4896, 4627};

pqcfuzz_status Dsa44Keygen(uint8_t *pk, uint8_t *sk) { return SigKeygen(kDsa44Spec, pk, sk); }
pqcfuzz_status Dsa44Sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk, const uint8_t *ctx, size_t ctx_len) {
  return SigSign(kDsa44Spec, sig, sig_len, msg, msg_len, sk, ctx, ctx_len);
}
pqcfuzz_status Dsa44Verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk, const uint8_t *ctx, size_t ctx_len) {
  return SigVerify(kDsa44Spec, sig, sig_len, msg, msg_len, pk, ctx, ctx_len);
}
pqcfuzz_status Dsa65Keygen(uint8_t *pk, uint8_t *sk) { return SigKeygen(kDsa65Spec, pk, sk); }
pqcfuzz_status Dsa65Sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk, const uint8_t *ctx, size_t ctx_len) {
  return SigSign(kDsa65Spec, sig, sig_len, msg, msg_len, sk, ctx, ctx_len);
}
pqcfuzz_status Dsa65Verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk, const uint8_t *ctx, size_t ctx_len) {
  return SigVerify(kDsa65Spec, sig, sig_len, msg, msg_len, pk, ctx, ctx_len);
}
pqcfuzz_status Dsa87Keygen(uint8_t *pk, uint8_t *sk) { return SigKeygen(kDsa87Spec, pk, sk); }
pqcfuzz_status Dsa87Sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk, const uint8_t *ctx, size_t ctx_len) {
  return SigSign(kDsa87Spec, sig, sig_len, msg, msg_len, sk, ctx, ctx_len);
}
pqcfuzz_status Dsa87Verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk, const uint8_t *ctx, size_t ctx_len) {
  return SigVerify(kDsa87Spec, sig, sig_len, msg, msg_len, pk, ctx, ctx_len);
}

const pqcfuzz_sig_adapter kLeftDsa44 = {"liboqs", "liboqs_mldsa44_wrapper_generic", "ML-DSA-44", 1312, 2560, 2420, kMlDsaSupportsContext, 0, 0, Dsa44Keygen, Dsa44Sign, Dsa44Verify, UnsupportedSignSeeded};
const pqcfuzz_sig_adapter kLeftDsa65 = {"liboqs", "liboqs_mldsa65_wrapper_generic", "ML-DSA-65", 1952, 4032, 3309, kMlDsaSupportsContext, 0, 0, Dsa65Keygen, Dsa65Sign, Dsa65Verify, UnsupportedSignSeeded};
const pqcfuzz_sig_adapter kLeftDsa87 = {"liboqs", "liboqs_mldsa87_wrapper_generic", "ML-DSA-87", 2592, 4896, 4627, kMlDsaSupportsContext, 0, 0, Dsa87Keygen, Dsa87Sign, Dsa87Verify, UnsupportedSignSeeded};
const pqcfuzz_sig_adapter kRightDsa44 = {"liboqs_self_reference", "selfref_mldsa44_via_liboqs", "ML-DSA-44", 1312, 2560, 2420, kMlDsaSupportsContext, 0, 0, Dsa44Keygen, Dsa44Sign, Dsa44Verify, UnsupportedSignSeeded};
const pqcfuzz_sig_adapter kRightDsa65 = {"liboqs_self_reference", "selfref_mldsa65_via_liboqs", "ML-DSA-65", 1952, 4032, 3309, kMlDsaSupportsContext, 0, 0, Dsa65Keygen, Dsa65Sign, Dsa65Verify, UnsupportedSignSeeded};
const pqcfuzz_sig_adapter kRightDsa87 = {"liboqs_self_reference", "selfref_mldsa87_via_liboqs", "ML-DSA-87", 2592, 4896, 4627, kMlDsaSupportsContext, 0, 0, Dsa87Keygen, Dsa87Sign, Dsa87Verify, UnsupportedSignSeeded};

#define PQCFUZZ_UNSUPPORTED_SLH(symbol, project, impl, algorithm, pk, sk, sig) \
  const pqcfuzz_sig_adapter symbol = {project, impl, algorithm, pk, sk, sig, 0, 0, 0, UnsupportedSigKeygen, UnsupportedSign, UnsupportedVerify, UnsupportedSignSeeded}

PQCFUZZ_UNSUPPORTED_SLH(kLeftSlhDsaSha2_128s, "liboqs", "liboqs_slhdsa_sha2_128s_wrapper_generic", "SLH-DSA-SHA2-128s", 32, 64, 7856);
PQCFUZZ_UNSUPPORTED_SLH(kLeftSlhDsaShake_128s, "liboqs", "liboqs_slhdsa_shake_128s_wrapper_generic", "SLH-DSA-SHAKE-128s", 32, 64, 7856);
PQCFUZZ_UNSUPPORTED_SLH(kLeftSlhDsaSha2_128f, "liboqs", "liboqs_slhdsa_sha2_128f_wrapper_generic", "SLH-DSA-SHA2-128f", 32, 64, 17088);
PQCFUZZ_UNSUPPORTED_SLH(kLeftSlhDsaShake_128f, "liboqs", "liboqs_slhdsa_shake_128f_wrapper_generic", "SLH-DSA-SHAKE-128f", 32, 64, 17088);
PQCFUZZ_UNSUPPORTED_SLH(kLeftSlhDsaSha2_192s, "liboqs", "liboqs_slhdsa_sha2_192s_wrapper_generic", "SLH-DSA-SHA2-192s", 48, 96, 16224);
PQCFUZZ_UNSUPPORTED_SLH(kLeftSlhDsaShake_192s, "liboqs", "liboqs_slhdsa_shake_192s_wrapper_generic", "SLH-DSA-SHAKE-192s", 48, 96, 16224);
PQCFUZZ_UNSUPPORTED_SLH(kLeftSlhDsaSha2_192f, "liboqs", "liboqs_slhdsa_sha2_192f_wrapper_generic", "SLH-DSA-SHA2-192f", 48, 96, 35664);
PQCFUZZ_UNSUPPORTED_SLH(kLeftSlhDsaShake_192f, "liboqs", "liboqs_slhdsa_shake_192f_wrapper_generic", "SLH-DSA-SHAKE-192f", 48, 96, 35664);
PQCFUZZ_UNSUPPORTED_SLH(kLeftSlhDsaSha2_256s, "liboqs", "liboqs_slhdsa_sha2_256s_wrapper_generic", "SLH-DSA-SHA2-256s", 64, 128, 29792);
PQCFUZZ_UNSUPPORTED_SLH(kLeftSlhDsaShake_256s, "liboqs", "liboqs_slhdsa_shake_256s_wrapper_generic", "SLH-DSA-SHAKE-256s", 64, 128, 29792);
PQCFUZZ_UNSUPPORTED_SLH(kLeftSlhDsaSha2_256f, "liboqs", "liboqs_slhdsa_sha2_256f_wrapper_generic", "SLH-DSA-SHA2-256f", 64, 128, 49856);
PQCFUZZ_UNSUPPORTED_SLH(kLeftSlhDsaShake_256f, "liboqs", "liboqs_slhdsa_shake_256f_wrapper_generic", "SLH-DSA-SHAKE-256f", 64, 128, 49856);
PQCFUZZ_UNSUPPORTED_SLH(kRightSlhDsaSha2_128s, "liboqs_self_reference", "selfref_slhdsa_sha2_128s_via_liboqs", "SLH-DSA-SHA2-128s", 32, 64, 7856);
PQCFUZZ_UNSUPPORTED_SLH(kRightSlhDsaShake_128s, "liboqs_self_reference", "selfref_slhdsa_shake_128s_via_liboqs", "SLH-DSA-SHAKE-128s", 32, 64, 7856);
PQCFUZZ_UNSUPPORTED_SLH(kRightSlhDsaSha2_128f, "liboqs_self_reference", "selfref_slhdsa_sha2_128f_via_liboqs", "SLH-DSA-SHA2-128f", 32, 64, 17088);
PQCFUZZ_UNSUPPORTED_SLH(kRightSlhDsaShake_128f, "liboqs_self_reference", "selfref_slhdsa_shake_128f_via_liboqs", "SLH-DSA-SHAKE-128f", 32, 64, 17088);
PQCFUZZ_UNSUPPORTED_SLH(kRightSlhDsaSha2_192s, "liboqs_self_reference", "selfref_slhdsa_sha2_192s_via_liboqs", "SLH-DSA-SHA2-192s", 48, 96, 16224);
PQCFUZZ_UNSUPPORTED_SLH(kRightSlhDsaShake_192s, "liboqs_self_reference", "selfref_slhdsa_shake_192s_via_liboqs", "SLH-DSA-SHAKE-192s", 48, 96, 16224);
PQCFUZZ_UNSUPPORTED_SLH(kRightSlhDsaSha2_192f, "liboqs_self_reference", "selfref_slhdsa_sha2_192f_via_liboqs", "SLH-DSA-SHA2-192f", 48, 96, 35664);
PQCFUZZ_UNSUPPORTED_SLH(kRightSlhDsaShake_192f, "liboqs_self_reference", "selfref_slhdsa_shake_192f_via_liboqs", "SLH-DSA-SHAKE-192f", 48, 96, 35664);
PQCFUZZ_UNSUPPORTED_SLH(kRightSlhDsaSha2_256s, "liboqs_self_reference", "selfref_slhdsa_sha2_256s_via_liboqs", "SLH-DSA-SHA2-256s", 64, 128, 29792);
PQCFUZZ_UNSUPPORTED_SLH(kRightSlhDsaShake_256s, "liboqs_self_reference", "selfref_slhdsa_shake_256s_via_liboqs", "SLH-DSA-SHAKE-256s", 64, 128, 29792);
PQCFUZZ_UNSUPPORTED_SLH(kRightSlhDsaSha2_256f, "liboqs_self_reference", "selfref_slhdsa_sha2_256f_via_liboqs", "SLH-DSA-SHA2-256f", 64, 128, 49856);
PQCFUZZ_UNSUPPORTED_SLH(kRightSlhDsaShake_256f, "liboqs_self_reference", "selfref_slhdsa_shake_256f_via_liboqs", "SLH-DSA-SHAKE-256f", 64, 128, 49856);

}  // namespace

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_liboqs_mlkem512_adapter(void) { return &kLeftKem512; }
extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_liboqs_mlkem768_adapter(void) { return &kLeftKem768; }
extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_liboqs_mlkem1024_adapter(void) { return &kLeftKem1024; }
extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_pqclean_mlkem512_adapter(void) { return &kRightKem512; }
extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_pqclean_mlkem768_adapter(void) { return &kRightKem768; }
extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_pqclean_mlkem1024_adapter(void) { return &kRightKem1024; }

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_mldsa44_adapter(void) { return &kLeftDsa44; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_mldsa65_adapter(void) { return &kLeftDsa65; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_mldsa87_adapter(void) { return &kLeftDsa87; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_mldsa44_adapter(void) { return &kRightDsa44; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_mldsa65_adapter(void) { return &kRightDsa65; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_mldsa87_adapter(void) { return &kRightDsa87; }

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_sha2_128s_adapter(void) { return &kLeftSlhDsaSha2_128s; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_shake_128s_adapter(void) { return &kLeftSlhDsaShake_128s; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_sha2_128f_adapter(void) { return &kLeftSlhDsaSha2_128f; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_shake_128f_adapter(void) { return &kLeftSlhDsaShake_128f; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_sha2_192s_adapter(void) { return &kLeftSlhDsaSha2_192s; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_shake_192s_adapter(void) { return &kLeftSlhDsaShake_192s; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_sha2_192f_adapter(void) { return &kLeftSlhDsaSha2_192f; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_shake_192f_adapter(void) { return &kLeftSlhDsaShake_192f; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_sha2_256s_adapter(void) { return &kLeftSlhDsaSha2_256s; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_shake_256s_adapter(void) { return &kLeftSlhDsaShake_256s; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_sha2_256f_adapter(void) { return &kLeftSlhDsaSha2_256f; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_shake_256f_adapter(void) { return &kLeftSlhDsaShake_256f; }

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_sha2_128s_adapter(void) { return &kRightSlhDsaSha2_128s; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_shake_128s_adapter(void) { return &kRightSlhDsaShake_128s; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_sha2_128f_adapter(void) { return &kRightSlhDsaSha2_128f; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_shake_128f_adapter(void) { return &kRightSlhDsaShake_128f; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_sha2_192s_adapter(void) { return &kRightSlhDsaSha2_192s; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_shake_192s_adapter(void) { return &kRightSlhDsaShake_192s; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_sha2_192f_adapter(void) { return &kRightSlhDsaSha2_192f; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_shake_192f_adapter(void) { return &kRightSlhDsaShake_192f; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_sha2_256s_adapter(void) { return &kRightSlhDsaSha2_256s; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_shake_256s_adapter(void) { return &kRightSlhDsaShake_256s; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_sha2_256f_adapter(void) { return &kRightSlhDsaSha2_256f; }
extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_shake_256f_adapter(void) { return &kRightSlhDsaShake_256f; }

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_liboqs_adapter(const char *implementation_id) {
  const pqcfuzz_kem_adapter *adapters[] = {&kLeftKem512, &kLeftKem768, &kLeftKem1024};
  for (const auto *adapter : adapters) {
    if (implementation_id != nullptr && std::strcmp(implementation_id, adapter->implementation_id) == 0) {
      return adapter;
    }
  }
  return nullptr;
}

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_pqclean_adapter(const char *implementation_id) {
  const pqcfuzz_kem_adapter *adapters[] = {&kRightKem512, &kRightKem768, &kRightKem1024};
  for (const auto *adapter : adapters) {
    if (implementation_id != nullptr && std::strcmp(implementation_id, adapter->implementation_id) == 0) {
      return adapter;
    }
  }
  return nullptr;
}

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_sig_adapter(const char *implementation_id) {
  const pqcfuzz_sig_adapter *adapters[] = {
      &kLeftDsa44, &kLeftDsa65, &kLeftDsa87,
      &kLeftSlhDsaSha2_128s, &kLeftSlhDsaShake_128s, &kLeftSlhDsaSha2_128f, &kLeftSlhDsaShake_128f,
      &kLeftSlhDsaSha2_192s, &kLeftSlhDsaShake_192s, &kLeftSlhDsaSha2_192f, &kLeftSlhDsaShake_192f,
      &kLeftSlhDsaSha2_256s, &kLeftSlhDsaShake_256s, &kLeftSlhDsaSha2_256f, &kLeftSlhDsaShake_256f};
  for (const auto *adapter : adapters) {
    if (implementation_id != nullptr && std::strcmp(implementation_id, adapter->implementation_id) == 0) {
      return adapter;
    }
  }
  return nullptr;
}

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_sig_adapter(const char *implementation_id) {
  const pqcfuzz_sig_adapter *adapters[] = {
      &kRightDsa44, &kRightDsa65, &kRightDsa87,
      &kRightSlhDsaSha2_128s, &kRightSlhDsaShake_128s, &kRightSlhDsaSha2_128f, &kRightSlhDsaShake_128f,
      &kRightSlhDsaSha2_192s, &kRightSlhDsaShake_192s, &kRightSlhDsaSha2_192f, &kRightSlhDsaShake_192f,
      &kRightSlhDsaSha2_256s, &kRightSlhDsaShake_256s, &kRightSlhDsaSha2_256f, &kRightSlhDsaShake_256f};
  for (const auto *adapter : adapters) {
    if (implementation_id != nullptr && std::strcmp(implementation_id, adapter->implementation_id) == 0) {
      return adapter;
    }
  }
  return nullptr;
}
CPP
}

write_generated_configs() {
  local tmp_root="$1"
  mkdir -p "$tmp_root"
  cat > "${tmp_root}/generated_config_kem.json" <<JSON
{
  "version": 1,
  "job_id": "pqcfuzz_eval_kem_liboqs_${VERSION}",
  "pair_id": "liboqs_${VERSION}_self_reference_kem",
  "primitive_type": "kem",
  "oracle_suite": "${ORACLE_SUITE}",
  "relation_mode": "${RELATION_MODE}",
  "target_runtime": "${TARGET_RUNTIME}",
  "liboqs_version": "${VERSION}",
  "skipped_families": ["SLH-DSA"]
}
JSON
  cat > "${tmp_root}/generated_config_sig.json" <<JSON
{
  "version": 1,
  "job_id": "pqcfuzz_eval_sig_liboqs_${VERSION}",
  "pair_id": "liboqs_${VERSION}_self_reference_sig",
  "primitive_type": "sig",
  "oracle_suite": "${ORACLE_SUITE}",
  "relation_mode": "${RELATION_MODE}",
  "target_runtime": "${TARGET_RUNTIME}",
  "liboqs_version": "${VERSION}",
  "skipped_families": ["SLH-DSA"]
}
JSON
}

make_seed() {
  local output="$1"
  local algorithm_enum="$2"
  local oracle_enum="$3"
  mkdir -p "$(dirname "$output")"
  python3 - "$output" "$algorithm_enum" "$oracle_enum" <<'PY'
import struct
import sys

path = sys.argv[1]
algorithm = int(sys.argv[2])
oracle = int(sys.argv[3])
seed = bytes(range(32))
message = b"PQCFuzz eval"
mutation = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
extra = b""

out = bytearray(b"PQCF")
out.extend(bytes([1, algorithm, oracle, 0]))
for field in (seed, message, mutation, extra):
    out.extend(struct.pack("<H", len(field)))
    out.extend(field)
with open(path, "wb") as f:
    f.write(out)
PY
}

oracle_specs_for_primitive() {
  local primitive="$1"
  case "${ORACLE_SUITE}:${primitive}" in
    metamorphic:kem)
      if [ "$ORACLE_SET" = "security" ]; then
        printf '%s\n' '18:kem_decaps_c'
      else
        printf '%s\n' \
          '18:kem_decaps_c' '19:kem_decaps_sk' '20:kem_encaps_badrng' \
          '21:kem_encaps_pk_0' '22:kem_encaps_pk' '23:kem_keygen_badrng'
      fi
      ;;
    metamorphic:sig)
      if [ "$ORACLE_SET" = "security" ]; then
        printf '%s\n' '28:sig_verify_m' '29:sig_verify_sig' '30:sig_verify_pk'
      else
        printf '%s\n' \
          '24:sig_keygen_badrng' '25:sig_sign_badrng' '26:sig_sign_m' \
          '27:sig_sign_sk' '28:sig_verify_m' '29:sig_verify_sig' '30:sig_verify_pk'
      fi
      ;;
    fips:kem)
      printf '%s\n' \
        '1:mlkem_local_roundtrip' '2:mlkem_cross_exchange_roundtrip' \
        '3:mlkem_tampered_ciphertext_implicit_rejection' '4:mlkem_bad_randomness_sanity'
      ;;
    fips:sig)
      printf '%s\n' \
        '5:mldsa_local_sign_verify' '6:mldsa_cross_verify' \
        '7:mldsa_mutated_signature_negative' '8:mldsa_mutated_message_negative' \
        '9:mldsa_mutated_context_negative' '10:mldsa_oid_field_mutation_sanity' \
        '11:mldsa_bad_randomness_sanity'
      ;;
    *)
      echo "unsupported oracle suite/primitive: ${ORACLE_SUITE}/${primitive}" >&2
      return 1
      ;;
  esac
}

make_seed_corpus() {
  local corpus_dir="$1" target="$2" algorithm_enum="$3" primitive="$4"
  local spec oracle_enum oracle_name
  mkdir -p "$corpus_dir"
  while IFS=: read -r oracle_enum oracle_name; do
    [ -n "$oracle_enum" ] || continue
    make_seed "${corpus_dir}/seed-pqcfuzz-${target}-${oracle_name}.bin" "$algorithm_enum" "$oracle_enum"
  done < <(oracle_specs_for_primitive "$primitive")
}

first_seed_in_corpus() {
  local corpus_dir="$1"
  find "$corpus_dir" -maxdepth 1 -type f -name 'seed-pqcfuzz-*.bin' -print | LC_ALL=C sort | head -n 1
}

verify_oracle_coverage() {
  local coverage_file="$1" primitive="$2"
  EXPECTED_ORACLE_SPECS="$(oracle_specs_for_primitive "$primitive" | paste -sd, -)" \
  python3 - "$coverage_file" <<'PY'
import json
import os
import sys
from pathlib import Path

coverage_path = Path(sys.argv[1])
try:
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"missing or unreadable oracle coverage file {coverage_path}: {exc}")

expected = []
for item in os.environ["EXPECTED_ORACLE_SPECS"].split(","):
    if not item:
        continue
    _, name = item.split(":", 1)
    expected.append(name)
oracles = coverage.get("oracles", {})
missing = []
for name in expected:
    counters = oracles.get(name, {})
    requirements = {
        "invoked": "oracle_invocations",
        "valid_setup": "valid_setup",
        "relation_evaluable": "relation_evaluable",
        "intervention_effective": "intervention_effective",
    }
    absent = [label for label, field in requirements.items() if int(counters.get(field, 0)) < 1]
    if int(counters.get("unsupported", 0)) > 0:
        absent.append("unsupported")
    if int(counters.get("skipped", 0)) > 0:
        absent.append("skipped")
    if absent:
        missing.append(name + " (" + ", ".join(absent) + ")")
if missing:
    raise SystemExit("oracle preflight did not produce an evaluable observation: " + ", ".join(missing))
PY
}

write_run_summary() {
  local summary_file="$1"
  local target="$2"
  local status="$3"
  local seconds="$4"
  local binary="$5"
  local log_file="$6"
  local crash_dir="$7"
  local corpus_dir="$8"
  local algorithm_enum="$9"
  local oracle_enum="${10}"
  local result_dir="${11}"
  local preflight_coverage="${12}"

  RUN_SUMMARY_FILE="$summary_file" \
  RUN_TARGET="$target" \
  RUN_STATUS="$status" \
  RUN_SECONDS="$seconds" \
  RUN_BINARY="$binary" \
  RUN_LOG="$log_file" \
  RUN_CRASH_DIR="$crash_dir" \
  RUN_CORPUS_DIR="$corpus_dir" \
  RUN_VERSION="$VERSION" \
  RUN_ALGORITHM_ENUM="$algorithm_enum" \
  RUN_ORACLE_ENUM="$oracle_enum" \
  RUN_ORACLE_SPECS="$(oracle_specs_for_primitive "$(target_metadata "$target" | cut -f1)")" \
  RUN_PREFLIGHT_ORACLE_COVERAGE_FILE="$preflight_coverage" \
  RUN_FUZZ_ORACLE_COVERAGE_FILE="${result_dir}/oracle_coverage.json" \
  RUN_PREFLIGHT_ONLY="$PREFLIGHT_ONLY" \
  RUN_FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE="$FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE" \
  RUN_RELATION_MODE="$RELATION_MODE" \
  RUN_SANITIZERS="$SANITIZERS" \
  RUN_LEAK_CHECK="$LEAK_CHECK" \
  RUN_RESULT_DIR="$result_dir" \
  RUN_SKIPPED_FAMILIES_JSON="$SKIPPED_FAMILIES_JSON" \
  python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

path = Path(os.environ["RUN_SUMMARY_FILE"])
path.parent.mkdir(parents=True, exist_ok=True)
result_dir = Path(os.environ["RUN_RESULT_DIR"])
sanitizer_findings = []
for finding_path in sorted(result_dir.glob("sanitizer_*/finding.json")):
    try:
        finding = json.loads(finding_path.read_text(encoding="utf-8"))
    except Exception:
        continue
    sanitizer_findings.append({
        "path": str(finding_path),
        "sanitizer": finding.get("sanitizer"),
        "fingerprint": finding.get("fingerprint"),
        "source_location": finding.get("source_location"),
        "message": finding.get("summary"),
    })
status = int(os.environ["RUN_STATUS"])
has_sanitizer_findings = bool(sanitizer_findings)

def load_coverage(path_value: str):
    path = Path(path_value)
    try:
        return json.loads(path.read_text(encoding="utf-8")), True
    except Exception:
        return {"schema_version": 1, "totals": {}, "oracles": {}}, False

preflight_coverage, preflight_coverage_present = load_coverage(
    os.environ["RUN_PREFLIGHT_ORACLE_COVERAGE_FILE"]
)
fuzz_coverage, fuzz_coverage_present = load_coverage(
    os.environ["RUN_FUZZ_ORACLE_COVERAGE_FILE"]
)
scheduled_oracles = []
for item in os.environ["RUN_ORACLE_SPECS"].splitlines():
    if not item:
        continue
    enum, name = item.split(":", 1)
    scheduled_oracles.append({"enum": int(enum), "oracle_id": name})
observed_oracles = (
    preflight_coverage.get("oracles", {}) if isinstance(preflight_coverage, dict) else {}
)
uncovered_oracles = []
for item in scheduled_oracles:
    counters = observed_oracles.get(item["oracle_id"], {})
    required = ("oracle_invocations", "valid_setup", "relation_evaluable", "intervention_effective")
    if (any(int(counters.get(field, 0)) < 1 for field in required) or
            int(counters.get("unsupported", 0)) > 0 or int(counters.get("skipped", 0)) > 0):
        uncovered_oracles.append(item["oracle_id"])
if not preflight_coverage_present:
    preflight_coverage_state = "not-run"
elif uncovered_oracles:
    preflight_coverage_state = "failed"
else:
    preflight_coverage_state = "passed"

min_evaluable_rate = float(os.environ["RUN_FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE"])
preflight_only = os.environ["RUN_PREFLIGHT_ONLY"] == "1"
fuzz_effectiveness_by_oracle = {}
fuzz_effectiveness_failures = []
if preflight_only:
    fuzz_effectiveness_state = "not-run"
elif not fuzz_coverage_present:
    fuzz_effectiveness_state = "not-run"
else:
    fuzz_oracles = fuzz_coverage.get("oracles", {}) if isinstance(fuzz_coverage, dict) else {}
    for item in scheduled_oracles:
        oracle_id = item["oracle_id"]
        counters = fuzz_oracles.get(oracle_id, {})
        invocations = int(counters.get("oracle_invocations", 0) or 0)
        evaluable = int(counters.get("relation_evaluable", 0) or 0)
        unsupported = int(counters.get("unsupported", 0) or 0)
        skipped = int(counters.get("skipped", 0) or 0)
        rate = (evaluable / invocations) if invocations else 0.0
        record = {
            "oracle_id": oracle_id,
            "oracle_invocations": invocations,
            "relation_evaluable": evaluable,
            "evaluable_rate": rate,
            "unsupported": unsupported,
            "skipped": skipped,
            "non_evaluable_reasons": counters.get("non_evaluable_reasons", {}),
        }
        fuzz_effectiveness_by_oracle[oracle_id] = record
        reason = None
        if invocations < 1:
            reason = "not_invoked"
        elif unsupported > 0:
            reason = "unexpected_unsupported"
        elif rate < min_evaluable_rate:
            reason = "evaluable_rate_below_threshold"
        if reason is not None:
            failure = dict(record)
            failure["reason"] = reason
            failure["min_evaluable_rate"] = min_evaluable_rate
            fuzz_effectiveness_failures.append(failure)
    fuzz_effectiveness_state = "failed" if fuzz_effectiveness_failures else "passed"

if preflight_coverage_state != "passed":
    oracle_coverage_state = "failed" if preflight_coverage_state == "failed" else "not-run"
elif preflight_only:
    oracle_coverage_state = "passed"
elif fuzz_effectiveness_state == "passed":
    oracle_coverage_state = "passed"
else:
    oracle_coverage_state = "failed"
doc = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "target": os.environ["RUN_TARGET"],
    "version": os.environ["RUN_VERSION"],
    "status": status,
    "max_total_time": int(os.environ["RUN_SECONDS"]),
    "wall_time_seconds": int(os.environ["RUN_SECONDS"]),
    "cpu_time_seconds": None,
    "worker_count": 1,
    "algorithm_coverage": [int(os.environ["RUN_ALGORITHM_ENUM"])],
    "seed_oracle_enum": int(os.environ["RUN_ORACLE_ENUM"]),
    "scheduled_oracles": scheduled_oracles,
    "preflight_oracle_coverage": preflight_coverage,
    "fuzz_oracle_coverage": fuzz_coverage,
    "fuzz_oracle_coverage_present": fuzz_coverage_present,
    "oracle_coverage": fuzz_coverage,
    "preflight_coverage_state": preflight_coverage_state,
    "preflight_uncovered_oracles": uncovered_oracles,
    "fuzz_effectiveness_state": fuzz_effectiveness_state,
    "fuzz_effectiveness_min_evaluable_rate": min_evaluable_rate,
    "fuzz_effectiveness_by_oracle": fuzz_effectiveness_by_oracle,
    "fuzz_effectiveness_failures": fuzz_effectiveness_failures,
    "oracle_coverage_state": oracle_coverage_state,
    "oracle_coverage_complete": oracle_coverage_state == "passed",
    "uncovered_oracles": uncovered_oracles,
    "stop_reason": "sanitizer-report" if has_sanitizer_findings else ("max_total_time" if status == 0 else "process_exit"),
    "state": "completed-with-findings" if has_sanitizer_findings else ("completed" if status == 0 else ("timed-out" if status == 124 else "harness-error")),
    "binary": os.environ["RUN_BINARY"],
    "log": os.environ["RUN_LOG"],
    "crash_dir": os.environ["RUN_CRASH_DIR"],
    "corpus_dir": os.environ["RUN_CORPUS_DIR"],
    "relation_mode": os.environ["RUN_RELATION_MODE"],
    "sanitizers": os.environ["RUN_SANITIZERS"],
    "leak_check": os.environ["RUN_LEAK_CHECK"],
    "sanitizer_finding_count": len(sanitizer_findings),
    "sanitizer_findings": sanitizer_findings,
    "skipped_families": json.loads(os.environ["RUN_SKIPPED_FAMILIES_JSON"]),
    "skipped": False,
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

target_metadata() {
  case "$1" in
    mlkem512) printf 'kem\tML-KEM-512\n' ;;
    mlkem768) printf 'kem\tML-KEM-768\n' ;;
    mlkem1024) printf 'kem\tML-KEM-1024\n' ;;
    mldsa44) printf 'sig\tML-DSA-44\n' ;;
    mldsa65) printf 'sig\tML-DSA-65\n' ;;
    mldsa87) printf 'sig\tML-DSA-87\n' ;;
    *) return 1 ;;
  esac
}

target_capability_state() {
  case "${VERSION}:$1" in
    0.4.0:mlkem512|0.4.0:mldsa44|0.4.0:mldsa65|0.4.0:mldsa87|0.8.0:mldsa44|0.8.0:mldsa65|0.8.0:mldsa87)
      printf '%s\n' 'not-applicable'
      ;;
    *)
      printf '%s\n' 'comparable'
      ;;
  esac
}

target_skip_reason() {
  case "${VERSION}:$1" in
    0.4.0:mlkem512)
      printf '%s\n' 'legacy Kyber512 in liboqs 0.4.0 has a 736-byte ciphertext and is not comparable with canonical ML-KEM-512 (768 bytes)'
      ;;
    0.4.0:mldsa44|0.4.0:mldsa65|0.4.0:mldsa87|0.8.0:mldsa44|0.8.0:mldsa65|0.8.0:mldsa87)
      printf '%s\n' "historical Dilithium parameters for liboqs ${VERSION} do not match FIPS ML-DSA canonical lengths"
      ;;
    *)
      printf '%s\n' 'target is not applicable to this liboqs capability profile'
      ;;
  esac
}

write_capability_manifest() {
  local manifest_file="${WORKSPACE_ROOT_ABS}/capabilities.json"
  CAPABILITY_MANIFEST_FILE="$manifest_file" CAPABILITY_VERSION="$VERSION" python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

version = os.environ["CAPABILITY_VERSION"]
canonical_layouts = {
    "mlkem512": {"public_key": 800, "secret_key": 1632, "ciphertext": 768, "shared_secret": 32},
    "mlkem768": {"public_key": 1184, "secret_key": 2400, "ciphertext": 1088, "shared_secret": 32},
    "mlkem1024": {"public_key": 1568, "secret_key": 3168, "ciphertext": 1568, "shared_secret": 32},
    "mldsa44": {"public_key": 1312, "secret_key": 2560, "signature": 2420},
    "mldsa65": {"public_key": 1952, "secret_key": 4032, "signature": 3309},
    "mldsa87": {"public_key": 2592, "secret_key": 4896, "signature": 4627},
}
algorithms = {
    "mlkem512": "ML-KEM-512", "mlkem768": "ML-KEM-768", "mlkem1024": "ML-KEM-1024",
    "mldsa44": "ML-DSA-44", "mldsa65": "ML-DSA-65", "mldsa87": "ML-DSA-87",
}
targets = []
for target, algorithm in algorithms.items():
    comparable = True
    reason = None
    observed_layout = None
    if version == "0.4.0" and target == "mlkem512":
        comparable = False
        reason = "legacy Kyber512 ciphertext length is 736 bytes; canonical ML-KEM-512 requires 768 bytes"
        observed_layout = {"public_key": 800, "secret_key": 1632, "ciphertext": 736, "shared_secret": 32}
    elif version != "0.14.0" and target.startswith("mldsa"):
        comparable = False
        reason = "historical Dilithium parameter lengths are not the canonical FIPS ML-DSA lengths"
    targets.append({
        "target": target,
        "algorithm": algorithm,
        "state": "comparable" if comparable else "not-applicable",
        "comparable": comparable,
        "reason": reason,
        "canonical_layout": canonical_layouts[target],
        "observed_layout": observed_layout,
        "preflight_state": "pending" if comparable else "not-applicable",
    })

doc = {
    "schema_version": 1,
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "version": version,
    "targets": targets,
}
path = Path(os.environ["CAPABILITY_MANIFEST_FILE"])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  printf '%s\n' "$manifest_file"
}

record_target_preflight() {
  local target="$1" state="$2" detail="${3:-}"
  [ -n "${CAPABILITY_MANIFEST:-}" ] || return 0
  CAPABILITY_MANIFEST_FILE="$CAPABILITY_MANIFEST" CAPABILITY_TARGET="$target" \
  CAPABILITY_PREFLIGHT_STATE="$state" CAPABILITY_PREFLIGHT_DETAIL="$detail" python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

path = Path(os.environ["CAPABILITY_MANIFEST_FILE"])
try:
    doc = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit("cannot update missing capability manifest")
for target in doc.get("targets", []):
    if target.get("target") == os.environ["CAPABILITY_TARGET"]:
        target["preflight_state"] = os.environ["CAPABILITY_PREFLIGHT_STATE"]
        target["preflight_detail"] = os.environ["CAPABILITY_PREFLIGHT_DETAIL"] or None
        break
else:
    raise SystemExit("target is missing from capability manifest")
doc["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

collect_sanitizer_findings() {
  local target="$1" phase="$2" log_file="$3" result_dir="$4" seed_file="$5" binary="$6" summary_file="$7"
  local primitive algorithm
  IFS=$'\t' read -r primitive algorithm < <(target_metadata "$target") || return 1
  python3 scripts/collect_sanitizer_findings.py \
    --log "$log_file" \
    --result-dir "$result_dir" \
    --summary-file "$summary_file" \
    --target "$target" \
    --version "$VERSION" \
    --algorithm "$algorithm" \
    --primitive "$primitive" \
    --job-id "pqcfuzz_eval_${target}_liboqs_${VERSION}" \
    --pair-id "liboqs_${VERSION}_${target}_single_target" \
    --oracle-suite "$ORACLE_SUITE" \
    --relation-mode "$RELATION_MODE" \
    --phase "$phase" \
    --binary "$binary" \
    --seed-file "$seed_file" >/dev/null || return $?
  SANITIZER_FINDING_COUNT="$(python3 - "$summary_file" <<'PY'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        print(int(json.load(handle).get("count", 0)))
except Exception:
    print(0)
PY
)"
}

refresh_sanitizer_summary() {
  local summary_file="$1" result_dir="$2"
  RUN_SUMMARY_FILE="$summary_file" RUN_RESULT_DIR="$result_dir" python3 - <<'PY'
import json
import os
from pathlib import Path

summary_path = Path(os.environ["RUN_SUMMARY_FILE"])
result_dir = Path(os.environ["RUN_RESULT_DIR"])
try:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit("cannot refresh missing run summary")
findings = []
for path in sorted(result_dir.glob("sanitizer_*/finding.json")):
    try:
        finding = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    findings.append({
        "path": str(path),
        "sanitizer": finding.get("sanitizer"),
        "fingerprint": finding.get("fingerprint"),
        "source_location": finding.get("source_location"),
        "message": finding.get("summary"),
    })
summary["sanitizer_finding_count"] = len(findings)
summary["sanitizer_findings"] = findings
if findings:
    summary["state"] = "completed-with-findings"
    summary["stop_reason"] = "sanitizer-report"
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

write_replay_manifest() {
  local manifest_file="$1"
  local target="$2"
  local result_dir="$3"
  REPLAY_MANIFEST_FILE="$manifest_file" REPLAY_TARGET="$target" REPLAY_RESULT_DIR="$result_dir" python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["REPLAY_RESULT_DIR"])
artifacts = []
paths = sorted(root.rglob("finding.json")) if root.is_dir() else []
for path in paths:
    try:
        finding = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        finding = {}
    artifacts.append({"path": str(path), "validated": bool(finding.get("validated", False))})
doc = {
    "version": 2,
    "target": os.environ["REPLAY_TARGET"],
    "artifact_count": len(artifacts),
    "validated_count": sum(item["validated"] for item in artifacts),
    "unvalidated_count": sum(not item["validated"] for item in artifacts),
    "state": "complete" if all(item["validated"] for item in artifacts) else "validation-required",
    "artifacts": artifacts,
}
path = Path(os.environ["REPLAY_MANIFEST_FILE"])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

write_skip_summary() {
  local summary_file="$1"
  local target="$2"
  local seconds="$3"
  local binary="$4"
  local log_file="$5"
  local crash_dir="$6"
  local corpus_dir="$7"
  local reason="$8"

  RUN_SUMMARY_FILE="$summary_file" \
  RUN_TARGET="$target" \
  RUN_SECONDS="$seconds" \
  RUN_BINARY="$binary" \
  RUN_LOG="$log_file" \
  RUN_CRASH_DIR="$crash_dir" \
  RUN_CORPUS_DIR="$corpus_dir" \
  RUN_SKIP_REASON="$reason" \
  RUN_VERSION="$VERSION" \
  RUN_RELATION_MODE="$RELATION_MODE" \
  RUN_SKIPPED_FAMILIES_JSON="$SKIPPED_FAMILIES_JSON" \
  python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

path = Path(os.environ["RUN_SUMMARY_FILE"])
path.parent.mkdir(parents=True, exist_ok=True)
doc = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "target": os.environ["RUN_TARGET"],
    "version": os.environ["RUN_VERSION"],
    "status": 0,
    "max_total_time": int(os.environ["RUN_SECONDS"]),
    "binary": os.environ["RUN_BINARY"],
    "log": os.environ["RUN_LOG"],
    "crash_dir": os.environ["RUN_CRASH_DIR"],
    "corpus_dir": os.environ["RUN_CORPUS_DIR"],
    "relation_mode": os.environ["RUN_RELATION_MODE"],
    "skipped_families": json.loads(os.environ["RUN_SKIPPED_FAMILIES_JSON"]),
    "skipped": True,
    "skip_reason": os.environ["RUN_SKIP_REASON"],
    "preflight_coverage_state": "not-applicable",
    "preflight_uncovered_oracles": [],
    "fuzz_effectiveness_state": "not-applicable",
    "fuzz_effectiveness_min_evaluable_rate": None,
    "fuzz_effectiveness_by_oracle": {},
    "fuzz_effectiveness_failures": [],
    "oracle_coverage_state": "not-applicable",
    "oracle_coverage_complete": None,
    "scheduled_oracles": [],
    "preflight_oracle_coverage": {"schema_version": 1, "totals": {}, "oracles": {}},
    "fuzz_oracle_coverage": {"schema_version": 1, "totals": {}, "oracles": {}},
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

build_liboqs() {
  local build_root="$1"
  local liboqs_src_dir="${build_root}/liboqs-src"
  local liboqs_build_dir="${build_root}/liboqs-build"
  local cc_bin="${CC:-clang}"
  local cxx_bin="${CXX:-clang++}"
  local parallel_jobs
  local cmake_status build_status archive
  local -a cmake_extra_flags=()
  parallel_jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

  cmake_extra_flags+=(
    -DOQS_BUILD_ONLY_LIB=ON
    -DOQS_DIST_BUILD=OFF
  )
  case "$VERSION" in
    0.14.0)
      cmake_extra_flags+=('-DOQS_MINIMAL_BUILD=KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87')
      ;;
    0.8.0)
      cmake_extra_flags+=('-DOQS_MINIMAL_BUILD=KEM_kyber_512;KEM_kyber_768;KEM_kyber_1024;SIG_dilithium_2;SIG_dilithium_3;SIG_dilithium_5')
      ;;
    0.4.0)
      cmake_extra_flags+=(
        -DOQS_ENABLE_KEM_BIKE=OFF
        -DOQS_ENABLE_KEM_FRODOKEM=OFF
        -DOQS_ENABLE_KEM_SIKE=OFF
        -DOQS_ENABLE_KEM_SIDH=OFF
        -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF
        -DOQS_ENABLE_KEM_HQC=OFF
        -DOQS_ENABLE_KEM_NEWHOPE=OFF
        -DOQS_ENABLE_KEM_NTRU=OFF
        -DOQS_ENABLE_KEM_SABER=OFF
        -DOQS_ENABLE_KEM_THREEBEARS=OFF
        -DOQS_ENABLE_SIG_PICNIC=OFF
        -DOQS_ENABLE_SIG_QTESLA=OFF
        -DOQS_ENABLE_SIG_FALCON=OFF
        -DOQS_ENABLE_SIG_MQDSS=OFF
        -DOQS_ENABLE_SIG_RAINBOW=OFF
        -DOQS_ENABLE_SIG_SPHINCS=OFF
        -DOQS_ENABLE_KEM_KYBER=ON
        -DOQS_ENABLE_SIG_DILITHIUM=ON
        -DOQS_ENABLE_KEM_kyber_512_90s=OFF
        -DOQS_ENABLE_KEM_kyber_768_90s=OFF
        -DOQS_ENABLE_KEM_kyber_1024_90s=OFF
        -DOQS_ENABLE_KEM_kyber_512_90s_avx2=OFF
        -DOQS_ENABLE_KEM_kyber_768_90s_avx2=OFF
        -DOQS_ENABLE_KEM_kyber_1024_90s_avx2=OFF
        -DOQS_ENABLE_KEM_kyber_512_avx2=OFF
        -DOQS_ENABLE_KEM_kyber_768_avx2=OFF
        -DOQS_ENABLE_KEM_kyber_1024_avx2=OFF
        -DOQS_ENABLE_SIG_dilithium_2_avx2=OFF
        -DOQS_ENABLE_SIG_dilithium_3_avx2=OFF
        -DOQS_ENABLE_SIG_dilithium_4_avx2=OFF
      )
      ;;
  esac

  mkdir -p "$build_root"
  if [ ! -d "${liboqs_src_dir}/.git" ]; then
    rm -rf "$liboqs_src_dir"
    git clone --branch "$VERSION" --depth 1 https://github.com/open-quantum-safe/liboqs.git "$liboqs_src_dir"
  else
    git config --global --add safe.directory "$liboqs_src_dir"
    if ! git -C "$liboqs_src_dir" rev-parse -q --verify "refs/tags/${VERSION}" >/dev/null; then
      git -C "$liboqs_src_dir" fetch --depth 1 origin "refs/tags/${VERSION}:refs/tags/${VERSION}"
    fi
    local current_commit target_commit
    current_commit="$(git -C "$liboqs_src_dir" rev-parse HEAD)"
    target_commit="$(git -C "$liboqs_src_dir" rev-list -n 1 "$VERSION")"
    if [ "$current_commit" != "$target_commit" ]; then
      git -C "$liboqs_src_dir" checkout --force "$VERSION"
    fi
  fi

  if [ "$VERSION" = "0.14.0" ]; then
    python3 scripts/patch_liboqs_mldsa_empty_context.py \
      --source-root "$liboqs_src_dir" \
      --manifest "${build_root}/liboqs-mldsa-empty-context-patch.json" || return $?
  fi

  rm -rf "$liboqs_build_dir"
  printf '[pqcfuzz-eval] liboqs CMake extra flags:'
  printf ' %q' "${cmake_extra_flags[@]}"
  printf '\n'

  cmake -S "$liboqs_src_dir" -B "$liboqs_build_dir" -GNinja \
    -DCMAKE_C_COMPILER="$cc_bin" \
    -DCMAKE_CXX_COMPILER="$cxx_bin" \
    -DCMAKE_ASM_COMPILER="$cc_bin" \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_FLAGS="-O1 -g -fno-omit-frame-pointer ${LIBOQS_SANITIZER_FLAGS}" \
    -DCMAKE_CXX_FLAGS="-O1 -g -fno-omit-frame-pointer ${LIBOQS_SANITIZER_FLAGS}" \
    -DCMAKE_ASM_FLAGS="-fno-omit-frame-pointer" \
    "${cmake_extra_flags[@]}"
  cmake_status="$?"
  if [ "$cmake_status" -ne 0 ]; then
    echo "liboqs CMake configure failed with status ${cmake_status}" >&2
    return "$cmake_status"
  fi

  cmake --build "$liboqs_build_dir" --target oqs --parallel "$parallel_jobs"
  build_status="$?"
  if [ "$build_status" -ne 0 ]; then
    echo "liboqs build failed with status ${build_status}" >&2
    return "$build_status"
  fi

  archive="${liboqs_build_dir}/lib/liboqs.a"
  if [ ! -s "$archive" ]; then
    echo "expected liboqs archive not found: ${archive}" >&2
    return 1
  fi
}

build_pqcfuzz() {
  local build_root="$1"
  local pqcfuzz_build_dir="${build_root}/pqcfuzz"
  local liboqs_build_dir="${build_root}/liboqs-build"
  local liboqs_archive="${liboqs_build_dir}/lib/liboqs.a"
  local adapter_src="${pqcfuzz_build_dir}/pqcfuzz_liboqs_self_reference_adapter.cc"
  local tmp_root="${WORKSPACE_ROOT_ABS}/tmp/liboqs-${VERSION}"
  local cxx_bin="${CXX:-clang++}"

  if [ ! -s "$liboqs_archive" ]; then
    echo "cannot build PQCFuzz targets; missing liboqs archive: ${liboqs_archive}" >&2
    return 1
  fi

  mkdir -p "$pqcfuzz_build_dir"
  write_compat_adapter "$adapter_src"
  write_generated_configs "$tmp_root"

  local common_sources=(
    src/adapters/status.cc
    src/adapters/rng_control.cc
    src/adapters/liboqs/rng_control.cc
    src/adapters/randombytes_override.cc
    src/mutators/envelope.cc
    src/mutators/envelope_fuzzer_mutator.cc
    src/mutators/maul.cc
    src/mutators/ml_kem_layout.cc
    src/mutators/ml_kem_mutator.cc
    src/mutators/ml_dsa_layout.cc
    src/mutators/ml_dsa_mutator.cc
    src/mutators/slh_dsa_layout.cc
    src/mutators/slh_dsa_mutator.cc
    src/oracles/expected_relation.cc
    src/oracles/oracle_spec.cc
    src/oracles/oracle_spec_loader.cc
    src/oracles/oracle_result.cc
    src/oracles/oracle_executor.cc
    src/oracles/metamorphic_observation.cc
    src/oracles/metamorphic_spec.cc
    src/oracles/metamorphic_executor.cc
    src/runtime/adapter_registry.cc
    src/runtime/replay_args.cc
    src/triage/finding_writer.cc
    src/triage/oracle_coverage.cc
    "$adapter_src"
  )

  # A binary is bound to one algorithm.  The envelope is only test data and
  # can no longer select (or relabel) an adapter at runtime.
  build_target() {
    local job="$1" primitive="$2" algorithm="$3" implementation="$4" source="$5" algorithm_enum="$6" oracle_specs config_file right_implementation
    if [ "$(target_capability_state "$job")" != "comparable" ]; then
      echo "[pqcfuzz-eval] not building non-comparable target ${job}: $(target_skip_reason "$job")"
      return 0
    fi
    oracle_specs="$(oracle_specs_for_primitive "$primitive" | cut -d: -f1 | paste -sd, -)"
    case "$job" in
      mlkem512) right_implementation="selfref_mlkem512_via_liboqs" ;;
      mlkem768) right_implementation="selfref_mlkem768_via_liboqs" ;;
      mlkem1024) right_implementation="selfref_mlkem1024_via_liboqs" ;;
      mldsa44) right_implementation="selfref_mldsa44_via_liboqs" ;;
      mldsa65) right_implementation="selfref_mldsa65_via_liboqs" ;;
      mldsa87) right_implementation="selfref_mldsa87_via_liboqs" ;;
      *) echo "unknown PQCFuzz target $job" >&2; return 1 ;;
    esac
    config_file="${tmp_root}/generated_config_${job}.json"
    cat > "$config_file" <<JSON
{"version":2,"job_id":"pqcfuzz_eval_${job}_liboqs_${VERSION}","primitive_type":"${primitive}","algorithm":"${algorithm}","oracle_semantics_version":3,"skipped_families":["SLH-DSA"]}
JSON
    "$cxx_bin" -std=c++17 -O1 -g -fno-omit-frame-pointer -Isrc -I"${liboqs_build_dir}/include" \
      "$FUZZER_SANITIZER_FLAGS" \
      -DPQCFUZZ_JOB_ID="\"pqcfuzz_eval_${job}_liboqs_${VERSION}\"" \
      -DPQCFUZZ_PAIR_ID="\"liboqs_${VERSION}_${job}_single_target\"" \
      -DPQCFUZZ_RESULT_DIR="\"${WORKSPACE_ROOT_REL}/results/${job}\"" \
      -DPQCFUZZ_GENERATED_CONFIG_PATH="\"${config_file}\"" \
      -DPQCFUZZ_ORACLE_SUITE="\"${ORACLE_SUITE}\"" \
      -DPQCFUZZ_RELATION_MODE="\"${RELATION_MODE}\"" \
      -DPQCFUZZ_FINDING_SAVE_MODE="\"${FINDING_SAVE_MODE}\"" \
      -DPQCFUZZ_MAX_FINDING_EXEMPLARS_PER_GROUP="${MAX_FINDING_EXEMPLARS_PER_GROUP}" \
      -DPQCFUZZ_LEFT_PROJECT_ID="\"liboqs\"" \
      -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"${implementation}\"" \
      -DPQCFUZZ_EXPECTED_IMPLEMENTATION_ID="\"${implementation}\"" \
      -DPQCFUZZ_EXPECTED_ALGORITHM="\"${algorithm}\"" \
      -DPQCFUZZ_FIXED_ALGORITHM_ID="${algorithm_enum}" \
      -DPQCFUZZ_ALLOWED_ORACLE_IDS="\"${oracle_specs}\"" \
      -DPQCFUZZ_RIGHT_PROJECT_ID="\"liboqs_self_reference\"" \
      -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"${right_implementation}\"" \
      -DPQCFUZZ_PUBLIC_KEY_EXCHANGE=1 -DPQCFUZZ_CIPHERTEXT_EXCHANGE=1 \
      -DPQCFUZZ_SECRET_KEY_EXCHANGE=0 -DPQCFUZZ_SECRET_KEY_FORMAT_COMPATIBLE=0 \
      -DPQCFUZZ_SIGNATURE_EXCHANGE=1 \
      "$source" "${common_sources[@]}" "$liboqs_archive" \
      -lcrypto -ldl -lpthread -lm -o "${pqcfuzz_build_dir}/pqcfuzz_${job}"
  }

  build_target "mlkem512" kem "ML-KEM-512" "liboqs_mlkem512_wrapper_generic" src/fuzzers/kem_pair_fuzzer.cc 1 || return $?
  build_target "mlkem768" kem "ML-KEM-768" "liboqs_mlkem768_wrapper_generic" src/fuzzers/kem_pair_fuzzer.cc 2 || return $?
  build_target "mlkem1024" kem "ML-KEM-1024" "liboqs_mlkem1024_wrapper_generic" src/fuzzers/kem_pair_fuzzer.cc 3 || return $?
  build_target "mldsa44" sig "ML-DSA-44" "liboqs_mldsa44_wrapper_generic" src/fuzzers/sig_pair_fuzzer.cc 4 || return $?
  build_target "mldsa65" sig "ML-DSA-65" "liboqs_mldsa65_wrapper_generic" src/fuzzers/sig_pair_fuzzer.cc 5 || return $?
  build_target "mldsa87" sig "ML-DSA-87" "liboqs_mldsa87_wrapper_generic" src/fuzzers/sig_pair_fuzzer.cc 6 || return $?
}

run_fuzzer() {
  local target="$1"
  local seconds="$2"
  local binary="$3"
  local algorithm_enum="$4"
  local oracle_enum="$5"
  local run_root="${WORKSPACE_ROOT_ABS}/runs/${target}"
  local corpus_dir="${run_root}/corpus"
  local crash_dir="${WORKSPACE_ROOT_ABS}/crashes/${target}"
  local result_dir="${WORKSPACE_ROOT_ABS}/results/${target}"
  local log_file="${run_root}/fuzz-${target}.log"
  local summary_file="${run_root}/summary.json"
  local seed_file timeout_seconds preflight_status status asan_options ubsan_options msan_options sanitizer_summary
  local primitive algorithm preflight_log preflight_coverage

  mkdir -p "$corpus_dir" "$crash_dir" "$result_dir"
  IFS=$'\t' read -r primitive algorithm < <(target_metadata "$target") || return 1
  make_seed_corpus "$corpus_dir" "$target" "$algorithm_enum" "$primitive" || return $?
  seed_file="$(first_seed_in_corpus "$corpus_dir")"
  if [ -z "$seed_file" ]; then
    echo "no structured corpus seed generated for ${target}" >&2
    return 1
  fi

  echo "[pqcfuzz-eval] preflighting all ${primitive} oracles for ${target}"
  asan_options="${ASAN_OPTIONS:-}"
  ubsan_options="${UBSAN_OPTIONS:-}"
  msan_options="${MSAN_OPTIONS:-}"
  if has_sanitizer address; then
    asan_options="${asan_options:+${asan_options}:}detect_leaks=0:symbolize=1:external_symbolizer_path=${LLVM_SYMBOLIZER_PATH}"
  fi
  if has_sanitizer undefined; then
    ubsan_options="${ubsan_options:+${ubsan_options}:}print_stacktrace=1:symbolize=1"
  fi
  if has_sanitizer memory; then
    msan_options="${msan_options:+${msan_options}:}symbolize=1:external_symbolizer_path=${LLVM_SYMBOLIZER_PATH}"
  fi
  preflight_log="${run_root}/preflight-${target}.log"
  preflight_coverage="${run_root}/preflight-oracle-coverage.json"
  ASAN_OPTIONS="$asan_options" UBSAN_OPTIONS="$ubsan_options" MSAN_OPTIONS="$msan_options" LLVM_SYMBOLIZER_PATH="${LLVM_SYMBOLIZER_PATH:-}" \
    timeout "$((INPUT_TIMEOUT_SECONDS + 60))s" "$binary" "$corpus_dir" -runs=1 > >(tee "$preflight_log") 2>&1
  preflight_status="$?"
  if [ -f "${result_dir}/oracle_coverage.json" ]; then
    cp "${result_dir}/oracle_coverage.json" "$preflight_coverage"
  fi
  if [ "$preflight_status" -ne 0 ] || ! verify_oracle_coverage "$preflight_coverage" "$primitive"; then
    echo "oracle preflight failed for ${target}" >&2
    record_target_preflight "$target" "failed" "seeded oracle corpus did not satisfy the preflight contract"
    write_run_summary "$summary_file" "$target" 70 "$seconds" "$binary" "$preflight_log" "$crash_dir" "$corpus_dir" "$algorithm_enum" "$oracle_enum" "$result_dir" "$preflight_coverage"
    return 70
  fi
  record_target_preflight "$target" "passed" "preflight seed corpus produced a valid, evaluable, effective observation for every scheduled oracle"

  # This allocation is part of the campaign-wide fuzzing budget.  A very
  # small requested budget can legitimately leave later targets with no fuzz
  # time; they were nevertheless preflighted above so coverage is explicit.
  if [ "$seconds" -le 0 ]; then
    write_run_summary "$summary_file" "$target" 0 "$seconds" "$binary" "$preflight_log" "$crash_dir" "$corpus_dir" "$algorithm_enum" "$oracle_enum" "$result_dir" "$preflight_coverage"
    return 0
  fi

  timeout_seconds="$((seconds + INPUT_TIMEOUT_SECONDS + 60))"
  echo "[pqcfuzz-eval] running $target for ${seconds}s with every ${primitive} oracle seeded"
  ASAN_OPTIONS="$asan_options" UBSAN_OPTIONS="$ubsan_options" MSAN_OPTIONS="$msan_options" LLVM_SYMBOLIZER_PATH="${LLVM_SYMBOLIZER_PATH:-}" \
    timeout "${timeout_seconds}s" \
    "$binary" "$corpus_dir" \
    "-artifact_prefix=${crash_dir}/" \
    "-max_total_time=${seconds}" \
    "-timeout=${INPUT_TIMEOUT_SECONDS}" \
    "-rss_limit_mb=${RSS_MB}" \
    > >(tee "$log_file") 2>&1
  status="$?"
  sanitizer_summary="${run_root}/fuzz-sanitizer-findings.json"
  collect_sanitizer_findings "$target" "fuzz" "$log_file" "$result_dir" "$seed_file" "$binary" "$sanitizer_summary" || return $?
  write_replay_manifest "${run_root}/replay_manifest.json" "$target" "$result_dir"
  write_run_summary "$summary_file" "$target" "$status" "$seconds" "$binary" "$log_file" "$crash_dir" "$corpus_dir" "$algorithm_enum" "$oracle_enum" "$result_dir" "$preflight_coverage"
  if [ "$SANITIZER_FINDING_COUNT" -gt 0 ]; then
    return 0
  fi
  return "$status"
}

run_leak_check() {
  local target="$1"
  local binary="$2"
  local algorithm_enum="$3"
  local oracle_enum="$4"
  local run_root="${WORKSPACE_ROOT_ABS}/runs/${target}"
  local corpus_dir="${run_root}/corpus"
  local result_dir="${WORKSPACE_ROOT_ABS}/results/${target}"
  local log_file="${run_root}/leak-${target}.log"
  local summary_file="${run_root}/summary.json"
  local seed_file status sanitizer_summary asan_options ubsan_options primitive algorithm

  if [ "$LEAK_CHECK" = "off" ] || ! has_sanitizer address; then
    return 0
  fi
  mkdir -p "$corpus_dir" "$result_dir"
  IFS=$'\t' read -r primitive algorithm < <(target_metadata "$target") || return 1
  make_seed_corpus "$corpus_dir" "$target" "$algorithm_enum" "$primitive" || return $?
  seed_file="$(first_seed_in_corpus "$corpus_dir")"
  if [ -z "$seed_file" ]; then
    echo "no structured corpus seed generated for ${target}" >&2
    return 1
  fi
  echo "[pqcfuzz-eval] leak-checking every seeded ${primitive} oracle for ${target}"
  asan_options="${ASAN_OPTIONS:-}"
  ubsan_options="${UBSAN_OPTIONS:-}"
  asan_options="${asan_options:+${asan_options}:}detect_leaks=1:symbolize=1:external_symbolizer_path=${LLVM_SYMBOLIZER_PATH}"
  if has_sanitizer undefined; then
    ubsan_options="${ubsan_options:+${ubsan_options}:}print_stacktrace=1:symbolize=1"
  fi
  ASAN_OPTIONS="$asan_options" UBSAN_OPTIONS="$ubsan_options" LLVM_SYMBOLIZER_PATH="${LLVM_SYMBOLIZER_PATH:-}" \
    timeout "$((INPUT_TIMEOUT_SECONDS + 60))s" "$binary" "$corpus_dir" -runs=1 > >(tee "$log_file") 2>&1
  status="$?"
  sanitizer_summary="${run_root}/leak-sanitizer-findings.json"
  collect_sanitizer_findings "$target" "leak-check" "$log_file" "$result_dir" "$seed_file" "$binary" "$sanitizer_summary" || return $?
  refresh_sanitizer_summary "$summary_file" "$result_dir" || return $?
  write_replay_manifest "${run_root}/replay_manifest.json" "$target" "$result_dir"
  if [ "$SANITIZER_FINDING_COUNT" -gt 0 ]; then
    return 0
  fi
  return "$status"
}

run_mldsa_empty_context_regression() {
  local job enum binary run_root corpus_dir result_dir seed_file log_file status sanitizer_summary
  if [ "$VERSION" != "0.14.0" ] || ! has_sanitizer undefined; then
    return 0
  fi
  echo "[pqcfuzz-eval] running ML-DSA empty-context UBSan regression checks"
  for job_spec in "mldsa44:4" "mldsa65:5" "mldsa87:6"; do
    IFS=: read -r job enum <<<"$job_spec"
    binary="${PQCFUZZ_BUILD_DIR}/pqcfuzz_${job}"
    run_root="${WORKSPACE_ROOT_ABS}/runs/${job}"
    corpus_dir="${run_root}/corpus"
    result_dir="${WORKSPACE_ROOT_ABS}/results/${job}"
    seed_file="${corpus_dir}/seed-pqcfuzz-${job}.bin"
    log_file="${run_root}/regression-empty-context-${job}.log"
    mkdir -p "$corpus_dir" "$result_dir"
    if [ ! -f "$seed_file" ]; then
      make_seed "$seed_file" "$enum" "$SIG_ORACLE_ENUM"
    fi
    UBSAN_OPTIONS="${UBSAN_OPTIONS:+${UBSAN_OPTIONS}:}halt_on_error=1:print_stacktrace=1:symbolize=1" \
      LLVM_SYMBOLIZER_PATH="${LLVM_SYMBOLIZER_PATH:-}" timeout "$((INPUT_TIMEOUT_SECONDS + 60))s" "$binary" "$seed_file" -runs=1 > >(tee "$log_file") 2>&1
    status="$?"
    sanitizer_summary="${run_root}/regression-sanitizer-findings.json"
    collect_sanitizer_findings "$job" "regression" "$log_file" "$result_dir" "$seed_file" "$binary" "$sanitizer_summary" || return $?
    if [ "$status" -ne 0 ] || [ "$SANITIZER_FINDING_COUNT" -ne 0 ]; then
      echo "ML-DSA empty-context UBSan regression failed for ${job}" >&2
      return 1
    fi
  done
}

skip_fuzzer() {
  local target="$1"
  local seconds="$2"
  local binary="$3"
  local reason="$4"
  local run_root="${WORKSPACE_ROOT_ABS}/runs/${target}"
  local corpus_dir="${run_root}/corpus"
  local crash_dir="${WORKSPACE_ROOT_ABS}/crashes/${target}"
  local result_dir="${WORKSPACE_ROOT_ABS}/results/${target}"
  local log_file="${run_root}/fuzz-${target}.log"
  local summary_file="${run_root}/summary.json"

  mkdir -p "$corpus_dir" "$crash_dir" "$result_dir"
  {
    echo "[pqcfuzz-eval] skipping $target"
    echo "[pqcfuzz-eval] reason: $reason"
  } | tee "$log_file"
  write_skip_summary "$summary_file" "$target" "$seconds" "$binary" "$log_file" "$crash_dir" "$corpus_dir" "$reason"
  write_replay_manifest "${run_root}/replay_manifest.json" "$target" "$result_dir"
  return 0
}

if [ "${PQCFUZZ_EVAL_IN_DOCKER:-0}" != "1" ]; then
  echo "[pqcfuzz-eval] session: $SESSION_NAME"
  echo "[pqcfuzz-eval] campaign: $CAMPAIGN"
  echo "[pqcfuzz-eval] liboqs version: $VERSION"
  echo "[pqcfuzz-eval] fuzzing time: ${FUZZING_SECONDS}s"
  echo "[pqcfuzz-eval] workspace root: $WORKSPACE_ROOT_REL"
  echo "[pqcfuzz-eval] started: $STARTED_AT"
  echo "[pqcfuzz-eval] log: $LOG_FILE_ABS_HOST"
  echo "[pqcfuzz-eval] status: $STATUS_FILE_ABS_HOST"
  echo "[pqcfuzz-eval] relation mode: $RELATION_MODE"
  echo

  write_status "docker-build" "running"
  run_step docker build --network=host --build-arg "BASE_IMAGE=${BASE_IMAGE}" -t "$IMAGE_NAME" -f "$DOCKERFILE_REL" "$DOCKER_DIR_REL"
  DOCKER_BUILD_STATUS="$?"
  echo "[pqcfuzz-eval] docker-build exited with status $DOCKER_BUILD_STATUS"
  if [ "$DOCKER_BUILD_STATUS" -ne 0 ]; then
    finish_campaign "build-failed" "$DOCKER_BUILD_STATUS" "Docker image build failed"
  fi

  HOST_UID="$(id -u)"
  HOST_GID="$(id -g)"
  write_status "docker-run" "running"
  run_step docker run --rm \
    --network=host \
    -e PQCFUZZ_EVAL_IN_DOCKER=1 \
    -e EVAL_START_EPOCH="$START_EPOCH" \
    -e EVAL_STARTED_AT="$STARTED_AT" \
    -e DOCKER_BUILD_STATUS="$DOCKER_BUILD_STATUS" \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    -e EVAL_ROOT_REL="$EVAL_ROOT_REL" \
    -v "${HOST_ROOT_DIR}:${CONTAINER_ROOT_DIR}" \
    -w "$CONTAINER_ROOT_DIR" \
    "$IMAGE_NAME" \
    bash -lc 'trap "chown -R ${HOST_UID}:${HOST_GID} ${EVAL_ROOT_REL} 2>/dev/null || true" EXIT; bash "$@"' \
    bash "$LAUNCHER_FILE_REL"
  DOCKER_RUN_STATUS="$?"
  echo "[pqcfuzz-eval] docker-run exited with status $DOCKER_RUN_STATUS"
  if [ "$DOCKER_RUN_STATUS" -ne 0 ]; then
    if status_file_finished; then
      exit "$DOCKER_RUN_STATUS"
    fi
    finish_campaign "infrastructure-failed" "$DOCKER_RUN_STATUS" "Docker campaign container exited before writing a finished status"
  fi
  if status_file_finished; then
    exit 0
  fi
  finish_campaign "completed" 0
fi

echo "[pqcfuzz-eval] in Docker for campaign $CAMPAIGN"
echo "[pqcfuzz-eval] liboqs version: $VERSION"
echo "[pqcfuzz-eval] workspace root: $WORKSPACE_ROOT_ABS"
echo "[pqcfuzz-eval] relation mode: $RELATION_MODE"
if ! resolve_llvm_symbolizer; then
  finish_campaign "build-failed" 1 "llvm-symbolizer is unavailable for the selected sanitizer profile"
fi
if [ -n "${LLVM_SYMBOLIZER_PATH:-}" ]; then
  echo "[pqcfuzz-eval] llvm-symbolizer: $LLVM_SYMBOLIZER_PATH"
fi

BUILD_ROOT="${WORKSPACE_ROOT_ABS}/build/liboqs-${VERSION}"
PQCFUZZ_BUILD_DIR="${BUILD_ROOT}/pqcfuzz"

write_status "liboqs-build" "running"
build_liboqs "$BUILD_ROOT"
LIBOQS_BUILD_STATUS="$?"
echo "[pqcfuzz-eval] liboqs-build exited with status $LIBOQS_BUILD_STATUS"
if [ "$LIBOQS_BUILD_STATUS" -ne 0 ]; then
  finish_campaign "build-failed" "$LIBOQS_BUILD_STATUS" "liboqs configure/build failed or did not produce lib/liboqs.a"
fi

write_status "pqcfuzz-build" "running"
build_pqcfuzz "$BUILD_ROOT"
PQCFUZZ_BUILD_STATUS="$?"
echo "[pqcfuzz-eval] pqcfuzz-build exited with status $PQCFUZZ_BUILD_STATUS"
if [ "$PQCFUZZ_BUILD_STATUS" -ne 0 ]; then
  finish_campaign "build-failed" "$PQCFUZZ_BUILD_STATUS" "PQCFuzz target compilation failed"
fi

write_status "capability-manifest" "running"
CAPABILITY_MANIFEST="$(write_capability_manifest)"
echo "[pqcfuzz-eval] capability manifest: $CAPABILITY_MANIFEST"

KEM_ORACLE_ENUM=1
SIG_ORACLE_ENUM=5
if [ "$ORACLE_SUITE" = "metamorphic" ]; then
  KEM_ORACLE_ENUM=18
  SIG_ORACLE_ENUM=28
fi

active_target_count() {
  local target count=0
  for target in mlkem512 mlkem768 mlkem1024 mldsa44 mldsa65 mldsa87; do
    if [ "$(target_capability_state "$target")" = "comparable" ]; then
      count=$((count + 1))
    fi
  done
  printf '%s\n' "$count"
}

target_budget_seconds() {
  local ordinal="$1" count base remainder
  count="$(active_target_count)"
  base=$((FUZZING_SECONDS / count))
  remainder=$((FUZZING_SECONDS % count))
  if [ "$ordinal" -lt "$remainder" ]; then
    printf '%s\n' "$((base + 1))"
  else
    printf '%s\n' "$base"
  fi
}

write_status "regression-mldsa-empty-context" "running"
run_mldsa_empty_context_regression || finish_campaign "harness-error" "$?" "ML-DSA empty-context UBSan regression failed"

KEM_STATUS=0
SIG_STATUS=0
kem_budget_ordinal=0
for job_spec in "mlkem512:1" "mlkem768:2" "mlkem1024:3"; do
  IFS=: read -r job enum <<<"$job_spec"
  write_status "run-${job}" "running"
  if [ "$(target_capability_state "$job")" = "comparable" ]; then
    target_seconds="$(target_budget_seconds "$kem_budget_ordinal")"
    if [ "$PREFLIGHT_ONLY" -eq 1 ]; then target_seconds=0; fi
    run_fuzzer "$job" "$target_seconds" "${PQCFUZZ_BUILD_DIR}/pqcfuzz_${job}" "$enum" "$KEM_ORACLE_ENUM" || KEM_STATUS="$?"
    if [ "$PREFLIGHT_ONLY" -eq 0 ]; then
      run_leak_check "$job" "${PQCFUZZ_BUILD_DIR}/pqcfuzz_${job}" "$enum" "$KEM_ORACLE_ENUM" || KEM_STATUS="$?"
    fi
    kem_budget_ordinal=$((kem_budget_ordinal + 1))
  else
    skip_fuzzer "$job" 0 "${PQCFUZZ_BUILD_DIR}/pqcfuzz_${job}" "$(target_skip_reason "$job")"
  fi
done

sig_budget_ordinal="$kem_budget_ordinal"
for job_spec in "mldsa44:4" "mldsa65:5" "mldsa87:6"; do
  IFS=: read -r job enum <<<"$job_spec"
  write_status "run-${job}" "running"
  if [ "$(target_capability_state "$job")" = "comparable" ]; then
    target_seconds="$(target_budget_seconds "$sig_budget_ordinal")"
    if [ "$PREFLIGHT_ONLY" -eq 1 ]; then target_seconds=0; fi
    run_fuzzer "$job" "$target_seconds" "${PQCFUZZ_BUILD_DIR}/pqcfuzz_${job}" "$enum" "$SIG_ORACLE_ENUM" || SIG_STATUS="$?"
    if [ "$PREFLIGHT_ONLY" -eq 0 ]; then
      run_leak_check "$job" "${PQCFUZZ_BUILD_DIR}/pqcfuzz_${job}" "$enum" "$SIG_ORACLE_ENUM" || SIG_STATUS="$?"
    fi
    sig_budget_ordinal=$((sig_budget_ordinal + 1))
  else
    skip_fuzzer "$job" 0 "${PQCFUZZ_BUILD_DIR}/pqcfuzz_${job}" "$(target_skip_reason "$job")"
  fi
done

if [ "$KEM_STATUS" -ne 0 ]; then FUZZ_STATUS="$KEM_STATUS"; else FUZZ_STATUS="$SIG_STATUS"; fi

if [ "$FUZZ_STATUS" -ne 0 ]; then
  if [ "$FUZZ_STATUS" -eq 124 ]; then
    finish_campaign "timed-out" "$FUZZ_STATUS" "one or more per-algorithm fuzz jobs exceeded their wall-clock budget"
  fi
  finish_campaign "harness-error" "$FUZZ_STATUS" "one or more per-algorithm fuzz jobs exited nonzero"
fi

if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
  if find "${WORKSPACE_ROOT_ABS}/results" -name finding.json -print -quit | grep -q .; then
    finish_campaign "preflight-completed-with-findings" 0
  fi
  finish_campaign "preflight-completed" 0
fi

if find "${WORKSPACE_ROOT_ABS}/results" -name finding.json -print -quit | grep -q .; then
  finish_campaign "completed-with-findings" 0
fi
finish_campaign "completed" 0
EOF
  } > "$launcher_file"

  chmod +x "$launcher_file"
}

read_status_fields() {
  local status_file="$1"
  if [ ! -f "$status_file" ]; then
    printf 'pending\tpending\t0\t-\n'
    return
  fi

  python3 - "$status_file" <<'PY'
import json
import sys
import time

try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    print("unknown\tunknown\t0\t-")
    raise SystemExit

elapsed = data.get("elapsed_seconds") or 0
if data.get("state") != "finished" and data.get("start_epoch") is not None:
    try:
        elapsed = max(0, int(time.time()) - int(data["start_epoch"]))
    except Exception:
        pass

print(
    f"{data.get('phase') or '-'}\t"
    f"{data.get('state') or '-'}\t"
    f"{elapsed}\t"
    f"{data.get('result') or '-'}"
)
PY
}

print_progress() {
  local now="$1"
  local id status_file session phase state elapsed result tmux_state fields

  echo
  echo "[pqcfuzz-eval] progress: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%-20s %-16s %-10s %-6s %-18s\n' "campaign" "phase" "elapsed" "tmux" "status"
  printf '%-20s %-16s %-10s %-6s %-18s\n' "--------" "-----" "-------" "----" "------"

  for id in "${CAMPAIGN_IDS[@]}"; do
    status_file="${STATUS_FILE_ABS_BY_ID[$id]}"
    session="${SESSION_BY_ID[$id]}"
    fields="$(read_status_fields "$status_file")"
    IFS=$'\t' read -r phase state elapsed result <<<"$fields"

    if tmux has-session -t "=${session}" 2>/dev/null; then
      tmux_state="alive"
    else
      tmux_state="dead"
    fi

    if [ "$state" = "pending" ] && [ "$tmux_state" = "alive" ]; then
      phase="starting"
      state="running"
      elapsed=0
    elif [ "$state" != "finished" ] && [ "$tmux_state" = "dead" ]; then
      state="exited-no-status"
    elif [ "$state" = "finished" ]; then
      state="$result"
    fi

    printf '%-20s %-16s %-10s %-6s %-18s\n' \
      "$id" "$phase" "$(format_elapsed "$elapsed")" "$tmux_state" "$state"
  done
  echo "[pqcfuzz-eval] next progress report in ${PROGRESS_INTERVAL}s"
}

write_final_summary() {
  SANITIZERS="$SANITIZERS" LEAK_CHECK="$LEAK_CHECK" ORACLE_SET="$ORACLE_SET" python3 - "$INDEX_FILE" "$SUMMARY_JSON" "$SUMMARY_TSV" "$FUZZING_SECONDS" <<'PY'
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

index_file = Path(sys.argv[1])
summary_json = Path(sys.argv[2])
summary_tsv = Path(sys.argv[3])
fuzzing_seconds = int(sys.argv[4])

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def rel(path):
    try:
        return os.path.relpath(path)
    except ValueError:
        return str(path)

def artifact_counts(root):
    counts = {"crash": 0, "timeout": 0, "leak": 0, "oom": 0}
    if not root.is_dir():
        return counts
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name
        for prefix in counts:
            if name.startswith(prefix + "-"):
                counts[prefix] += 1
                break
    return counts

campaigns = []
with open(index_file, "r", encoding="utf-8", newline="") as f:
    reader = csv.DictReader(f, delimiter="\t")
    campaigns.extend(reader)

rows = []
overall_status = 0
for campaign in campaigns:
    status_path = Path(campaign["status_file_abs"])
    workspace_root = Path(campaign["workspace_root_abs"])
    status = load_json(status_path) or {}
    capability_manifest_path = workspace_root / "capabilities.json"
    capability_manifest = load_json(capability_manifest_path)
    run_summary_paths = sorted((workspace_root / "runs").rglob("summary.json")) if (workspace_root / "runs").is_dir() else []
    run_summaries = []
    for path in run_summary_paths:
        parsed = load_json(path)
        sanitizer_findings = parsed.get("sanitizer_findings") if isinstance(parsed, dict) else []
        if not isinstance(sanitizer_findings, list):
            sanitizer_findings = []
        run_summaries.append({
            "path": rel(path),
            "target": parsed.get("target") if isinstance(parsed, dict) else None,
            "status": parsed.get("status") if isinstance(parsed, dict) else None,
            "relation_mode": parsed.get("relation_mode") if isinstance(parsed, dict) else None,
            "skipped": parsed.get("skipped") if isinstance(parsed, dict) else None,
            "skip_reason": parsed.get("skip_reason") if isinstance(parsed, dict) else None,
            "state": parsed.get("state") if isinstance(parsed, dict) else None,
            "sanitizer_finding_count": parsed.get("sanitizer_finding_count", len(sanitizer_findings)) if isinstance(parsed, dict) else 0,
            "sanitizer_findings": sanitizer_findings,
            "scheduled_oracles": parsed.get("scheduled_oracles", []) if isinstance(parsed, dict) else [],
            "oracle_coverage": parsed.get("oracle_coverage", {}) if isinstance(parsed, dict) else {},
            "preflight_oracle_coverage": (
                parsed.get("preflight_oracle_coverage", parsed.get("oracle_coverage", {}))
                if isinstance(parsed, dict) else {}
            ),
            "fuzz_oracle_coverage": (
                parsed.get("fuzz_oracle_coverage", parsed.get("oracle_coverage", {}))
                if isinstance(parsed, dict) else {}
            ),
            "preflight_coverage_state": parsed.get("preflight_coverage_state", "not-run") if isinstance(parsed, dict) else "not-run",
            "preflight_uncovered_oracles": parsed.get("preflight_uncovered_oracles", []) if isinstance(parsed, dict) else [],
            "fuzz_effectiveness_state": parsed.get("fuzz_effectiveness_state", "not-run") if isinstance(parsed, dict) else "not-run",
            "fuzz_effectiveness_min_evaluable_rate": parsed.get("fuzz_effectiveness_min_evaluable_rate") if isinstance(parsed, dict) else None,
            "fuzz_effectiveness_by_oracle": parsed.get("fuzz_effectiveness_by_oracle", {}) if isinstance(parsed, dict) else {},
            "fuzz_effectiveness_failures": parsed.get("fuzz_effectiveness_failures", []) if isinstance(parsed, dict) else [],
            "oracle_coverage_state": (
                parsed.get("oracle_coverage_state", "passed" if parsed.get("oracle_coverage_complete") else "failed")
                if isinstance(parsed, dict) else "not-run"
            ),
            "oracle_coverage_complete": bool(parsed.get("oracle_coverage_complete", False)) if isinstance(parsed, dict) else False,
            "uncovered_oracles": parsed.get("uncovered_oracles", []) if isinstance(parsed, dict) else [],
        })

    counts = artifact_counts(workspace_root / "crashes")
    skipped_targets = sorted(
        item["target"]
        for item in run_summaries
        if item.get("skipped") and item.get("target")
    )
    sanitizer_findings = [
        finding
        for item in run_summaries
        for finding in item.get("sanitizer_findings", [])
        if isinstance(finding, dict)
    ]
    oracle_totals = {
        "inputs": 0,
        "parse_rejected": 0,
        "parsed": 0,
        "algorithm_rejected": 0,
        "routing_rejected": 0,
        "oracle_invocations": 0,
        "valid_setup": 0,
        "relation_evaluable": 0,
        "not_evaluable": 0,
        "intervention_effective": 0,
        "rng_intervention_observed": 0,
        "skipped": 0,
        "unsupported": 0,
        "finding_records": 0,
    }
    oracle_reason_totals = {"skipped_subtest_reasons": {}, "non_evaluable_reasons": {}}
    uncovered_oracles = []
    scheduled_oracle_count = 0
    covered_oracle_count = 0
    coverage_states = []
    preflight_coverage_states = []
    fuzz_effectiveness_states = []
    fuzz_effectiveness_failures = []
    for item in run_summaries:
        scheduled = item.get("scheduled_oracles") or []
        if scheduled:
            coverage_states.append(item.get("oracle_coverage_state") or "not-run")
            preflight_coverage_states.append(item.get("preflight_coverage_state") or "not-run")
            fuzz_effectiveness_states.append(item.get("fuzz_effectiveness_state") or "not-run")
        scheduled_oracle_count += len(scheduled)
        fuzz_coverage = item.get("fuzz_oracle_coverage") if isinstance(item.get("fuzz_oracle_coverage"), dict) else {}
        totals = fuzz_coverage.get("totals") if isinstance(fuzz_coverage.get("totals"), dict) else {}
        for key in oracle_totals:
            oracle_totals[key] += int(totals.get(key, 0) or 0)
        for reason_field, aggregate in oracle_reason_totals.items():
            reasons = totals.get(reason_field) if isinstance(totals.get(reason_field), dict) else {}
            for reason, count in reasons.items():
                aggregate[str(reason)] = aggregate.get(str(reason), 0) + int(count or 0)
        preflight_coverage = item.get("preflight_oracle_coverage") if isinstance(item.get("preflight_oracle_coverage"), dict) else {}
        oracle_map = preflight_coverage.get("oracles") if isinstance(preflight_coverage.get("oracles"), dict) else {}
        for scheduled_item in scheduled:
            oracle_id = scheduled_item.get("oracle_id") if isinstance(scheduled_item, dict) else None
            if oracle_id and int(oracle_map.get(oracle_id, {}).get("oracle_invocations", 0) or 0) > 0:
                covered_oracle_count += 1
        for oracle_id in item.get("uncovered_oracles") or []:
            uncovered_oracles.append({"target": item.get("target"), "oracle_id": oracle_id})
        for failure in item.get("fuzz_effectiveness_failures") or []:
            if isinstance(failure, dict):
                item_failure = dict(failure)
                item_failure["target"] = item.get("target")
                fuzz_effectiveness_failures.append(item_failure)
    if not preflight_coverage_states:
        preflight_coverage_state = "not-run"
    elif any(state != "passed" for state in preflight_coverage_states):
        preflight_coverage_state = "failed"
    else:
        preflight_coverage_state = "passed"
    preflight_only = bool(status.get("preflight_only", False))
    if not fuzz_effectiveness_states:
        fuzz_effectiveness_state = "not-run"
    elif preflight_only and all(state == "not-run" for state in fuzz_effectiveness_states):
        fuzz_effectiveness_state = "not-run"
    elif any(state != "passed" for state in fuzz_effectiveness_states):
        fuzz_effectiveness_state = "failed"
    else:
        fuzz_effectiveness_state = "passed"
    if not coverage_states:
        oracle_coverage_state = "not-run"
    elif uncovered_oracles or any(state != "passed" for state in coverage_states):
        oracle_coverage_state = "failed"
    else:
        oracle_coverage_state = "passed"
    sanitizer_counts = {"address": 0, "undefined": 0, "memory": 0, "leak": 0}
    for finding in sanitizer_findings:
        sanitizer = str(finding.get("sanitizer") or "")
        if sanitizer in sanitizer_counts:
            sanitizer_counts[sanitizer] += 1
        message = str(finding.get("message") or "").lower()
        if "leak" in message:
            sanitizer_counts["leak"] += 1
    final_status = status.get("final_status")
    result = status.get("result") or "missing-status"
    if sanitizer_findings and result == "completed":
        result = "completed-with-findings"
    aggregate_status = 1 if final_status is None else int(final_status)
    if aggregate_status == 0 and len(run_summaries) < 2:
        aggregate_status = 1
        result = "missing-run-summary"
    if aggregate_status == 0 and oracle_coverage_state != "passed":
        aggregate_status = 1
        result = "oracle-coverage-incomplete"
    if aggregate_status != 0:
        overall_status = 1

    row = {
        "campaign": campaign["campaign"],
        "version": campaign["version"],
        "session_name": campaign["session_name"],
        "workspace_root": campaign["workspace_root"],
        "started_at": status.get("started_at"),
        "ended_at": status.get("ended_at"),
        "elapsed_seconds": status.get("elapsed_seconds"),
        "docker_build_status": status.get("docker_build_status"),
        "docker_run_status": status.get("docker_run_status"),
        "liboqs_build_status": status.get("liboqs_build_status"),
        "pqcfuzz_build_status": status.get("pqcfuzz_build_status"),
        "fuzz_run_status": status.get("fuzz_status"),
        "kem_status": status.get("kem_status"),
        "sig_status": status.get("sig_status"),
        "final_status": final_status,
        "aggregate_status": aggregate_status,
        "result": result,
        "failure_reason": status.get("failure_reason"),
        "oracle_suite": status.get("oracle_suite") or os.environ.get("ORACLE_SUITE", "metamorphic"),
        "oracle_set": status.get("oracle_set") or os.environ.get("ORACLE_SET", "all"),
        "relation_mode": status.get("relation_mode") or os.environ.get("RELATION_MODE", "single-target"),
        "sanitizers": status.get("sanitizers") or os.environ.get("SANITIZERS", "address,undefined"),
        "leak_check": status.get("leak_check") or os.environ.get("LEAK_CHECK", "off"),
        "preflight_only": bool(status.get("preflight_only", False)),
        "skipped_families": status.get("skipped_families") or ["SLH-DSA"],
        "skipped_targets": skipped_targets,
        "log": campaign["log_file_abs"],
        "status_file": campaign["status_file_abs"],
        "capability_manifest": capability_manifest,
        "capability_manifest_path": rel(capability_manifest_path),
        "run_summaries": run_summaries,
        "preflight_coverage_state": preflight_coverage_state,
        "fuzz_effectiveness_state": fuzz_effectiveness_state,
        "fuzz_effectiveness_min_evaluable_rate": status.get("fuzz_effectiveness_min_evaluable_rate"),
        "fuzz_effectiveness_failures": fuzz_effectiveness_failures,
        "oracle_coverage_state": oracle_coverage_state,
        "oracle_coverage_complete": oracle_coverage_state == "passed",
        "scheduled_oracle_count": scheduled_oracle_count,
        "covered_oracle_count": covered_oracle_count,
        "uncovered_oracles": uncovered_oracles,
        "oracle_totals": oracle_totals,
        "oracle_reason_totals": oracle_reason_totals,
        "crash_count": counts["crash"],
        "timeout_count": counts["timeout"],
        "leak_count": counts["leak"],
        "oom_count": counts["oom"],
        "sanitizer_finding_count": len(sanitizer_findings),
        "address_sanitizer_count": sanitizer_counts["address"],
        "undefined_sanitizer_count": sanitizer_counts["undefined"],
        "memory_sanitizer_count": sanitizer_counts["memory"],
        "leak_sanitizer_count": sanitizer_counts["leak"],
    }
    rows.append(row)

summary = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "fuzzing_seconds": fuzzing_seconds,
    "overall_status": overall_status,
    "oracle_suite": os.environ.get("ORACLE_SUITE", "metamorphic"),
    "oracle_set": os.environ.get("ORACLE_SET", "all"),
    "relation_mode": os.environ.get("RELATION_MODE", "single-target"),
    "sanitizers": os.environ.get("SANITIZERS", "address,undefined"),
    "leak_check": os.environ.get("LEAK_CHECK", "off"),
    "skipped_families": ["SLH-DSA"],
    "campaigns": rows,
}

summary_json.parent.mkdir(parents=True, exist_ok=True)
with open(summary_json, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, sort_keys=True)
    f.write("\n")

columns = [
    "campaign",
    "version",
    "result",
    "failure_reason",
    "aggregate_status",
    "relation_mode",
    "sanitizers",
    "leak_check",
    "preflight_only",
    "preflight_coverage_state",
    "fuzz_effectiveness_state",
    "fuzz_effectiveness_min_evaluable_rate",
    "fuzz_effectiveness_failures",
    "oracle_coverage_state",
    "oracle_coverage_complete",
    "scheduled_oracle_count",
    "covered_oracle_count",
    "uncovered_oracles",
    "skipped_families",
    "skipped_targets",
    "docker_build_status",
    "docker_run_status",
    "liboqs_build_status",
    "pqcfuzz_build_status",
    "fuzz_run_status",
    "kem_status",
    "sig_status",
    "elapsed_seconds",
    "crash_count",
    "timeout_count",
    "leak_count",
    "oom_count",
    "sanitizer_finding_count",
    "address_sanitizer_count",
    "undefined_sanitizer_count",
    "memory_sanitizer_count",
    "leak_sanitizer_count",
    "log",
]
with open(summary_tsv, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, delimiter="\t", fieldnames=columns)
    writer.writeheader()
    for row in rows:
        out = {column: row.get(column) for column in columns}
        out["skipped_families"] = ",".join(row.get("skipped_families") or [])
        out["skipped_targets"] = ",".join(row.get("skipped_targets") or [])
        out["uncovered_oracles"] = ",".join(
            f"{item.get('target')}:{item.get('oracle_id')}" for item in row.get("uncovered_oracles") or []
        )
        out["fuzz_effectiveness_failures"] = ",".join(
            f"{item.get('target')}:{item.get('oracle_id')}:{item.get('reason')}:{float(item.get('evaluable_rate') or 0):.6f}"
            for item in row.get("fuzz_effectiveness_failures") or []
        )
        writer.writerow(out)

print(summary_json)
print(summary_tsv)
raise SystemExit(overall_status)
PY
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZING_TIME="24h"
PROGRESS_INTERVAL="3600"
SESSION_PREFIX="pqcfuzz"
EVAL_ROOT_REL="workspace/pqcfuzz_eval"
VERSIONS_CSV="0.14.0,0.8.0,0.4.0"
BASE_IMAGE="ubuntu:22.04"
ORACLE_SUITE="metamorphic"
ORACLE_SET="all"
RELATION_MODE="single-target"
TARGET_RUNTIME="liboqs"
SANITIZERS="address,undefined"
LEAK_CHECK="auto"
INPUT_TIMEOUT_SECONDS="30"
RSS_MB="2048"
REPORT_FORMATS="json,tsv"
REPORT_TIMEOUT="10m"
FINDING_SAVE_MODE="grouped"
MAX_FINDING_EXEMPLARS_PER_GROUP="1"
FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE="0.95"
PAIR_ALG="src/config/pair_alg.default.json"
DRY_RUN=0
PREFLIGHT_ONLY=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --fuzzing-time)
      if [ "$#" -lt 2 ]; then
        die "missing value for --fuzzing-time"
      fi
      FUZZING_TIME="$2"
      shift 2
      ;;
    --fuzzing-time=*)
      FUZZING_TIME="${1#--fuzzing-time=}"
      shift
      ;;
    --progress-interval)
      if [ "$#" -lt 2 ]; then
        die "missing value for --progress-interval"
      fi
      PROGRESS_INTERVAL="$2"
      shift 2
      ;;
    --progress-interval=*)
      PROGRESS_INTERVAL="${1#--progress-interval=}"
      shift
      ;;
    --session-prefix)
      if [ "$#" -lt 2 ]; then
        die "missing value for --session-prefix"
      fi
      SESSION_PREFIX="$2"
      shift 2
      ;;
    --session-prefix=*)
      SESSION_PREFIX="${1#--session-prefix=}"
      shift
      ;;
    --output-root)
      if [ "$#" -lt 2 ]; then
        die "missing value for --output-root"
      fi
      EVAL_ROOT_REL="$2"
      shift 2
      ;;
    --output-root=*)
      EVAL_ROOT_REL="${1#--output-root=}"
      shift
      ;;
    --versions)
      if [ "$#" -lt 2 ]; then
        die "missing value for --versions"
      fi
      VERSIONS_CSV="$2"
      shift 2
      ;;
    --versions=*)
      VERSIONS_CSV="${1#--versions=}"
      shift
      ;;
    --oracle-suite)
      if [ "$#" -lt 2 ]; then
        die "missing value for --oracle-suite"
      fi
      ORACLE_SUITE="$2"
      shift 2
      ;;
    --oracle-suite=*)
      ORACLE_SUITE="${1#--oracle-suite=}"
      shift
      ;;
    --oracle-set)
      if [ "$#" -lt 2 ]; then
        die "missing value for --oracle-set"
      fi
      ORACLE_SET="$2"
      shift 2
      ;;
    --oracle-set=*)
      ORACLE_SET="${1#--oracle-set=}"
      shift
      ;;
    --relation-mode)
      if [ "$#" -lt 2 ]; then
        die "missing value for --relation-mode"
      fi
      RELATION_MODE="$2"
      shift 2
      ;;
    --relation-mode=*)
      RELATION_MODE="${1#--relation-mode=}"
      shift
      ;;
    --target-runtime)
      if [ "$#" -lt 2 ]; then
        die "missing value for --target-runtime"
      fi
      TARGET_RUNTIME="$2"
      shift 2
      ;;
    --target-runtime=*)
      TARGET_RUNTIME="${1#--target-runtime=}"
      shift
      ;;
    --sanitizers)
      if [ "$#" -lt 2 ]; then
        die "missing value for --sanitizers"
      fi
      SANITIZERS="$2"
      shift 2
      ;;
    --sanitizers=*)
      SANITIZERS="${1#--sanitizers=}"
      shift
      ;;
    --leak-check)
      if [ "$#" -lt 2 ]; then
        die "missing value for --leak-check"
      fi
      LEAK_CHECK="$2"
      shift 2
      ;;
    --leak-check=*)
      LEAK_CHECK="${1#--leak-check=}"
      shift
      ;;
    --input-timeout-seconds)
      if [ "$#" -lt 2 ]; then
        die "missing value for --input-timeout-seconds"
      fi
      INPUT_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --input-timeout-seconds=*)
      INPUT_TIMEOUT_SECONDS="${1#--input-timeout-seconds=}"
      shift
      ;;
    --rss-mb)
      if [ "$#" -lt 2 ]; then
        die "missing value for --rss-mb"
      fi
      RSS_MB="$2"
      shift 2
      ;;
    --rss-mb=*)
      RSS_MB="${1#--rss-mb=}"
      shift
      ;;
    --report-formats)
      if [ "$#" -lt 2 ]; then
        die "missing value for --report-formats"
      fi
      REPORT_FORMATS="$2"
      shift 2
      ;;
    --report-formats=*)
      REPORT_FORMATS="${1#--report-formats=}"
      shift
      ;;
    --report-timeout)
      if [ "$#" -lt 2 ]; then
        die "missing value for --report-timeout"
      fi
      REPORT_TIMEOUT="$2"
      shift 2
      ;;
    --report-timeout=*)
      REPORT_TIMEOUT="${1#--report-timeout=}"
      shift
      ;;
    --finding-save-mode)
      if [ "$#" -lt 2 ]; then
        die "missing value for --finding-save-mode"
      fi
      FINDING_SAVE_MODE="$2"
      shift 2
      ;;
    --finding-save-mode=*)
      FINDING_SAVE_MODE="${1#--finding-save-mode=}"
      shift
      ;;
    --max-finding-exemplars-per-group)
      if [ "$#" -lt 2 ]; then
        die "missing value for --max-finding-exemplars-per-group"
      fi
      MAX_FINDING_EXEMPLARS_PER_GROUP="$2"
      shift 2
      ;;
    --max-finding-exemplars-per-group=*)
      MAX_FINDING_EXEMPLARS_PER_GROUP="${1#--max-finding-exemplars-per-group=}"
      shift
      ;;
    --fuzz-effectiveness-min-evaluable-rate)
      if [ "$#" -lt 2 ]; then
        die "missing value for --fuzz-effectiveness-min-evaluable-rate"
      fi
      FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE="$2"
      shift 2
      ;;
    --fuzz-effectiveness-min-evaluable-rate=*)
      FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE="${1#--fuzz-effectiveness-min-evaluable-rate=}"
      shift
      ;;
    --pair-alg)
      if [ "$#" -lt 2 ]; then
        die "missing value for --pair-alg"
      fi
      PAIR_ALG="$2"
      shift 2
      ;;
    --pair-alg=*)
      PAIR_ALG="${1#--pair-alg=}"
      shift
      ;;
    --base-image)
      if [ "$#" -lt 2 ]; then
        die "missing value for --base-image"
      fi
      BASE_IMAGE="$2"
      shift 2
      ;;
    --base-image=*)
      BASE_IMAGE="${1#--base-image=}"
      shift
      ;;
    --preflight-only)
      PREFLIGHT_ONLY=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option '$1'"
      ;;
  esac
done

case "$ORACLE_SUITE" in
  fips|metamorphic) ;;
  *) die "--oracle-suite must be fips or metamorphic" ;;
esac
case "$ORACLE_SET" in
  all|security) ;;
  *) die "--oracle-set must be all or security" ;;
esac
case "$RELATION_MODE" in
  single-liboqs) RELATION_MODE="single-target" ;;
  liboqs-vs-pqclean) RELATION_MODE="cross-implementation" ;;
esac
case "$RELATION_MODE" in
  single-target|self-reference|cross-implementation) ;;
  *) die "--relation-mode must be single-target, self-reference, or cross-implementation" ;;
esac
if [ "$TARGET_RUNTIME" != "liboqs" ]; then
  die "--target-runtime currently supports liboqs"
fi
SANITIZERS="$(normalize_sanitizers "$SANITIZERS")" || die "--sanitizers must be a nonempty combination of address, undefined, memory, or none; memory cannot be combined with address"
case "$LEAK_CHECK" in
  auto)
    if sanitizer_enabled address; then LEAK_CHECK="on"; else LEAK_CHECK="off"; fi
    ;;
  on|off) ;;
  *) die "--leak-check must be auto, on, or off" ;;
esac
if [ "$LEAK_CHECK" = "on" ] && ! sanitizer_enabled address; then
  die "--leak-check=on requires --sanitizers to include address"
fi
if [[ ! "$INPUT_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || [ "$INPUT_TIMEOUT_SECONDS" -le 0 ]; then
  die "--input-timeout-seconds must be a positive integer"
fi
if [[ ! "$RSS_MB" =~ ^[0-9]+$ ]] || [ "$RSS_MB" -le 0 ]; then
  die "--rss-mb must be a positive integer"
fi
case "$FINDING_SAVE_MODE" in
  grouped|all) ;;
  *) die "--finding-save-mode must be grouped or all" ;;
esac
if [[ ! "$MAX_FINDING_EXEMPLARS_PER_GROUP" =~ ^[0-9]+$ ]]; then
  die "--max-finding-exemplars-per-group must be a non-negative integer"
fi
if [ "$FINDING_SAVE_MODE" = "grouped" ] && [ "$MAX_FINDING_EXEMPLARS_PER_GROUP" -le 0 ]; then
  die "--max-finding-exemplars-per-group must be positive in grouped mode"
fi
if ! [[ "$FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE" =~ ^(0(\.[0-9]+)?|1(\.0+)?)$ ]]; then
  die "--fuzz-effectiveness-min-evaluable-rate must be between 0 and 1"
fi

validate_session_prefix "$SESSION_PREFIX"
validate_output_root "$EVAL_ROOT_REL"
FUZZING_SECONDS="$(parse_duration_seconds "$FUZZING_TIME")"
REPORT_TIMEOUT_SECONDS="$(parse_duration_seconds "$REPORT_TIMEOUT")"
if [[ ! "$PROGRESS_INTERVAL" =~ ^[0-9]+$ ]] || [ "$PROGRESS_INTERVAL" -le 0 ]; then
  die "--progress-interval must be a positive integer number of seconds"
fi

mapfile -t VERSIONS < <(parse_versions "$VERSIONS_CSV")

EVAL_ROOT="${ROOT_DIR}/${EVAL_ROOT_REL}"
CAMPAIGN_ROOT="${EVAL_ROOT}/campaigns"
LOG_DIR="${EVAL_ROOT}/logs"
LAUNCHER_DIR="${EVAL_ROOT}/launchers"
STATUS_DIR="${EVAL_ROOT}/status"
DOCKER_DIR_REL="${EVAL_ROOT_REL}/docker"
DOCKER_DIR="${ROOT_DIR}/${DOCKER_DIR_REL}"
DOCKERFILE_REL="${DOCKER_DIR_REL}/Dockerfile"
DOCKERFILE="${ROOT_DIR}/${DOCKERFILE_REL}"
INDEX_FILE="${STATUS_DIR}/campaigns.tsv"
SUMMARY_JSON="${EVAL_ROOT}/summary.json"
SUMMARY_TSV="${EVAL_ROOT}/summary.tsv"

declare -a CAMPAIGN_IDS=()
declare -A VERSION_BY_ID
declare -A SESSION_BY_ID
declare -A WORKSPACE_REL_BY_ID
declare -A WORKSPACE_ABS_BY_ID
declare -A LOG_FILE_REL_BY_ID
declare -A LOG_FILE_ABS_BY_ID
declare -A LAUNCHER_FILE_BY_ID
declare -A STATUS_FILE_REL_BY_ID
declare -A STATUS_FILE_ABS_BY_ID

for version in "${VERSIONS[@]}"; do
  safe="$(safe_version "$version")"
  campaign="liboqs-${version}"
  session_name="${SESSION_PREFIX}-liboqs-${safe}"
  workspace_root_rel="${EVAL_ROOT_REL}/campaigns/${campaign}/workspace"
  workspace_root_abs="${ROOT_DIR}/${workspace_root_rel}"
  log_file_rel="${EVAL_ROOT_REL}/logs/${campaign}.log"
  log_file_abs="${ROOT_DIR}/${log_file_rel}"
  launcher_file="${LAUNCHER_DIR}/${campaign}.sh"
  status_file_rel="${EVAL_ROOT_REL}/status/${campaign}.json"
  status_file_abs="${ROOT_DIR}/${status_file_rel}"

  CAMPAIGN_IDS+=("$campaign")
  VERSION_BY_ID["$campaign"]="$version"
  SESSION_BY_ID["$campaign"]="$session_name"
  WORKSPACE_REL_BY_ID["$campaign"]="$workspace_root_rel"
  WORKSPACE_ABS_BY_ID["$campaign"]="$workspace_root_abs"
  LOG_FILE_REL_BY_ID["$campaign"]="$log_file_rel"
  LOG_FILE_ABS_BY_ID["$campaign"]="$log_file_abs"
  LAUNCHER_FILE_BY_ID["$campaign"]="$launcher_file"
  STATUS_FILE_REL_BY_ID["$campaign"]="$status_file_rel"
  STATUS_FILE_ABS_BY_ID["$campaign"]="$status_file_abs"
done

echo "[pqcfuzz-eval] repository: $ROOT_DIR"
echo "[pqcfuzz-eval] output root: $EVAL_ROOT"
echo "[pqcfuzz-eval] fuzzing time: ${FUZZING_SECONDS}s"
echo "[pqcfuzz-eval] progress interval: ${PROGRESS_INTERVAL}s"
echo "[pqcfuzz-eval] session prefix: $SESSION_PREFIX"
echo "[pqcfuzz-eval] versions: ${VERSIONS[*]}"
echo "[pqcfuzz-eval] base image: $BASE_IMAGE"
echo "[pqcfuzz-eval] oracle_suite: $ORACLE_SUITE"
echo "[pqcfuzz-eval] oracle_set: $ORACLE_SET"
echo "[pqcfuzz-eval] relation_mode: $RELATION_MODE"
echo "[pqcfuzz-eval] target_runtime: $TARGET_RUNTIME"
echo "[pqcfuzz-eval] sanitizers: $SANITIZERS"
echo "[pqcfuzz-eval] leak check: $LEAK_CHECK"
echo "[pqcfuzz-eval] input timeout: ${INPUT_TIMEOUT_SECONDS}s"
echo "[pqcfuzz-eval] rss mb: $RSS_MB"
echo "[pqcfuzz-eval] report formats: $REPORT_FORMATS"
echo "[pqcfuzz-eval] report timeout: ${REPORT_TIMEOUT_SECONDS}s"
echo "[pqcfuzz-eval] finding save mode: $FINDING_SAVE_MODE"
echo "[pqcfuzz-eval] max finding exemplars per group: $MAX_FINDING_EXEMPLARS_PER_GROUP"
echo "[pqcfuzz-eval] fuzz effectiveness min evaluable rate: $FUZZ_EFFECTIVENESS_MIN_EVALUABLE_RATE"
echo "[pqcfuzz-eval] skipped families: SLH-DSA"
echo "[pqcfuzz-eval] preflight only: $PREFLIGHT_ONLY"
echo "[pqcfuzz-eval] dry run: $DRY_RUN"
echo

if [ "$DRY_RUN" -eq 1 ]; then
  for campaign in "${CAMPAIGN_IDS[@]}"; do
    version="${VERSION_BY_ID[$campaign]}"
    echo "[dry-run] campaign: $campaign"
    echo "[dry-run] session: ${SESSION_BY_ID[$campaign]}"
    echo "[dry-run] workspace: ${WORKSPACE_REL_BY_ID[$campaign]}"
    echo "[dry-run] log: ${LOG_FILE_ABS_BY_ID[$campaign]}"
    echo "[dry-run] status: ${STATUS_FILE_ABS_BY_ID[$campaign]}"
    print_campaign_commands "$version" "$FUZZING_SECONDS" "${WORKSPACE_REL_BY_ID[$campaign]}" |
      sed 's/^/[dry-run] command: /'
    echo
  done
  exit 0
fi

command -v tmux >/dev/null 2>&1 || die "tmux is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
command -v docker >/dev/null 2>&1 || die "docker is required"

if ! docker info >/dev/null 2>&1; then
  die "Docker is installed, but the Docker daemon is not available to this user"
fi

if [ ! -d "${ROOT_DIR}/src" ]; then
  die "missing src/ tree"
fi

CONFLICTS=0
for campaign in "${CAMPAIGN_IDS[@]}"; do
  if tmux has-session -t "=${SESSION_BY_ID[$campaign]}" 2>/dev/null; then
    echo "[pqcfuzz-eval] session already exists: ${SESSION_BY_ID[$campaign]}" >&2
    echo "[pqcfuzz-eval] stop it first with: tmux kill-session -t ${SESSION_BY_ID[$campaign]}" >&2
    CONFLICTS=1
  fi
done
if [ "$CONFLICTS" -ne 0 ]; then
  exit 2
fi

archive_existing_eval_root
mkdir -p "$CAMPAIGN_ROOT" "$LOG_DIR" "$LAUNCHER_DIR" "$STATUS_DIR"
write_dockerfile

{
  printf 'campaign\tversion\tsession_name\tworkspace_root\tworkspace_root_abs\tlog_file\tlog_file_abs\tstatus_file\tstatus_file_abs\n'
  for campaign in "${CAMPAIGN_IDS[@]}"; do
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$campaign" \
      "${VERSION_BY_ID[$campaign]}" \
      "${SESSION_BY_ID[$campaign]}" \
      "${WORKSPACE_REL_BY_ID[$campaign]}" \
      "${WORKSPACE_ABS_BY_ID[$campaign]}" \
      "${LOG_FILE_REL_BY_ID[$campaign]}" \
      "${LOG_FILE_ABS_BY_ID[$campaign]}" \
      "${STATUS_FILE_REL_BY_ID[$campaign]}" \
      "${STATUS_FILE_ABS_BY_ID[$campaign]}"
  done
} > "$INDEX_FILE"

START_FAILURE=0
for campaign in "${CAMPAIGN_IDS[@]}"; do
  write_launcher \
    "${LAUNCHER_FILE_BY_ID[$campaign]}" \
    "${VERSION_BY_ID[$campaign]}" \
    "$campaign" \
    "${SESSION_BY_ID[$campaign]}" \
    "${WORKSPACE_REL_BY_ID[$campaign]}" \
    "${WORKSPACE_ABS_BY_ID[$campaign]}" \
    "${LOG_FILE_REL_BY_ID[$campaign]}" \
    "${LOG_FILE_ABS_BY_ID[$campaign]}" \
    "${STATUS_FILE_REL_BY_ID[$campaign]}" \
    "${STATUS_FILE_ABS_BY_ID[$campaign]}" \
    "$FUZZING_SECONDS"

  # The launcher is generated from nested Bash/Python heredocs.  Parse the
  # generated artifact before tmux starts it so a template error is reported
  # synchronously instead of looking like a campaign that vanished.
  if ! bash -n "${LAUNCHER_FILE_BY_ID[$campaign]}"; then
    echo "[pqcfuzz-eval] generated launcher failed syntax validation: ${LAUNCHER_FILE_BY_ID[$campaign]}" >&2
    START_FAILURE=1
    continue
  fi

  if tmux new-session -d -s "${SESSION_BY_ID[$campaign]}" -c "$ROOT_DIR" "${LAUNCHER_FILE_BY_ID[$campaign]}"; then
    echo "[pqcfuzz-eval] started: ${SESSION_BY_ID[$campaign]}"
    echo "[pqcfuzz-eval] campaign: $campaign"
    echo "[pqcfuzz-eval] log: ${LOG_FILE_ABS_BY_ID[$campaign]}"
    echo
  else
    echo "[pqcfuzz-eval] failed to start tmux session: ${SESSION_BY_ID[$campaign]}" >&2
    START_FAILURE=1
  fi
done

LAST_PROGRESS=0
SLEEP_SECONDS=5
if [ "$PROGRESS_INTERVAL" -lt "$SLEEP_SECONDS" ]; then
  SLEEP_SECONDS="$PROGRESS_INTERVAL"
fi

while :; do
  now="$(date +%s)"
  if [ $((now - LAST_PROGRESS)) -ge "$PROGRESS_INTERVAL" ]; then
    print_progress "$now"
    LAST_PROGRESS="$now"
  fi

  remaining=0
  for campaign in "${CAMPAIGN_IDS[@]}"; do
    session="${SESSION_BY_ID[$campaign]}"
    status_file="${STATUS_FILE_ABS_BY_ID[$campaign]}"
    fields="$(read_status_fields "$status_file")"
    IFS=$'\t' read -r phase state elapsed result <<<"$fields"

    if [ "$state" = "finished" ]; then
      if tmux has-session -t "=${session}" 2>/dev/null; then
        tmux kill-session -t "=${session}" 2>/dev/null || true
      fi
      continue
    fi

    if tmux has-session -t "=${session}" 2>/dev/null; then
      remaining=$((remaining + 1))
    fi
  done

  if [ "$remaining" -eq 0 ]; then
    break
  fi

  sleep "$SLEEP_SECONDS"
done

print_progress "$(date +%s)"

echo
echo "[pqcfuzz-eval] writing final summaries"
set +e
SUMMARY_OUTPUT="$(write_final_summary)"
SUMMARY_STATUS="$?"
set -e
echo "$SUMMARY_OUTPUT"
declare -a REPORT_INPUT_ARGS=()
for campaign in "${CAMPAIGN_IDS[@]}"; do
  result_root="${WORKSPACE_ABS_BY_ID[$campaign]}/results"
  if [ -d "$result_root" ]; then
    REPORT_INPUT_ARGS+=(--input-root "$result_root")
  fi
done

REPORT_STATUS=0
if [ "${#REPORT_INPUT_ARGS[@]}" -gt 0 ]; then
  echo "[pqcfuzz-eval] writing finding reports"
  set +e
  if command -v timeout >/dev/null 2>&1; then
    timeout "$REPORT_TIMEOUT_SECONDS" python3 src/reporting/write_report.py \
      "${REPORT_INPUT_ARGS[@]}" \
      --output-root "$EVAL_ROOT" \
      --formats "$REPORT_FORMATS" \
      --trace-mode exemplar \
      --findings-mode fast-summary
  else
    python3 src/reporting/write_report.py \
      "${REPORT_INPUT_ARGS[@]}" \
      --output-root "$EVAL_ROOT" \
      --formats "$REPORT_FORMATS" \
      --trace-mode exemplar \
      --findings-mode fast-summary
  fi
  REPORT_STATUS="$?"
  set -e
  if [ "$REPORT_STATUS" -ne 0 ]; then
    echo "[pqcfuzz-eval] finding report generation failed with status $REPORT_STATUS" >&2
  fi
else
  echo "[pqcfuzz-eval] no finding result directories found; skipping finding reports"
fi

if [ "$START_FAILURE" -ne 0 ] && [ "$SUMMARY_STATUS" -eq 0 ]; then
  SUMMARY_STATUS=1
fi
if [ "$REPORT_STATUS" -ne 0 ] && [ "$SUMMARY_STATUS" -eq 0 ]; then
  SUMMARY_STATUS="$REPORT_STATUS"
fi

if [ "$SUMMARY_STATUS" -eq 0 ]; then
  echo "[pqcfuzz-eval] all campaigns completed successfully"
else
  echo "[pqcfuzz-eval] one or more campaigns failed; see $SUMMARY_JSON" >&2
fi

exit "$SUMMARY_STATUS"

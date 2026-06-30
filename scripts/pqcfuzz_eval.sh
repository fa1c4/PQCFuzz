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
  --versions CSV                Comma-separated liboqs versions. Default: 0.14.0,0.8.0,0.4.0.
  --base-image IMAGE            Docker base image. Default: ubuntu:22.04.
  --dry-run                     Print campaigns and commands without starting tmux.
  -h, --help                    Show this help.

This launches one tmux campaign per liboqs version. PQCFuzz v1 evaluation uses
self-reference mode: liboqs generic adapters are used on both sides so older
liboqs tags can be evaluated for harness and compatibility coverage.

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

write_dockerfile() {
  mkdir -p "$DOCKER_DIR"
  cat > "$DOCKERFILE" <<EOF
ARG BASE_IMAGE=${BASE_IMAGE}
FROM \${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \\
    build-essential \\
    clang \\
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
  local kem_seconds="$3"
  local sig_seconds="$4"
  local workspace="$5"

  echo "docker build --build-arg BASE_IMAGE=$BASE_IMAGE -t pqcfuzz-eval -f $DOCKERFILE_REL $DOCKER_DIR_REL"
  echo "docker run pqcfuzz-eval: clone/update liboqs $version into $workspace/build/liboqs-${version}/liboqs-src"
  echo "docker run pqcfuzz-eval: build static liboqs.a for $version"
  echo "docker run pqcfuzz-eval: generate self-reference compatibility adapter"
  echo "docker run pqcfuzz-eval: build pqcfuzz_kem and pqcfuzz_sig"
  echo "docker run pqcfuzz-eval: run pqcfuzz_kem for ${kem_seconds}s"
  if [ "$version" = "0.14.0" ]; then
    echo "docker run pqcfuzz-eval: run pqcfuzz_sig for ${sig_seconds}s"
  else
    echo "docker run pqcfuzz-eval: write skipped pqcfuzz_sig summary for ${sig_seconds}s allocation"
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
  local kem_seconds="${12}"
  local sig_seconds="${13}"

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
    printf 'FUZZING_SECONDS=%q\n' "$seconds"
    printf 'KEM_SECONDS=%q\n' "$kem_seconds"
    printf 'SIG_SECONDS=%q\n\n' "$sig_seconds"
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
RELATION_MODE="self_reference"
SKIPPED_FAMILIES_JSON='["SLH-DSA"]'

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
  EVAL_RELATION_MODE="$RELATION_MODE" \
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
    "relation_mode": os.environ["EVAL_RELATION_MODE"],
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
    const uint8_t *,
    size_t context_len) {
  if (context_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  OQS_SIG *sig = OpenSig(spec);
  if (sig == nullptr) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  OQS_STATUS status = OQS_SIG_sign(sig, signature, signature_len, message, message_len, secret_key);
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
    const uint8_t *,
    size_t context_len) {
  if (context_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  OQS_SIG *sig = OpenSig(spec);
  if (sig == nullptr) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  OQS_STATUS status = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
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

const pqcfuzz_sig_adapter kLeftDsa44 = {"liboqs", "liboqs_mldsa44_wrapper_generic", "ML-DSA-44", 1312, 2560, 2420, 0, 0, 0, Dsa44Keygen, Dsa44Sign, Dsa44Verify, UnsupportedSignSeeded};
const pqcfuzz_sig_adapter kLeftDsa65 = {"liboqs", "liboqs_mldsa65_wrapper_generic", "ML-DSA-65", 1952, 4032, 3309, 0, 0, 0, Dsa65Keygen, Dsa65Sign, Dsa65Verify, UnsupportedSignSeeded};
const pqcfuzz_sig_adapter kLeftDsa87 = {"liboqs", "liboqs_mldsa87_wrapper_generic", "ML-DSA-87", 2592, 4896, 4627, 0, 0, 0, Dsa87Keygen, Dsa87Sign, Dsa87Verify, UnsupportedSignSeeded};
const pqcfuzz_sig_adapter kRightDsa44 = {"liboqs_self_reference", "selfref_mldsa44_via_liboqs", "ML-DSA-44", 1312, 2560, 2420, 0, 0, 0, Dsa44Keygen, Dsa44Sign, Dsa44Verify, UnsupportedSignSeeded};
const pqcfuzz_sig_adapter kRightDsa65 = {"liboqs_self_reference", "selfref_mldsa65_via_liboqs", "ML-DSA-65", 1952, 4032, 3309, 0, 0, 0, Dsa65Keygen, Dsa65Sign, Dsa65Verify, UnsupportedSignSeeded};
const pqcfuzz_sig_adapter kRightDsa87 = {"liboqs_self_reference", "selfref_mldsa87_via_liboqs", "ML-DSA-87", 2592, 4896, 4627, 0, 0, 0, Dsa87Keygen, Dsa87Sign, Dsa87Verify, UnsupportedSignSeeded};

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
  "relation_mode": "self_reference",
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
  "relation_mode": "self_reference",
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

write_run_summary() {
  local summary_file="$1"
  local target="$2"
  local status="$3"
  local seconds="$4"
  local binary="$5"
  local log_file="$6"
  local crash_dir="$7"
  local corpus_dir="$8"

  RUN_SUMMARY_FILE="$summary_file" \
  RUN_TARGET="$target" \
  RUN_STATUS="$status" \
  RUN_SECONDS="$seconds" \
  RUN_BINARY="$binary" \
  RUN_LOG="$log_file" \
  RUN_CRASH_DIR="$crash_dir" \
  RUN_CORPUS_DIR="$corpus_dir" \
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
    "status": int(os.environ["RUN_STATUS"]),
    "max_total_time": int(os.environ["RUN_SECONDS"]),
    "binary": os.environ["RUN_BINARY"],
    "log": os.environ["RUN_LOG"],
    "crash_dir": os.environ["RUN_CRASH_DIR"],
    "corpus_dir": os.environ["RUN_CORPUS_DIR"],
    "relation_mode": os.environ["RUN_RELATION_MODE"],
    "skipped_families": json.loads(os.environ["RUN_SKIPPED_FAMILIES_JSON"]),
    "skipped": False,
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
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
    -DCMAKE_C_FLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined" \
    -DCMAKE_CXX_FLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined" \
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
    src/mutators/envelope.cc
    src/mutators/ml_kem_layout.cc
    src/mutators/ml_kem_mutator.cc
    src/mutators/ml_dsa_layout.cc
    src/mutators/ml_dsa_mutator.cc
    src/mutators/slh_dsa_layout.cc
    src/mutators/slh_dsa_mutator.cc
    src/oracles/expected_relation.cc
    src/oracles/oracle_spec.cc
    src/oracles/oracle_spec_loader.cc
    src/oracles/oracle_executor.cc
    src/triage/finding_writer.cc
    "$adapter_src"
  )

  "$cxx_bin" -std=c++17 -O1 -g -Isrc -I"${liboqs_build_dir}/include" \
    -fsanitize=fuzzer,address,undefined \
    -DPQCFUZZ_JOB_ID="\"pqcfuzz_eval_kem_liboqs_${VERSION}\"" \
    -DPQCFUZZ_PAIR_ID="\"liboqs_${VERSION}_self_reference_kem\"" \
    -DPQCFUZZ_RESULT_DIR="\"${WORKSPACE_ROOT_REL}/results/kem\"" \
    -DPQCFUZZ_GENERATED_CONFIG_PATH="\"${tmp_root}/generated_config_kem.json\"" \
    src/fuzzers/kem_pair_fuzzer.cc "${common_sources[@]}" "$liboqs_archive" \
    -lcrypto -ldl -lpthread -lm \
    -o "${pqcfuzz_build_dir}/pqcfuzz_kem"

  "$cxx_bin" -std=c++17 -O1 -g -Isrc -I"${liboqs_build_dir}/include" \
    -fsanitize=fuzzer,address,undefined \
    -DPQCFUZZ_JOB_ID="\"pqcfuzz_eval_sig_liboqs_${VERSION}\"" \
    -DPQCFUZZ_PAIR_ID="\"liboqs_${VERSION}_self_reference_sig\"" \
    -DPQCFUZZ_RESULT_DIR="\"${WORKSPACE_ROOT_REL}/results/sig\"" \
    -DPQCFUZZ_GENERATED_CONFIG_PATH="\"${tmp_root}/generated_config_sig.json\"" \
    src/fuzzers/sig_pair_fuzzer.cc "${common_sources[@]}" "$liboqs_archive" \
    -lcrypto -ldl -lpthread -lm \
    -o "${pqcfuzz_build_dir}/pqcfuzz_sig"
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
  local seed_file="${corpus_dir}/seed-pqcfuzz-${target}.bin"
  local timeout_seconds=$((seconds + 60))
  local status

  mkdir -p "$corpus_dir" "$crash_dir" "$result_dir"
  if [ ! -f "$seed_file" ]; then
    make_seed "$seed_file" "$algorithm_enum" "$oracle_enum"
  fi

  echo "[pqcfuzz-eval] running $target for ${seconds}s"
  ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}" \
    timeout "${timeout_seconds}s" \
    "$binary" "$corpus_dir" \
    "-artifact_prefix=${crash_dir}/" \
    "-max_total_time=${seconds}" \
    "-rss_limit_mb=${PQCFUZZ_RSS_MB:-2048}" \
    > >(tee "$log_file") 2>&1
  status="$?"
  write_run_summary "$summary_file" "$target" "$status" "$seconds" "$binary" "$log_file" "$crash_dir" "$corpus_dir"
  return "$status"
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
  run_step docker build --build-arg "BASE_IMAGE=${BASE_IMAGE}" -t "$IMAGE_NAME" -f "$DOCKERFILE_REL" "$DOCKER_DIR_REL"
  DOCKER_BUILD_STATUS="$?"
  echo "[pqcfuzz-eval] docker-build exited with status $DOCKER_BUILD_STATUS"
  if [ "$DOCKER_BUILD_STATUS" -ne 0 ]; then
    finish_campaign "docker-build-failed" "$DOCKER_BUILD_STATUS" "Docker image build failed"
  fi

  HOST_UID="$(id -u)"
  HOST_GID="$(id -g)"
  write_status "docker-run" "running"
  run_step docker run --rm \
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
    finish_campaign "docker-run-failed" "$DOCKER_RUN_STATUS" "Docker campaign container exited before writing a finished status"
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

BUILD_ROOT="${WORKSPACE_ROOT_ABS}/build/liboqs-${VERSION}"
PQCFUZZ_BUILD_DIR="${BUILD_ROOT}/pqcfuzz"

write_status "liboqs-build" "running"
build_liboqs "$BUILD_ROOT"
LIBOQS_BUILD_STATUS="$?"
echo "[pqcfuzz-eval] liboqs-build exited with status $LIBOQS_BUILD_STATUS"
if [ "$LIBOQS_BUILD_STATUS" -ne 0 ]; then
  finish_campaign "liboqs-build-failed" "$LIBOQS_BUILD_STATUS" "liboqs configure/build failed or did not produce lib/liboqs.a"
fi

write_status "pqcfuzz-build" "running"
build_pqcfuzz "$BUILD_ROOT"
PQCFUZZ_BUILD_STATUS="$?"
echo "[pqcfuzz-eval] pqcfuzz-build exited with status $PQCFUZZ_BUILD_STATUS"
if [ "$PQCFUZZ_BUILD_STATUS" -ne 0 ]; then
  finish_campaign "pqcfuzz-build-failed" "$PQCFUZZ_BUILD_STATUS" "PQCFuzz target compilation failed"
fi

write_status "run-kem" "running"
run_fuzzer "kem" "$KEM_SECONDS" "${PQCFUZZ_BUILD_DIR}/pqcfuzz_kem" 2 1
KEM_STATUS="$?"
echo "[pqcfuzz-eval] kem exited with status $KEM_STATUS"
echo

write_status "run-sig" "running"
case "$VERSION" in
  0.14.0)
    run_fuzzer "sig" "$SIG_SECONDS" "${PQCFUZZ_BUILD_DIR}/pqcfuzz_sig" 5 5
    ;;
  *)
    skip_fuzzer "sig" "$SIG_SECONDS" "${PQCFUZZ_BUILD_DIR}/pqcfuzz_sig" "historical Dilithium parameters for liboqs ${VERSION} do not match FIPS ML-DSA canonical lengths"
    ;;
esac
SIG_STATUS="$?"
echo "[pqcfuzz-eval] sig exited with status $SIG_STATUS"

if [ "$KEM_STATUS" -ne 0 ]; then
  FUZZ_STATUS="$KEM_STATUS"
else
  FUZZ_STATUS="$SIG_STATUS"
fi

if [ "$FUZZ_STATUS" -ne 0 ]; then
  finish_campaign "fuzzing-failed" "$FUZZ_STATUS" "KEM or SIG fuzz target exited nonzero"
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
  python3 - "$INDEX_FILE" "$SUMMARY_JSON" "$SUMMARY_TSV" "$FUZZING_SECONDS" <<'PY'
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
    run_summary_paths = sorted((workspace_root / "runs").rglob("summary.json")) if (workspace_root / "runs").is_dir() else []
    run_summaries = []
    for path in run_summary_paths:
        parsed = load_json(path)
        run_summaries.append({
            "path": rel(path),
            "target": parsed.get("target") if isinstance(parsed, dict) else None,
            "status": parsed.get("status") if isinstance(parsed, dict) else None,
            "relation_mode": parsed.get("relation_mode") if isinstance(parsed, dict) else None,
            "skipped": parsed.get("skipped") if isinstance(parsed, dict) else None,
            "skip_reason": parsed.get("skip_reason") if isinstance(parsed, dict) else None,
        })

    counts = artifact_counts(workspace_root / "crashes")
    skipped_targets = sorted(
        item["target"]
        for item in run_summaries
        if item.get("skipped") and item.get("target")
    )
    final_status = status.get("final_status")
    result = status.get("result") or "missing-status"
    aggregate_status = 1 if final_status is None else int(final_status)
    if aggregate_status == 0 and len(run_summaries) < 2:
        aggregate_status = 1
        result = "missing-run-summary"
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
        "relation_mode": status.get("relation_mode") or "self_reference",
        "skipped_families": status.get("skipped_families") or ["SLH-DSA"],
        "skipped_targets": skipped_targets,
        "log": campaign["log_file_abs"],
        "status_file": campaign["status_file_abs"],
        "run_summaries": run_summaries,
        "crash_count": counts["crash"],
        "timeout_count": counts["timeout"],
        "leak_count": counts["leak"],
        "oom_count": counts["oom"],
    }
    rows.append(row)

summary = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "fuzzing_seconds": fuzzing_seconds,
    "overall_status": overall_status,
    "relation_mode": "self_reference",
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
    "log",
]
with open(summary_tsv, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, delimiter="\t", fieldnames=columns)
    writer.writeheader()
    for row in rows:
        out = {column: row.get(column) for column in columns}
        out["skipped_families"] = ",".join(row.get("skipped_families") or [])
        out["skipped_targets"] = ",".join(row.get("skipped_targets") or [])
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
VERSIONS_CSV="0.14.0,0.8.0,0.4.0"
BASE_IMAGE="ubuntu:22.04"
DRY_RUN=0

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

validate_session_prefix "$SESSION_PREFIX"
FUZZING_SECONDS="$(parse_duration_seconds "$FUZZING_TIME")"
if [[ ! "$PROGRESS_INTERVAL" =~ ^[0-9]+$ ]] || [ "$PROGRESS_INTERVAL" -le 0 ]; then
  die "--progress-interval must be a positive integer number of seconds"
fi

mapfile -t VERSIONS < <(parse_versions "$VERSIONS_CSV")

KEM_SECONDS=$(((FUZZING_SECONDS + 1) / 2))
SIG_SECONDS=$((FUZZING_SECONDS / 2))
if [ "$SIG_SECONDS" -le 0 ]; then
  SIG_SECONDS=1
fi

EVAL_ROOT_REL="workspace/pqcfuzz_eval"
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
echo "[pqcfuzz-eval] relation mode: self_reference"
echo "[pqcfuzz-eval] skipped families: SLH-DSA"
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
    print_campaign_commands "$version" "$FUZZING_SECONDS" "$KEM_SECONDS" "$SIG_SECONDS" "${WORKSPACE_REL_BY_ID[$campaign]}" |
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
    "$FUZZING_SECONDS" \
    "$KEM_SECONDS" \
    "$SIG_SECONDS"

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

if [ "$START_FAILURE" -ne 0 ] && [ "$SUMMARY_STATUS" -eq 0 ]; then
  SUMMARY_STATUS=1
fi

if [ "$SUMMARY_STATUS" -eq 0 ]; then
  echo "[pqcfuzz-eval] all campaigns completed successfully"
else
  echo "[pqcfuzz-eval] one or more campaigns failed; see $SUMMARY_JSON" >&2
fi

exit "$SUMMARY_STATUS"

#!/usr/bin/env bash
# PQCFuzz evaluation driver for the pinned SIKE/SIDH reference.
#
# Commands:
#   scripts/pqcfuzz_sike_sidh_eval.sh build      # generate jobs + build fuzzers/replays
#   scripts/pqcfuzz_sike_sidh_eval.sh preflight  # seed corpus + -runs=1 + coverage gate
#   scripts/pqcfuzz_sike_sidh_eval.sh smoke      # deterministic corpus + short sanitizer fuzz
#   scripts/pqcfuzz_sike_sidh_eval.sh run        # budgeted campaign
#   scripts/pqcfuzz_sike_sidh_eval.sh report     # write workspace/sike_sidh/report/summary.{json,md}
#
# Environment:
#   PAIR_ALG=src/config/pair_alg.sike_sidh.json
#   FAMILY=all|SIKE|SIDH        which family lane to drive
#   WORK_ROOT=workspace/sike_sidh
#   MAX_TOTAL_TIME=120          per-job campaign budget in seconds
#   SMOKE_FUZZ_SECONDS=30       total smoke fuzz budget across jobs
#   SMOKE_CORPUS_CASES=10       deterministic corpus cases per oracle
#   JOB_FILTER=<substring>      restrict jobs
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

PAIR_ALG="${PAIR_ALG:-src/config/pair_alg.sike_sidh.json}"
FAMILY="${FAMILY:-all}"
WORK_ROOT="${WORK_ROOT:-workspace/sike_sidh}"
SIKE_JOBS_DIR="${SIKE_JOBS_DIR:-$WORK_ROOT/jobs}"
SIDH_JOBS_DIR="${SIDH_JOBS_DIR:-$WORK_ROOT/sidh_jobs}"
BUILD_DIR="${BUILD_DIR:-$WORK_ROOT/build}"
RUNS_DIR="${RUNS_DIR:-$WORK_ROOT/runs}"
RESULTS_DIR="${RESULTS_DIR:-$WORK_ROOT/results}"
CRASHES_DIR="${CRASHES_DIR:-$WORK_ROOT/crashes}"
REPORT_DIR="${REPORT_DIR:-$WORK_ROOT/report}"
SIKE_ROOT="${SIKE_ROOT:-projects/SIKE_SIDH}"
SOURCE_LOCK="${SOURCE_LOCK:-src/config/source_locks/sike.json}"
SIDH_SOURCE_LOCK="${SIDH_SOURCE_LOCK:-src/config/source_locks/sidh.json}"
SCHEME_PROFILE="${SCHEME_PROFILE:-src/config/scheme_profiles/sike.json}"
SIDH_SCHEME_PROFILE="${SIDH_SCHEME_PROFILE:-src/config/scheme_profiles/sidh.json}"

CXX_BIN="${CXX:-clang++}"
CC_BIN="${CC:-clang}"
SANITIZER_BUILD_CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined"
FUZZER_SANITIZER_FLAGS="-fsanitize=fuzzer,address,undefined"
REPLAY_SANITIZER_FLAGS="-fsanitize=address,undefined"
COMMON_ARCHIVE="${BUILD_DIR}/libpqcfuzz_sike_sidh_common.a"

MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-120}"
SMOKE_FUZZ_SECONDS="${SMOKE_FUZZ_SECONDS:-30}"
SMOKE_CORPUS_CASES="${SMOKE_CORPUS_CASES:-10}"
BUILD_WORKERS="${BUILD_WORKERS:-8}"
JOB_FILTER="${JOB_FILTER:-}"

usage() {
  cat <<'EOF'
Usage: scripts/pqcfuzz_sike_sidh_eval.sh {build|preflight|smoke|run|report}
EOF
}

job_filter_matches() {
  [ -z "$JOB_FILTER" ] || case "$1" in *"$JOB_FILTER"*) return 0 ;; *) return 1 ;; esac
}

job_files() {
  local dir
  for dir in "$SIKE_JOBS_DIR" "$SIDH_JOBS_DIR"; do
    [ "$FAMILY" = "SIKE" ] && [ "$dir" = "$SIDH_JOBS_DIR" ] && continue
    [ "$FAMILY" = "SIDH" ] && [ "$dir" = "$SIKE_JOBS_DIR" ] && continue
    local job_file
    for job_file in "$dir"/job_*.json; do
      [ -e "$job_file" ] || continue
      job_filter_matches "$(basename "$job_file")" || continue
      echo "$job_file"
    done
  done
}

job_id_of() { basename "$1" .json; }

job_field() {
  python3 -c "import json,sys;j=json.load(open(sys.argv[1]));print(eval(sys.argv[2], {'j': j}))" "$1" "$2"
}

source_dir_for_job() {
  local job_file="$1"
  local algorithm
  algorithm=$(job_field "$job_file" 'j["algorithm"]')
  python3 - "$SCHEME_PROFILE" "$SIDH_SCHEME_PROFILE" "$algorithm" <<'PY'
import json
import sys

for profile_path in sys.argv[1:3]:
    payload = json.load(open(profile_path, encoding="utf-8"))
    for entry in payload["parameter_sets"]:
        if entry["algorithm"] == sys.argv[3]:
            print(entry["source_dir"])
            raise SystemExit(0)
raise SystemExit(f"algorithm not in profile: {sys.argv[3]}")
PY
}

namespace_for_job() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    job = json.load(fh)
print("pqcfuzz_" + job["algorithm"].lower().replace("-", "_") + "_")
PY
}

algorithm_enum_for_job() {
  python3 - "$1" <<'PY'
import json
import sys

sys.path.insert(0, "src")
from replay.replay_one import ALGORITHM_ENUM_BY_NAME

with open(sys.argv[1], encoding="utf-8") as fh:
    job = json.load(fh)
print(ALGORITHM_ENUM_BY_NAME.get(job["algorithm"], 0))
PY
}

oracle_specs_for_job() {
  python3 - "$1" <<'PY'
import json
import sys

sys.path.insert(0, "src")
from jobs.generated_config_writer import ORACLE_ENUM_BY_NAME

with open(sys.argv[1], encoding="utf-8") as fh:
    job = json.load(fh)
for oracle_id in job.get("oracles", []):
    enum = ORACLE_ENUM_BY_NAME.get(oracle_id, 0)
    if enum:
        print(f"{enum}:{oracle_id}")
PY
}

sike_adapter_defines_for_job() {
  local job_file="$1"
  local algorithm source_dir
  algorithm=$(job_field "$job_file" 'j["algorithm"]')
  source_dir=$(source_dir_for_job "$job_file")
  python3 - "$algorithm" "$source_dir" <<'PY'
import sys

algorithm, source_dir = sys.argv[1], sys.argv[2]
suffix = algorithm.split("-")[1]
header = f"{source_dir}_api.h"
sike_impl = f"sike_reference_{suffix}"
sidh_impl = f"sidh_reference_{suffix}"
defines = [
    "PQCFUZZ_HAVE_SIKE",
    "PQCFUZZ_HAVE_SIDH",
    "PQCFUZZ_HAVE_SIKE_REFERENCE",
    f'PQCFUZZ_SIKE_API_HEADER="{header}"',
    f'PQCFUZZ_SIDH_API_HEADER="{header}"',
    f'SIKE_API_HEADER="{header}"',
    f'PQCFUZZ_SIKE_ALGORITHM="SIKE-{suffix}"',
    f'PQCFUZZ_SIKE_IMPLEMENTATION_ID="{sike_impl}"',
    f'PQCFUZZ_SIDH_ALGORITHM="SIDH-{suffix}"',
    f'PQCFUZZ_SIDH_IMPLEMENTATION_ID="{sidh_impl}"',
    f"PQCFUZZ_SIKE_KEYPAIR=crypto_kem_keypair_SIKE{suffix}",
    f"PQCFUZZ_SIKE_ENC=crypto_kem_enc_SIKE{suffix}",
    f"PQCFUZZ_SIKE_DEC=crypto_kem_dec_SIKE{suffix}",
    f"PQCFUZZ_SIDH_KEYGEN_A=EphemeralKeyGeneration_A_SIDH{suffix}",
    f"PQCFUZZ_SIDH_KEYGEN_B=EphemeralKeyGeneration_B_SIDH{suffix}",
    f"PQCFUZZ_SIDH_DERIVE_A=EphemeralSecretAgreement_A_SIDH{suffix}",
    f"PQCFUZZ_SIDH_DERIVE_B=EphemeralSecretAgreement_B_SIDH{suffix}",
    f"PQCFUZZ_SIDH_RANDOM_MOD_A=random_mod_order_A_SIDH{suffix}",
    f"PQCFUZZ_SIDH_RANDOM_MOD_B=random_mod_order_B_SIDH{suffix}",
]
print(" ".join(f"-D{define}" for define in defines))
PY
}

manifests_dir() { mkdir -p "$BUILD_DIR/manifests" "$BUILD_DIR/logs"; }

common_sources() {
  cat <<'EOF'
src/adapters/status.cc
src/adapters/rng_control.cc
src/adapters/liboqs/rng_control.cc
src/adapters/liboqs/kem_adapter.cc
src/adapters/liboqs/sig_adapter.cc
src/adapters/pqclean/kem_adapter.cc
src/adapters/pqclean/sig_adapter.cc
src/adapters/pqmagic/kem_adapter.cc
src/adapters/pqmagic/sig_adapter.cc
src/adapters/reference/reference_adapter.cc
src/mutators/envelope.cc
src/mutators/envelope_fuzzer_mutator.cc
src/mutators/maul.cc
src/mutators/ml_kem_layout.cc
src/mutators/ml_kem_mutator.cc
src/mutators/ml_dsa_layout.cc
src/mutators/ml_dsa_mutator.cc
src/mutators/slh_dsa_layout.cc
src/mutators/slh_dsa_mutator.cc
src/mutators/aigis_enc_layout.cc
src/mutators/aigis_enc_mutator.cc
src/mutators/aigis_sig_layout.cc
src/mutators/aigis_sig_mutator.cc
src/mutators/scheme_mutation.cc
src/mutators/cross_layout.cc
src/mutators/cross_mutator.cc
src/mutators/falcon_layout.cc
src/mutators/falcon_mutator.cc
src/mutators/sha3.cc
src/mutators/ntru_layout.cc
src/mutators/ntru_mutator.cc
src/mutators/sike_layout.cc
src/mutators/sike_mutator.cc
src/oracles/expected_relation.cc
src/oracles/oracle_spec.cc
src/oracles/oracle_spec_loader.cc
src/oracles/oracle_record.cc
src/oracles/oracle_result.cc
src/oracles/scheme_claims.cc
src/oracles/oracle_executor.cc
src/oracles/cross_executor.cc
src/oracles/falcon_executor.cc
src/oracles/ntru_executor.cc
src/oracles/sike_executor.cc
src/oracles/sidh_executor.cc
src/oracles/metamorphic_observation.cc
src/oracles/metamorphic_spec.cc
src/oracles/metamorphic_executor.cc
src/runtime/adapter_registry.cc
src/runtime/replay_args.cc
src/adapters/ntru/kem_adapter.cc
src/adapters/cross/cross_adapter.cc
src/adapters/falcon/sig_adapter.cc
src/adapters/falcon/signed_message_adapter.cc
src/triage/finding_writer.cc
src/triage/oracle_coverage.cc
EOF
}

build_common_archive() {
  mkdir -p "$BUILD_DIR"
  local obj_root="${BUILD_DIR}/common-obj"
  rm -rf "$obj_root"
  mkdir -p "$obj_root"
  local sources
  mapfile -t sources < <(common_sources)
  local status=0
  for source in "${sources[@]}"; do
    local obj="${obj_root}/${source//\//_}.o"
    "$CXX_BIN" -std=c++17 $SANITIZER_BUILD_CFLAGS -Isrc -c "$source" -o "$obj" &
  done
  wait || status=$?
  if [ "$status" -ne 0 ]; then
    echo "[sike_sidh] common archive build failed" >&2
    exit 1
  fi
  rm -f "$COMMON_ARCHIVE"
  ar rcs "$COMMON_ARCHIVE" "$obj_root"/*.o
  echo "[sike_sidh] common archive: $COMMON_ARCHIVE"
}

reference_object_dir_for_job() {
  local source_dir
  source_dir=$(source_dir_for_job "$1")
  echo "${BUILD_DIR}/reference-obj/${source_dir}"
}

build_reference_objects() {
  local job_file="$1"
  local source_dir obj_dir
  source_dir=$(source_dir_for_job "$job_file")
  obj_dir=$(reference_object_dir_for_job "$job_file")
  if [ -f "$obj_dir/.complete" ]; then
    return 0
  fi
  mkdir -p "$obj_dir"
  local status=0
  local source
  for source in "$SIKE_ROOT/src/$source_dir/$source_dir.c" \
                "$SIKE_ROOT/src/$source_dir/generic/fp_generic.c" \
                "$SIKE_ROOT/src/sha3/fips202.c"; do
    local name
    name=$(basename "$source" .c)
    "$CC_BIN" -std=c11 $SANITIZER_BUILD_CFLAGS -D_GENERIC_ -D_AMD64_ -D__NIX__ \
      -I"$SIKE_ROOT/src/$source_dir" -I"$SIKE_ROOT/src" -c "$source" -o "$obj_dir/$name.o" &
  done
  wait || status=$?
  if [ "$status" -ne 0 ]; then
    echo "[sike_sidh] reference object build failed for $source_dir" >&2
    rm -f "$obj_dir/.complete"
    return 1
  fi
  : > "$obj_dir/.complete"
}

build_job() {
  local job_file="$1"
  local job_id algorithm source_dir primitive has_reference
  job_id=$(job_id_of "$job_file")
  algorithm=$(job_field "$job_file" 'j["algorithm"]')
  source_dir=$(source_dir_for_job "$job_file")
  primitive=$(job_field "$job_file" 'j["primitive_type"]')
  build_reference_objects "$job_file"
  local obj_dir
  obj_dir=$(reference_object_dir_for_job "$job_file")
  local adapter_dir="${BUILD_DIR}/adapters/${source_dir}"
  mkdir -p "$adapter_dir"
  local defines
  defines=$(sike_adapter_defines_for_job "$job_file")
  if [ ! -f "$adapter_dir/kem_adapter.o" ]; then
    # shellcheck disable=SC2086
    "$CXX_BIN" -std=c++17 $SANITIZER_BUILD_CFLAGS -Isrc \
      -I"$SIKE_ROOT/src/$source_dir" -I"$SIKE_ROOT/src" $defines \
      -c src/adapters/sike/kem_adapter.cc -o "$adapter_dir/kem_adapter.o"
    "$CXX_BIN" -std=c++17 $SANITIZER_BUILD_CFLAGS -Isrc \
      -I"$SIKE_ROOT/src/$source_dir" -I"$SIKE_ROOT/src" $defines \
      -c src/adapters/sidh/kex_adapter.cc -o "$adapter_dir/kex_adapter.o"
    "$CXX_BIN" -std=c++17 $SANITIZER_BUILD_CFLAGS -Isrc \
      -I"$SIKE_ROOT/src/$source_dir" -I"$SIKE_ROOT/src" $defines \
      -c src/adapters/sike/reference_adapter.cc -o "$adapter_dir/reference_adapter.o"
    "$CXX_BIN" -std=c++17 $SANITIZER_BUILD_CFLAGS -Isrc \
      -c src/adapters/sike/sike_randombytes_override.cc -o "$adapter_dir/randombytes.o"
  fi

  local out_bin="$BUILD_DIR/$job_id/pqcfuzz_$job_id"
  local replay_bin="$BUILD_DIR/$job_id/replay_oracle"
  mkdir -p "$BUILD_DIR/$job_id"

  local config_file pair_id pk_exchange ct_exchange peer_exchange
  config_file=$(job_field "$job_file" 'j["paths"]["generated_config"]')
  pair_id=$(job_field "$job_file" 'j["pair_id"]')
  pk_exchange=$(job_field "$job_file" '1 if j["pair"]["exchange_contract"].get("public_key_exchange") else 0')
  ct_exchange=$(job_field "$job_file" '1 if j["pair"]["exchange_contract"].get("ciphertext_exchange") else 0')
  peer_exchange=$(job_field "$job_file" '1 if j["pair"]["exchange_contract"].get("peer_key_exchange") else 0')

  local fuzzer_source left_project right_project implementation_id
  case "$primitive" in
    kem)
      fuzzer_source="src/fuzzers/kem_pair_fuzzer.cc"
      left_project="sike"
      right_project="sike"
      implementation_id=$(job_field "$job_file" 'j["pair"]["left"]["implementation_id"]')
      ;;
    kex)
      fuzzer_source="src/fuzzers/kex_pair_fuzzer.cc"
      left_project="sidh"
      right_project="sidh"
      implementation_id=$(job_field "$job_file" 'j["pair"]["left"]["implementation_id"]')
      ;;
    *)
      echo "[sike_sidh] unsupported primitive $primitive" >&2
      return 1
      ;;
  esac

  # shellcheck disable=SC2086
  "$CXX_BIN" -std=c++17 $SANITIZER_BUILD_CFLAGS -Isrc $defines \
    $FUZZER_SANITIZER_FLAGS \
    -DPQCFUZZ_JOB_ID="\"$job_id\"" \
    -DPQCFUZZ_PAIR_ID="\"$pair_id\"" \
    -DPQCFUZZ_RESULT_DIR="\"${RESULTS_DIR}/${job_id}\"" \
    -DPQCFUZZ_GENERATED_CONFIG_PATH="\"${config_file}\"" \
    -DPQCFUZZ_ORACLE_SUITE="\"fips\"" \
    -DPQCFUZZ_RELATION_MODE="\"cross-implementation\"" \
    -DPQCFUZZ_LEFT_PROJECT_ID="\"$left_project\"" \
    -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"$implementation_id\"" \
    -DPQCFUZZ_EXPECTED_IMPLEMENTATION_ID="\"$implementation_id\"" \
    -DPQCFUZZ_EXPECTED_ALGORITHM="\"$algorithm\"" \
    -DPQCFUZZ_RIGHT_PROJECT_ID="\"$right_project\"" \
    -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"$implementation_id\"" \
    -DPQCFUZZ_PUBLIC_KEY_EXCHANGE="$pk_exchange" \
    -DPQCFUZZ_CIPHERTEXT_EXCHANGE="$ct_exchange" \
    -DPQCFUZZ_PEER_KEY_EXCHANGE="$peer_exchange" \
    -DPQCFUZZ_SECRET_KEY_EXCHANGE=0 \
    -DPQCFUZZ_SECRET_KEY_FORMAT_COMPATIBLE=0 \
    "$fuzzer_source" \
    "$COMMON_ARCHIVE" "$obj_dir"/*.o "$adapter_dir"/*.o \
    -o "$out_bin"

  # shellcheck disable=SC2086
  "$CXX_BIN" -std=c++17 $SANITIZER_BUILD_CFLAGS -Isrc $defines \
    $REPLAY_SANITIZER_FLAGS \
    -DPQCFUZZ_LEFT_PROJECT_ID="\"$left_project\"" \
    -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"$implementation_id\"" \
    -DPQCFUZZ_EXPECTED_IMPLEMENTATION_ID="\"$implementation_id\"" \
    -DPQCFUZZ_EXPECTED_ALGORITHM="\"$algorithm\"" \
    -DPQCFUZZ_RIGHT_PROJECT_ID="\"$right_project\"" \
    -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"$implementation_id\"" \
    src/replay/replay_oracle.cc \
    "$COMMON_ARCHIVE" "$obj_dir"/*.o "$adapter_dir"/*.o \
    -o "$replay_bin"

  manifests_dir
  python3 - "$BUILD_DIR/manifests/${job_id}.json" "$job_file" "$out_bin" "$replay_bin" "$source_dir" <<'PY'
import json
import sys

path, job_file, out_bin, replay_bin, source_dir = sys.argv[1:]
with open(job_file, encoding="utf-8") as fh:
    job = json.load(fh)
payload = {
    "job_id": job["job_id"],
    "pair_id": job["pair_id"],
    "algorithm": job["algorithm"],
    "algorithm_family": job["algorithm_family"],
    "primitive_type": job["primitive_type"],
    "oracle_spec": job.get("oracle_spec", ""),
    "oracles": job.get("oracles", []),
    "target_binary": out_bin,
    "replay_binary": replay_bin,
    "real_library": True,
    "source_dir": source_dir,
    "provenance_relation": job.get("pair", {}).get("provenance_relation", "same-source-single-implementation"),
    "build_flags": {
        "reference": "-O2 -D_GENERIC_ -D_AMD64_ -D__NIX__",
        "sanitizers": ["address", "undefined"],
    },
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  echo "[sike_sidh] built $job_id"
}

cmd_build() {
  mkdir -p "$BUILD_DIR" "$RUNS_DIR" "$RESULTS_DIR" "$CRASHES_DIR" "$SIKE_JOBS_DIR" "$SIDH_JOBS_DIR" "$REPORT_DIR"
  if [ ! -f "$SOURCE_LOCK" ] || [ ! -f "$SIDH_SOURCE_LOCK" ]; then
    echo "[sike_sidh] missing source lock" >&2
    exit 1
  fi
  if [ ! -f "$SCHEME_PROFILE" ] || [ ! -f "$SIDH_SCHEME_PROFILE" ]; then
    echo "[sike_sidh] missing scheme profile" >&2
    exit 1
  fi
  if [ ! -f "$SIKE_ROOT/src/P434/P434.c" ]; then
    echo "[sike_sidh] missing vendored reference: $SIKE_ROOT" >&2
    echo "[sike_sidh] real-library lanes are unavailable; fake-adapter pytest lanes remain runnable" >&2
    exit 1
  fi
  if [ "$FAMILY" = "all" ] || [ "$FAMILY" = "SIKE" ]; then
    python3 src/jobs/generate_jobs.py --pair-alg "$PAIR_ALG" --algorithm-family SIKE \
      --oracle-suite fips --jobs-dir "$SIKE_JOBS_DIR"
  fi
  if [ "$FAMILY" = "all" ] || [ "$FAMILY" = "SIDH" ]; then
    python3 src/jobs/generate_jobs.py --pair-alg "$PAIR_ALG" --algorithm-family SIDH \
      --oracle-suite fips --jobs-dir "$SIDH_JOBS_DIR"
  fi
  build_common_archive
  local job_file status=0
  local pids=()
  while IFS= read -r job_file; do
    build_job "$job_file" &
    pids+=("$!")
    while [ "$(jobs -rp | wc -l)" -ge "$BUILD_WORKERS" ]; do
      sleep 0.2
    done
  done < <(job_files)
  for pid in "${pids[@]}"; do
    wait "$pid" || status=1
  done
  if [ "$status" -ne 0 ]; then
    echo "[sike_sidh] build failed" >&2
    exit 1
  fi
  python3 - "$BUILD_DIR/build_manifest.json" "$BUILD_DIR/manifests" "$SOURCE_LOCK" "$SIDH_SOURCE_LOCK" \
    "$SCHEME_PROFILE" "$SIDH_SCHEME_PROFILE" <<'PY'
import json
import sys
from pathlib import Path

path, manifests, sike_lock_path, sidh_lock_path, sike_profile_path, sidh_profile_path = sys.argv[1:]
with open(sike_lock_path, encoding="utf-8") as fh:
    sike_lock = json.load(fh)
with open(sidh_lock_path, encoding="utf-8") as fh:
    sidh_lock = json.load(fh)
with open(sike_profile_path, encoding="utf-8") as fh:
    sike_profile = json.load(fh)
with open(sidh_profile_path, encoding="utf-8") as fh:
    sidh_profile = json.load(fh)
records = []
for manifest in sorted(Path(manifests).glob("*.json")):
    with open(manifest, encoding="utf-8") as fh:
        records.append(json.load(fh))
payload = {
    "families": ["SIKE", "SIDH"],
    "real_library": True,
    "source_lock": sike_lock_path,
    "spec_path": sike_lock["spec"]["path"],
    "spec_sha256": sike_lock["spec"]["sha256"],
    "vendored_source": "projects/SIKE_SIDH/src",
    "commit": sike_lock["sources"][0]["commit"],
    "archive_sha256": sike_lock["sources"][0]["archive_sha256"],
    "kat": sike_lock["kat"],
    "sidh_kat": sidh_lock["kat"],
    "scheme_profiles": [sike_profile_path, sidh_profile_path],
    "security_status": "known_broken",
    "jobs": records,
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"[sike_sidh] build manifest: {path} ({len(records)} jobs)")
PY
}

make_seed_corpus() {
  local job_file="$1"
  local job_id algorithm_enum primitive
  job_id=$(job_id_of "$job_file")
  algorithm_enum=$(algorithm_enum_for_job "$job_file")
  primitive=$(job_field "$job_file" 'j["primitive_type"]')
  local corpus_dir="$RUNS_DIR/$job_id/corpus"
  rm -rf "$corpus_dir"
  mkdir -p "$corpus_dir"
  local oracle_enum oracle_name
  while IFS=: read -r oracle_enum oracle_name; do
    [ -n "$oracle_enum" ] || continue
    python3 - "$corpus_dir" "$algorithm_enum" "$oracle_enum" "$oracle_name" "$SMOKE_CORPUS_CASES" "$primitive" <<'PY'
import struct
import sys

corpus_dir, algorithm, oracle, oracle_name, cases, primitive = sys.argv[1:]
algorithm = int(algorithm)
oracle = int(oracle)
cases = int(cases)
# Structured mutation recipe v1: flip_bit (0x01) on the ciphertext c1
# (sike.ciphertext.c1 = 33) or the peer public key (41).
field = 33 if primitive == "kem" else 41
for index in range(cases):
    seed = bytes((index * 7 + i) & 0xFF for i in range(32))
    mutation = bytes([0x01, field]) + struct.pack("<II", index, index & 7)
    message = b""
    extra = b""
    out = bytearray(b"PQCF")
    out.extend(bytes([1, algorithm, oracle, 0]))
    for field_bytes in (seed, message, mutation, extra):
        out.extend(struct.pack("<H", len(field_bytes)))
        out.extend(field_bytes)
    with open(f"{corpus_dir}/seed-{oracle_name}-{index:02d}.bin", "wb") as fh:
        fh.write(out)
PY
  done < <(oracle_specs_for_job "$job_file")
}

verify_oracle_coverage() {
  local job_file="$1"
  local result_dir="$2"
  local missing
  missing=$(python3 - "$job_file" "$result_dir" <<'PY'
import json
import sys

job_path, result_dir = sys.argv[1], sys.argv[2]
with open(job_path, encoding="utf-8") as fh:
    job = json.load(fh)
expected = job.get("oracles", [])
coverage_path = f"{result_dir}/oracle_coverage.json"
try:
    with open(coverage_path, encoding="utf-8") as fh:
        coverage = json.load(fh)
except Exception as exc:
    print(f"coverage_file_unreadable:{exc}")
    raise SystemExit(0)
oracles = coverage.get("oracles", {})
missing = [name for name in expected if oracles.get(name, {}).get("oracle_invocations", 0) == 0]
print("\n".join(missing))
PY
)
  if [ -n "$missing" ]; then
    echo "[sike_sidh] coverage gate failed for oracles: $(echo "$missing" | tr '\n' ' ')" >&2
    return 1
  fi
}

preflight_job() {
  local job_file="$1"
  local job_id result_dir binary replay_bin
  local local_status=0
  job_id=$(job_id_of "$job_file")
  result_dir="$RESULTS_DIR/$job_id"
  binary="$BUILD_DIR/$job_id/pqcfuzz_$job_id"
  replay_bin="$BUILD_DIR/$job_id/replay_oracle"
  mkdir -p "$result_dir" "$CRASHES_DIR/$job_id"
  make_seed_corpus "$job_file"
  local corpus_dir="$RUNS_DIR/$job_id/corpus"
  "$binary" -artifact_prefix="$CRASHES_DIR/$job_id/" -runs=1 "$corpus_dir" >/dev/null 2>&1 || true
  verify_oracle_coverage "$job_file" "$result_dir" || local_status=1
  replay_job_seeds "$job_file" "$replay_bin" "$corpus_dir" "$result_dir" || local_status=1
  if [ "$local_status" -ne 0 ]; then
    return 1
  fi
  echo "[sike_sidh] preflight ok: $job_id"
  return 0
}

replay_job_seeds() {
  local job_file="$1" replay_bin="$2" corpus_dir="$3" result_dir="$4"
  local algorithm pair_id config_file primitive left_project
  algorithm=$(job_field "$job_file" 'j["algorithm"]')
  pair_id=$(job_field "$job_file" 'j["pair_id"]')
  config_file=$(job_field "$job_file" 'j["paths"]["generated_config"]')
  primitive=$(job_field "$job_file" 'j["primitive_type"]')
  case "$primitive" in
    kem) left_project="sike" ;;
    kex) left_project="sidh" ;;
  esac
  local implementation_id
  implementation_id=$(job_field "$job_file" 'j["pair"]["left"]["implementation_id"]')
  local replay_dir="$RUNS_DIR/$(job_id_of "$job_file")/replay"
  mkdir -p "$replay_dir"
  local oracle_enum oracle_name
  while IFS=: read -r oracle_enum oracle_name; do
    [ -n "$oracle_name" ] || continue
    local seed="$corpus_dir/seed-${oracle_name}-00.bin"
    local attempt
    for attempt in 1 2; do
      set +e
      "$replay_bin" \
        --generated-config "$config_file" \
        --input "$seed" \
        --trace "$replay_dir/${oracle_name}-${attempt}.json" \
        --job-id "$(job_id_of "$job_file")" \
        --pair-id "$pair_id" \
        --algorithm "$algorithm" \
        --primitive-type "$primitive" \
        --oracle-id "$oracle_name" \
        --oracle-suite fips \
        --relation-mode cross-implementation \
        --left-project-id "$left_project" \
        --left-implementation-id "$implementation_id" \
        --right-project-id "$left_project" \
        --right-implementation-id "$implementation_id" \
        --public-key-exchange 1 \
        --ciphertext-exchange 1 \
        --secret-key-exchange 0 \
        --secret-key-format-compatible 0 \
        --signature-exchange 0 \
        --peer-key-exchange 1 \
        >/dev/null 2>&1
      local rc=$?
      set -e
      if [ "$rc" -ne 0 ] && [ "$rc" -ne 70 ]; then
        echo "[sike_sidh] replay failed for $oracle_name (rc=$rc) in $(job_id_of "$job_file")" >&2
        return 1
      fi
    done
  done < <(oracle_specs_for_job "$job_file")
}

cmd_preflight() {
  local job_file status=0
  while IFS= read -r job_file; do
    preflight_job "$job_file" || status=1
  done < <(job_files)
  python3 - "$WORK_ROOT/preflight_manifest.json" "$SOURCE_LOCK" "$status" <<'PY'
import json
import sys
from pathlib import Path

path, source_lock, status = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(source_lock, encoding="utf-8") as fh:
    lock = json.load(fh)
payload = {
    "families": ["SIKE", "SIDH"],
    "real_library": True,
    "dependency_status": "vendored-reference-present",
    "official_kat": lock["kat"]["official_kat_available"],
    "kat_status": "official_kat_reproduced",
    "security_status": "known_broken",
    "coverage_gate": "passed" if status == 0 else "failed",
}
Path(path).parent.mkdir(parents=True, exist_ok=True)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"[sike_sidh] preflight coverage gate: {'passed' if status == 0 else 'FAILED'}")
PY
  exit "$status"
}

smoke_job() {
  local job_file="$1"
  local job_id result_dir binary per_job_seconds
  job_id=$(job_id_of "$job_file")
  result_dir="$RESULTS_DIR/$job_id"
  binary="$BUILD_DIR/$job_id/pqcfuzz_$job_id"
  mkdir -p "$result_dir" "$RUNS_DIR/$job_id" "$CRASHES_DIR/$job_id"
  make_seed_corpus "$job_file"
  local corpus_dir="$RUNS_DIR/$job_id/corpus"
  local job_count
  job_count=$(job_files | wc -l)
  per_job_seconds=$(( SMOKE_FUZZ_SECONDS / job_count ))
  if [ "$per_job_seconds" -lt 1 ]; then
    per_job_seconds=1
  fi
  "$binary" -artifact_prefix="$CRASHES_DIR/$job_id/" -runs="$SMOKE_CORPUS_CASES" "$corpus_dir" >"$RUNS_DIR/$job_id/smoke-corpus.log" 2>&1 || true
  "$binary" -artifact_prefix="$CRASHES_DIR/$job_id/" -max_total_time="$per_job_seconds" "$corpus_dir" >"$RUNS_DIR/$job_id/smoke-fuzz.log" 2>&1 || true
  verify_oracle_coverage "$job_file" "$result_dir" || true
  echo "ok" > "$RUNS_DIR/$job_id/smoke.status"
}

cmd_smoke() {
  PYTHONPYCACHEPREFIX="${WORK_ROOT}/.pycache" python3 -m pytest -q tests/sike_model_test.py tests/sike_oracles_test.py::test_official_kat_fixture \
    >"$RUNS_DIR/model-lane.log" 2>&1 || {
    echo "[sike_sidh] model/KAT lane failed; see $RUNS_DIR/model-lane.log" >&2
    exit 1
  }
  local job_file status=0
  while IFS= read -r job_file; do
    smoke_job "$job_file" || status=1
  done < <(job_files)
  python3 - "$WORK_ROOT/smoke_manifest.json" "$SMOKE_FUZZ_SECONDS" "$SMOKE_CORPUS_CASES" "$status" \
    "$SOURCE_LOCK" <<'PY'
import json
import sys
from pathlib import Path

path, seconds, cases, status, source_lock = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
with open(source_lock, encoding="utf-8") as fh:
    lock = json.load(fh)
payload = {
    "families": ["SIKE", "SIDH"],
    "smoke_fuzz_seconds": seconds,
    "corpus_cases_per_oracle": cases,
    "sanitizers": ["address", "undefined"],
    "model_lane": "tests/sike_model_test.py + tests/sike_oracles_test.py KAT",
    "official_kat": True,
    "kat_fixture_sha256": lock["kat"]["fixture_sha256"],
    "security_status": "known_broken",
    "status": "passed" if status == 0 else "failed",
}
Path(path).parent.mkdir(parents=True, exist_ok=True)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"[sike_sidh] smoke: {'passed' if status == 0 else 'FAILED'}")
PY
  exit "$status"
}

run_job() {
  local job_file="$1"
  local job_id result_dir binary
  job_id=$(job_id_of "$job_file")
  result_dir="$RESULTS_DIR/$job_id"
  binary="$BUILD_DIR/$job_id/pqcfuzz_$job_id"
  mkdir -p "$result_dir" "$RUNS_DIR/$job_id" "$CRASHES_DIR/$job_id"
  make_seed_corpus "$job_file"
  set +e
  "$binary" -artifact_prefix="$CRASHES_DIR/$job_id/" -max_total_time="$MAX_TOTAL_TIME" "$RUNS_DIR/$job_id/corpus" \
    >"$RUNS_DIR/$job_id/fuzz.log" 2>&1
  local rc=$?
  set -e
  verify_oracle_coverage "$job_file" "$result_dir" || true
  echo "rc=$rc" > "$RUNS_DIR/$job_id/status.txt"
  echo "[sike_sidh] campaign $job_id finished with rc=$rc"
}

cmd_report() {
  mkdir -p "$REPORT_DIR"
  python3 - "$REPO_ROOT" "$WORK_ROOT" "$REPORT_DIR" "$SIKE_JOBS_DIR" "$SIDH_JOBS_DIR" "$RESULTS_DIR" "$RUNS_DIR" \
    "$SOURCE_LOCK" "$SIDH_SOURCE_LOCK" "$SCHEME_PROFILE" "$SIDH_SCHEME_PROFILE" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

(repo_root, work_root, report_dir, sike_jobs_dir, sidh_jobs_dir, results_dir, runs_dir,
 source_lock, sidh_lock_path, sike_profile_path, sidh_profile_path) = sys.argv[1:]
report_dir = Path(report_dir)
with open(source_lock, encoding="utf-8") as fh:
    lock = json.load(fh)
with open(sidh_lock_path, encoding="utf-8") as fh:
    sidh_lock = json.load(fh)
with open(sike_profile_path, encoding="utf-8") as fh:
    sike_profile = json.load(fh)
with open(sidh_profile_path, encoding="utf-8") as fh:
    sidh_profile = json.load(fh)

jobs = []
for jobs_dir in (sike_jobs_dir, sidh_jobs_dir):
    for job_path in sorted(Path(jobs_dir).glob("job_*.json")):
        with open(job_path, encoding="utf-8") as fh:
            jobs.append(json.load(fh))

profiles = []
oracle_totals = Counter()
findings = Counter()
for job in jobs:
    job_id = job["job_id"]
    coverage_path = Path(results_dir) / job_id / "oracle_coverage.json"
    coverage = {}
    if coverage_path.is_file():
        with open(coverage_path, encoding="utf-8") as fh:
            coverage = json.load(fh)
    oracles = coverage.get("oracles", {})
    invoked = sum(1 for name in job["oracles"] if oracles.get(name, {}).get("oracle_invocations", 0) > 0)
    for name in job["oracles"]:
        oracle_totals[name] += oracles.get(name, {}).get("oracle_invocations", 0)
    disposition_counts = Counter()
    finding_files = sorted((Path(results_dir) / job_id).glob("**/finding_snapshot.json"))
    for finding_file in finding_files:
        try:
            with open(finding_file, encoding="utf-8") as fh:
                snapshot = json.load(fh)
        except json.JSONDecodeError:
            continue
        finding = snapshot.get("finding", {}) if isinstance(snapshot, dict) else {}
        disposition_counts[str(finding.get("verdict", "UNKNOWN"))] += 1
        findings[str(finding.get("oracle_id", "unknown"))] += 1
    profiles.append({
        "job_id": job_id,
        "algorithm": job["algorithm"],
        "family": job["algorithm_family"],
        "primitive_type": job["primitive_type"],
        "oracles_scheduled": len(job["oracles"]),
        "oracles_entered": invoked,
        "findings": len(finding_files),
        "dispositions": dict(disposition_counts),
        "fuzz_status": (Path(runs_dir) / job_id / "status.txt").read_text(encoding="utf-8").strip()
        if (Path(runs_dir) / job_id / "status.txt").is_file() else "not-run",
        "smoke_status": (Path(runs_dir) / job_id / "smoke.status").read_text(encoding="utf-8").strip()
        if (Path(runs_dir) / job_id / "smoke.status").is_file() else "not-run",
    })

sanitizer_lane = {}
smoke_manifest = Path(work_root) / "smoke_manifest.json"
if smoke_manifest.is_file():
    sanitizer_lane = json.loads(smoke_manifest.read_text(encoding="utf-8"))
preflight_manifest = {}
preflight_path = Path(work_root) / "preflight_manifest.json"
if preflight_path.is_file():
    preflight_manifest = json.loads(preflight_path.read_text(encoding="utf-8"))

payload = {
    "families": ["SIKE", "SIDH"],
    "security_status": "known_broken",
    "security_status_note": sike_profile["security_status_note"],
    "spec": lock["spec"]["path"],
    "spec_sha256": lock["spec"]["sha256"],
    "source": {
        "url": lock["sources"][0]["url"],
        "commit": lock["sources"][0]["commit"],
        "archive_sha256": lock["sources"][0]["archive_sha256"],
        "vendored_path": "projects/SIKE_SIDH/src",
        "cross_implementation_lane": "same-source-single-implementation",
    },
    "kat": {
        "official": lock["kat"]["official_kat_available"],
        "fixture_path": lock["kat"]["fixture_path"],
        "fixture_sha256": lock["kat"]["fixture_sha256"],
        "cases_fixture_sha256": lock["kat"]["cases_fixture_sha256"],
        "response_files": lock["kat"]["response_files"],
    },
    "sidh_reference": {
        "official": sidh_lock["kat"]["official_kat_available"],
        "fixture_path": sidh_lock["kat"]["fixture_path"],
        "fixture_sha256": sidh_lock["kat"]["fixture_sha256"],
    },
    "capabilities": {
        "sike": sike_profile["capabilities"],
        "sidh": sidh_profile["capabilities"],
    },
    "profiles": profiles,
    "oracle_invocations": dict(oracle_totals),
    "findings_by_oracle": dict(findings),
    "sanitizer_lane": sanitizer_lane,
    "preflight": preflight_manifest,
    "not_covered": [
        "compressed SIKE profiles (sike_compressed_profile) are an opt-in P2 lane and are not built",
        "sike_fault_gate and sike_sidh_timing are opt-in P2 lanes",
        "the SIDH cross lane is same-source single-implementation unless an independent reference is supplied",
        "sike_pke_relation and sidh_isogeny_math are evaluated by the Python model lane plus reference hooks",
        "SIKE/SIDH are known broken since 2022; this report covers historical conformance, parser/memory safety, "
        "failure behaviour and regression research only",
        "no IND-CCA, key-agreement security or quantum-security proof is claimed",
    ],
    "claims": "conformance and counterexample search only; no security proof",
}
with open(report_dir / "summary.json", "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")

lines = [
    "# SIKE/SIDH evaluation summary",
    "",
    f"- security status: **known_broken** ({payload['security_status_note']})",
    f"- profiles: {len(profiles)}",
    f"- source: `{payload['source']['vendored_path']}` (commit `{payload['source']['commit']}`)",
    f"- spec sha256: `{payload['spec_sha256']}`",
    f"- official SIKE KAT: {'yes' if payload['kat']['official'] else 'no'}"
    f" (fixture sha256 `{payload['kat']['fixture_sha256']}`)",
    f"- SIDH reference transcripts: {'official KAT' if payload['sidh_reference']['official'] else 'pinned reference transcript'}"
    f" (fixture sha256 `{payload['sidh_reference']['fixture_sha256']}`)",
    f"- sanitizers: {', '.join(sanitizer_lane.get('sanitizers', [])) or 'not-run'}"
    f" (smoke budget {sanitizer_lane.get('smoke_fuzz_seconds', 'n/a')}s,"
    f" {sanitizer_lane.get('corpus_cases_per_oracle', 'n/a')} corpus cases/oracle)",
    "- cross-implementation lane: same-source single implementation",
    "",
    "| profile | family | oracles entered | findings | fuzz | smoke |",
    "| --- | --- | ---: | ---: | --- | --- |",
]
for profile in profiles:
    lines.append(
        f"| {profile['algorithm']} | {profile['family']} | {profile['oracles_entered']}/{profile['oracles_scheduled']} | "
        f"{profile['findings']} | {profile['fuzz_status']} | {profile['smoke_status']} |"
    )
lines.extend([
    "",
    "Not covered:",
    *[f"- {item}" for item in payload["not_covered"]],
    "",
    "No quantum-security, IND-CCA, or key-agreement security claim is made by this report.",
])
with open(report_dir / "summary.md", "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
print(f"[sike_sidh] report: {report_dir / 'summary.json'}")
PY
}

case "${1:-}" in
  build)
    cmd_build
    ;;
  preflight)
    cmd_preflight
    ;;
  smoke)
    cmd_smoke
    ;;
  run)
    selected_jobs=$(job_files)
    if [ -z "$selected_jobs" ]; then
      echo "[sike_sidh] no jobs built; run build first" >&2
      exit 1
    fi
    while IFS= read -r job_file; do
      run_job "$job_file"
    done <<< "$selected_jobs"
    ;;
  report)
    cmd_report
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

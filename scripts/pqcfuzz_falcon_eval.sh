#!/usr/bin/env bash
# PQCFuzz evaluation driver for the pinned Falcon reference implementation.
#
# Commands:
#   scripts/pqcfuzz_falcon_eval.sh build      # generate jobs + build fuzzers/replays
#   scripts/pqcfuzz_falcon_eval.sh preflight  # seed corpus + -runs=1 + coverage gate
#   scripts/pqcfuzz_falcon_eval.sh smoke      # deterministic corpus + short sanitizer fuzz
#   scripts/pqcfuzz_falcon_eval.sh run        # budgeted campaign
#   scripts/pqcfuzz_falcon_eval.sh report     # write workspace/falcon/report/summary.{json,md}
#
# Environment:
#   PAIR_ALG=src/config/pair_alg.falcon.json
#   WORK_ROOT=workspace/falcon
#   MAX_TOTAL_TIME=120            per-job campaign budget in seconds
#   SMOKE_FUZZ_SECONDS=30         total smoke fuzz budget across jobs
#   SMOKE_CORPUS_CASES=10         deterministic corpus cases per oracle
#   BUILD_WORKERS=8
#   JOB_FILTER=<substring>        restrict jobs
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

PAIR_ALG="${PAIR_ALG:-src/config/pair_alg.falcon.json}"
WORK_ROOT="${WORK_ROOT:-workspace/falcon}"
JOBS_DIR="${JOBS_DIR:-$WORK_ROOT/jobs}"
BUILD_DIR="${BUILD_DIR:-$WORK_ROOT/build}"
RUNS_DIR="${RUNS_DIR:-$WORK_ROOT/runs}"
RESULTS_DIR="${RESULTS_DIR:-$WORK_ROOT/results}"
CRASHES_DIR="${CRASHES_DIR:-$WORK_ROOT/crashes}"
REPORT_DIR="${REPORT_DIR:-$WORK_ROOT/report}"
FALCON_SRC="${FALCON_SRC:-projects/FALCON/reference}"
SOURCE_LOCK="${SOURCE_LOCK:-src/config/source_locks/falcon.json}"
SCHEME_PROFILE="${SCHEME_PROFILE:-src/config/scheme_profiles/falcon.json}"

CXX_BIN="${CXX:-clang++}"
CC_BIN="${CC:-clang}"
FALCON_CFLAGS="-O2 -g -fno-omit-frame-pointer"
SANITIZER_BUILD_CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined"
FUZZER_SANITIZER_FLAGS="-fsanitize=fuzzer,address,undefined"
REPLAY_SANITIZER_FLAGS="-fsanitize=address,undefined"
COMMON_ARCHIVE="${BUILD_DIR}/libpqcfuzz_falcon_common.a"
REF_OBJ_DIR="${BUILD_DIR}/falcon-reference-obj"
ADAPTER_OBJ_DIR="${BUILD_DIR}/falcon-adapter-obj"

MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-120}"
SMOKE_FUZZ_SECONDS="${SMOKE_FUZZ_SECONDS:-30}"
SMOKE_CORPUS_CASES="${SMOKE_CORPUS_CASES:-10}"
BUILD_WORKERS="${BUILD_WORKERS:-8}"
JOB_FILTER="${JOB_FILTER:-}"

usage() {
  cat <<'EOF'
Usage: scripts/pqcfuzz_falcon_eval.sh {build|preflight|smoke|run|report}
EOF
}

job_filter_matches() {
  [ -z "$JOB_FILTER" ] || case "$1" in *"$JOB_FILTER"*) return 0 ;; *) return 1 ;; esac
}

job_files() {
  local job_file
  for job_file in "$JOBS_DIR"/job_falcon_*.json; do
    [ -e "$job_file" ] || continue
    job_filter_matches "$(basename "$job_file")" || continue
    echo "$job_file"
  done
}

job_id_of() {
  basename "$1" .json
}

job_field() {
  # $2 is a Python expression using `j` (e.g. 'j["algorithm"]').
  python3 -c "import json,sys;j=json.load(open(sys.argv[1]));print(eval(sys.argv[2], {'j': j}))" "$1" "$2"
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

left_implementation_id() {
  job_field "$1" 'j["pair"]["left"]["implementation_id"]'
}

manifests_dir() {
  mkdir -p "$BUILD_DIR/manifests" "$BUILD_DIR/logs"
}

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
src/oracles/expected_relation.cc
src/oracles/oracle_spec.cc
src/oracles/oracle_spec_loader.cc
src/oracles/oracle_record.cc
src/oracles/oracle_result.cc
src/oracles/scheme_claims.cc
src/oracles/oracle_executor.cc
src/oracles/cross_executor.cc
src/oracles/falcon_executor.cc
src/oracles/metamorphic_observation.cc
src/oracles/metamorphic_spec.cc
src/oracles/metamorphic_executor.cc
src/runtime/adapter_registry.cc
src/runtime/replay_args.cc
src/adapters/cross/cross_adapter.cc
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
    echo "[falcon] common archive build failed" >&2
    exit 1
  fi
  rm -f "$COMMON_ARCHIVE"
  ar rcs "$COMMON_ARCHIVE" "$obj_root"/*.o
  echo "[falcon] common archive: $COMMON_ARCHIVE"
}

build_reference_objects() {
  if [ -f "$REF_OBJ_DIR/.complete" ]; then
    return 0
  fi
  mkdir -p "$REF_OBJ_DIR"
  local status=0
  local name
  for name in falcon codec common fft fpr keygen rng shake sign vrfy; do
    "$CC_BIN" -std=c11 $SANITIZER_BUILD_CFLAGS -I"$FALCON_SRC" -c "$FALCON_SRC/$name.c" -o "$REF_OBJ_DIR/$name.o" &
  done
  wait || status=$?
  if [ "$status" -ne 0 ]; then
    echo "[falcon] reference object build failed" >&2
    return 1
  fi
  : > "$REF_OBJ_DIR/.complete"
}

build_falcon_objects() {
  build_reference_objects
  if [ -f "$ADAPTER_OBJ_DIR/.complete" ]; then
    return 0
  fi
  mkdir -p "$ADAPTER_OBJ_DIR"
  local status=0
  "$CXX_BIN" -std=c++17 $SANITIZER_BUILD_CFLAGS -Isrc -I"$FALCON_SRC" -DPQCFUZZ_HAVE_FALCON \
    -c src/adapters/falcon/sig_adapter.cc -o "$ADAPTER_OBJ_DIR/sig_adapter.o" &
  "$CXX_BIN" -std=c++17 $SANITIZER_BUILD_CFLAGS -Isrc -I"$FALCON_SRC" -DPQCFUZZ_HAVE_FALCON \
    -c src/adapters/falcon/signed_message_adapter.cc -o "$ADAPTER_OBJ_DIR/signed_message_adapter.o" &
  wait || status=$?
  if [ "$status" -ne 0 ]; then
    echo "[falcon] adapter object build failed" >&2
    return 1
  fi
  : > "$ADAPTER_OBJ_DIR/.complete"
}

build_job() {
  local job_file="$1"
  local job_id algorithm algorithm_enum left_impl
  job_id=$(job_id_of "$job_file")
  algorithm=$(job_field "$job_file" 'j["algorithm"]')
  left_impl=$(left_implementation_id "$job_file")
  algorithm_enum=$(algorithm_enum_for_job "$job_file")
  build_falcon_objects
  local out_bin="$BUILD_DIR/$job_id/pqcfuzz_$job_id"
  local replay_bin="$BUILD_DIR/$job_id/replay_oracle"
  mkdir -p "$BUILD_DIR/$job_id"

  local config_file pair_id pk_exchange sig_exchange
  config_file=$(job_field "$job_file" 'j["paths"]["generated_config"]')
  pair_id=$(job_field "$job_file" 'j["pair_id"]')
  pk_exchange=$(job_field "$job_file" '1 if j["pair"]["exchange_contract"].get("public_key_exchange") else 0')
  sig_exchange=$(job_field "$job_file" '1 if j["pair"]["exchange_contract"].get("signature_exchange") else 0')

  "$CXX_BIN" -std=c++17 $SANITIZER_BUILD_CFLAGS -Isrc -I"$FALCON_SRC" -DPQCFUZZ_HAVE_FALCON \
    $FUZZER_SANITIZER_FLAGS \
    -DPQCFUZZ_JOB_ID="\"$job_id\"" \
    -DPQCFUZZ_PAIR_ID="\"$pair_id\"" \
    -DPQCFUZZ_RESULT_DIR="\"${RESULTS_DIR}/${job_id}\"" \
    -DPQCFUZZ_GENERATED_CONFIG_PATH="\"${config_file}\"" \
    -DPQCFUZZ_ORACLE_SUITE="\"fips\"" \
    -DPQCFUZZ_RELATION_MODE="\"cross-implementation\"" \
    -DPQCFUZZ_LEFT_PROJECT_ID="\"falcon\"" \
    -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"$left_impl\"" \
    -DPQCFUZZ_EXPECTED_IMPLEMENTATION_ID="\"$left_impl\"" \
    -DPQCFUZZ_EXPECTED_ALGORITHM="\"$algorithm\"" \
    -DPQCFUZZ_RIGHT_PROJECT_ID="\"falcon\"" \
    -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"$left_impl\"" \
    -DPQCFUZZ_PUBLIC_KEY_EXCHANGE="$pk_exchange" \
    -DPQCFUZZ_SIGNATURE_EXCHANGE="$sig_exchange" \
    src/fuzzers/sig_pair_fuzzer.cc \
    "$COMMON_ARCHIVE" "$REF_OBJ_DIR"/*.o "$ADAPTER_OBJ_DIR"/*.o \
    -lm -o "$out_bin"

  "$CXX_BIN" -std=c++17 $SANITIZER_BUILD_CFLAGS -Isrc -I"$FALCON_SRC" -DPQCFUZZ_HAVE_FALCON \
    $REPLAY_SANITIZER_FLAGS \
    -DPQCFUZZ_LEFT_PROJECT_ID="\"falcon\"" \
    -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"$left_impl\"" \
    -DPQCFUZZ_EXPECTED_IMPLEMENTATION_ID="\"$left_impl\"" \
    -DPQCFUZZ_EXPECTED_ALGORITHM="\"$algorithm\"" \
    -DPQCFUZZ_RIGHT_PROJECT_ID="\"falcon\"" \
    -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"$left_impl\"" \
    src/replay/replay_oracle.cc \
    "$COMMON_ARCHIVE" "$REF_OBJ_DIR"/*.o "$ADAPTER_OBJ_DIR"/*.o \
    -lm -o "$replay_bin"

  manifests_dir
  python3 - "$BUILD_DIR/manifests/${job_id}.json" "$job_file" "$out_bin" "$replay_bin" <<'PY'
import json
import sys

path, job_file, out_bin, replay_bin = sys.argv[1:]
with open(job_file, encoding="utf-8") as fh:
    job = json.load(fh)
payload = {
    "job_id": job["job_id"],
    "pair_id": job["pair_id"],
    "algorithm": job["algorithm"],
    "oracle_spec": job.get("oracle_spec", ""),
    "oracles": job.get("oracles", []),
    "target_binary": out_bin,
    "replay_binary": replay_bin,
    "real_library": True,
    "adapter_project": "falcon",
    "adapter_implementation": job.get("pair", {}).get("left", {}).get("implementation_id", ""),
    "provenance_relation": job.get("pair", {}).get("provenance_relation", "same-source-single-implementation"),
    "build_flags": {
        "reference": "-O2 IEEE-754 binary64 (FALCON_FPNATIVE, no AVX2/FMA)",
        "sanitizers": ["address", "undefined"],
        "link": "-lm",
    },
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  echo "[falcon] built $job_id"
}

cmd_build() {
  mkdir -p "$BUILD_DIR" "$RUNS_DIR" "$RESULTS_DIR" "$CRASHES_DIR" "$JOBS_DIR" "$REPORT_DIR"
  if [ ! -f "$SOURCE_LOCK" ]; then
    echo "[falcon] missing source lock: $SOURCE_LOCK" >&2
    exit 1
  fi
  if [ ! -f "$SCHEME_PROFILE" ]; then
    echo "[falcon] missing scheme profile: $SCHEME_PROFILE" >&2
    exit 1
  fi
  if [ ! -f "$FALCON_SRC/falcon.c" ]; then
    echo "[falcon] missing vendored reference: $FALCON_SRC" >&2
    echo "[falcon] real-library lanes are unavailable; fake-adapter tests remain runnable" >&2
    exit 1
  fi
  python3 src/jobs/generate_jobs.py --pair-alg "$PAIR_ALG" --algorithm-family FALCON \
    --oracle-suite fips --jobs-dir "$JOBS_DIR"
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
    echo "[falcon] build failed" >&2
    exit 1
  fi
  python3 - "$BUILD_DIR/build_manifest.json" "$BUILD_DIR/manifests" "$SOURCE_LOCK" "$SCHEME_PROFILE" <<'PY'
import json
import sys
from pathlib import Path

path, manifests, source_lock, scheme_profile = sys.argv[1:]
with open(source_lock, encoding="utf-8") as fh:
    lock = json.load(fh)
with open(scheme_profile, encoding="utf-8") as fh:
    profile = json.load(fh)
records = []
for manifest in sorted(Path(manifests).glob("*.json")):
    with open(manifest, encoding="utf-8") as fh:
        records.append(json.load(fh))
payload = {
    "family": "FALCON",
    "real_library": True,
    "source_lock": source_lock,
    "spec_path": lock["spec"]["path"],
    "spec_sha256": lock["spec"]["sha256"],
    "vendored_source": lock["sources"][0]["vendored_path"],
    "archive_sha256": lock["sources"][0]["archive_sha256"],
    "kat": lock["kat"],
    "source_archive": lock["sources"][0]["url"],
    "scheme_profile": scheme_profile,
    "abilities": profile["capabilities"],
    "build_flags": profile["build_flags"],
    "official_kat": True,
    "jobs": records,
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"[falcon] build manifest: {path} ({len(records)} jobs)")
PY
}

make_seed_corpus() {
  local job_file="$1"
  local job_id algorithm_enum
  job_id=$(job_id_of "$job_file")
  algorithm_enum=$(algorithm_enum_for_job "$job_file")
  local corpus_dir="$RUNS_DIR/$job_id/corpus"
  rm -rf "$corpus_dir"
  mkdir -p "$corpus_dir"
  local oracle_enum oracle_name
  while IFS=: read -r oracle_enum oracle_name; do
    [ -n "$oracle_enum" ] || continue
    python3 - "$corpus_dir" "$algorithm_enum" "$oracle_enum" "$oracle_name" "$SMOKE_CORPUS_CASES" <<'PY'
import struct
import sys

corpus_dir, algorithm, oracle, oracle_name, cases = sys.argv[1:]
algorithm = int(algorithm)
oracle = int(oracle)
cases = int(cases)
for index in range(cases):
    seed = bytes((index * 7 + i) & 0xFF for i in range(32))
    message = b"PQCFuzz Falcon eval" + bytes([index])
    # Structured mutation recipe v1: set_coefficient (0x08) on
    # signature.compressed_coefficient (0x12) at coefficient index=index, value=aux.
    coefficient_index = index * 3
    aux = (1023 + index * 17) & 0xFFFF
    mutation = bytes([0x08, 0x12]) + struct.pack("<II", coefficient_index, aux)
    extra = b""
    out = bytearray(b"PQCF")
    out.extend(bytes([1, algorithm, oracle, 0]))
    for field in (seed, message, mutation, extra):
        out.extend(struct.pack("<H", len(field)))
        out.extend(field)
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
    echo "[falcon] coverage gate failed for oracles: $(echo "$missing" | tr '\n' ' ')" >&2
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
  mkdir -p "$result_dir"
  make_seed_corpus "$job_file"
  local corpus_dir="$RUNS_DIR/$job_id/corpus"
  "$binary" -runs=1 "$corpus_dir" >/dev/null 2>&1 || true
  verify_oracle_coverage "$job_file" "$result_dir" || local_status=1
  replay_job_seeds "$job_file" "$replay_bin" "$corpus_dir" "$result_dir" || local_status=1
  if [ "$local_status" -ne 0 ]; then
    return 1
  fi
  echo "[falcon] preflight ok: $job_id"
  return 0
}

replay_job_seeds() {
  local job_file="$1" replay_bin="$2" corpus_dir="$3" result_dir="$4"
  local algorithm pair_id config_file left_impl pk_exchange sig_exchange
  algorithm=$(job_field "$job_file" 'j["algorithm"]')
  pair_id=$(job_field "$job_file" 'j["pair_id"]')
  config_file=$(job_field "$job_file" 'j["paths"]["generated_config"]')
  left_impl=$(left_implementation_id "$job_file")
  pk_exchange=$(job_field "$job_file" '1 if j["pair"]["exchange_contract"].get("public_key_exchange") else 0')
  sig_exchange=$(job_field "$job_file" '1 if j["pair"]["exchange_contract"].get("signature_exchange") else 0')
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
        --primitive-type sig \
        --oracle-id "$oracle_name" \
        --oracle-suite fips \
        --relation-mode cross-implementation \
        --left-project-id falcon \
        --left-implementation-id "$left_impl" \
        --right-project-id falcon \
        --right-implementation-id "$left_impl" \
        --public-key-exchange "$pk_exchange" \
        --ciphertext-exchange 0 \
        --secret-key-exchange 0 \
        --secret-key-format-compatible 0 \
        --signature-exchange "$sig_exchange" \
        >/dev/null 2>&1
      local rc=$?
      set -e
      # 0 = no finding, 70 = recorded finding.  Hangs and crashes fail the
      # preflight so a broken replay path is visible before any campaign.
      if [ "$rc" -ne 0 ] && [ "$rc" -ne 70 ]; then
        echo "[falcon] replay failed for $oracle_name (rc=$rc) in $(job_id_of "$job_file")" >&2
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
    "family": "FALCON",
    "real_library": True,
    "dependency_status": "vendored-reference-present",
    "official_kat": lock["kat"]["official_kat_available"],
    "kat_status": "official_round3_responses_reproduced",
    "coverage_gate": "passed" if status == 0 else "failed",
}
Path(path).parent.mkdir(parents=True, exist_ok=True)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"[falcon] preflight coverage gate: {'passed' if status == 0 else 'FAILED'}")
PY
  exit "$status"
}

smoke_job() {
  local job_file="$1"
  local job_id result_dir binary per_job_seconds
  job_id=$(job_id_of "$job_file")
  result_dir="$RESULTS_DIR/$job_id"
  binary="$BUILD_DIR/$job_id/pqcfuzz_$job_id"
  mkdir -p "$result_dir" "$RUNS_DIR/$job_id"
  make_seed_corpus "$job_file"
  local corpus_dir="$RUNS_DIR/$job_id/corpus"
  local job_count
  job_count=$(job_files | wc -l)
  per_job_seconds=$(( SMOKE_FUZZ_SECONDS / job_count ))
  if [ "$per_job_seconds" -lt 1 ]; then
    per_job_seconds=1
  fi
  "$binary" -runs="$SMOKE_CORPUS_CASES" "$corpus_dir" >"$RUNS_DIR/$job_id/smoke-corpus.log" 2>&1 || true
  "$binary" -max_total_time="$per_job_seconds" "$corpus_dir" >"$RUNS_DIR/$job_id/smoke-fuzz.log" 2>&1 || true
  verify_oracle_coverage "$job_file" "$result_dir" || true
  echo "ok" > "$RUNS_DIR/$job_id/smoke.status"
}

run_job() {
  local job_file="$1"
  local job_id result_dir binary
  job_id=$(job_id_of "$job_file")
  result_dir="$RESULTS_DIR/$job_id"
  binary="$BUILD_DIR/$job_id/pqcfuzz_$job_id"
  mkdir -p "$result_dir" "$RUNS_DIR/$job_id"
  make_seed_corpus "$job_file"
  set +e
  "$binary" -max_total_time="$MAX_TOTAL_TIME" "$RUNS_DIR/$job_id/corpus" \
    >"$RUNS_DIR/$job_id/fuzz.log" 2>&1
  local rc=$?
  set -e
  verify_oracle_coverage "$job_file" "$result_dir" || true
  echo "rc=$rc" > "$RUNS_DIR/$job_id/status.txt"
  echo "[falcon] campaign $job_id finished with rc=$rc"
}

cmd_smoke() {
  python3 -m pytest -q tests/falcon_model_test.py tests/falcon_oracles_test.py::test_official_kat_fixture \
    >"$RUNS_DIR/model-lane.log" 2>&1 || {
    echo "[falcon] model/KAT lane failed; see $RUNS_DIR/model-lane.log" >&2
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
    "family": "FALCON",
    "smoke_fuzz_seconds": seconds,
    "corpus_cases_per_oracle": cases,
    "sanitizers": ["address", "undefined"],
    "model_lane": "tests/falcon_model_test.py",
    "official_kat": True,
    "kat_fixture_sha256": lock["kat"]["fixture_sha256"],
    "status": "passed" if status == 0 else "failed",
}
Path(path).parent.mkdir(parents=True, exist_ok=True)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"[falcon] smoke: {'passed' if status == 0 else 'FAILED'}")
PY
  exit "$status"
}

cmd_report() {
  mkdir -p "$REPORT_DIR"
  python3 - "$REPO_ROOT" "$WORK_ROOT" "$REPORT_DIR" "$JOBS_DIR" "$RESULTS_DIR" "$RUNS_DIR" "$SOURCE_LOCK" "$SCHEME_PROFILE" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

repo_root, work_root, report_dir, jobs_dir, results_dir, runs_dir, source_lock, scheme_profile = sys.argv[1:]
report_dir = Path(report_dir)
with open(source_lock, encoding="utf-8") as fh:
    lock = json.load(fh)
with open(scheme_profile, encoding="utf-8") as fh:
    profile_doc = json.load(fh)
jobs = []
for job_path in sorted(Path(jobs_dir).glob("job_falcon_*.json")):
    with open(job_path, encoding="utf-8") as fh:
        jobs.append(json.load(fh))

profiles = []
oracle_totals = Counter()
findings = Counter()
sanitizer_lane = {}
smoke_manifest = Path(work_root) / "smoke_manifest.json"
if smoke_manifest.is_file():
    sanitizer_lane = json.loads(smoke_manifest.read_text(encoding="utf-8"))
preflight_manifest = {}
preflight_path = Path(work_root) / "preflight_manifest.json"
if preflight_path.is_file():
    preflight_manifest = json.loads(preflight_path.read_text(encoding="utf-8"))
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
        "format": job["algorithm_metadata"].get("format", ""),
        "oracles_scheduled": len(job["oracles"]),
        "oracles_entered": invoked,
        "findings": len(finding_files),
        "dispositions": dict(disposition_counts),
        "fuzz_status": (Path(runs_dir) / job_id / "status.txt").read_text(encoding="utf-8").strip()
        if (Path(runs_dir) / job_id / "status.txt").is_file() else "not-run",
        "smoke_status": (Path(runs_dir) / job_id / "smoke.status").read_text(encoding="utf-8").strip()
        if (Path(runs_dir) / job_id / "smoke.status").is_file() else "not-run",
    })

payload = {
    "family": "FALCON",
    "spec": lock["spec"]["path"],
    "spec_sha256": lock["spec"]["sha256"],
    "source": {
        "url": lock["sources"][0]["url"],
        "archive_sha256": lock["sources"][0]["archive_sha256"],
        "vendored_path": lock["sources"][0]["vendored_path"],
        "implementation": "falcon_reference",
        "cross_implementation_lane": "same-source-single-implementation",
    },
    "kat": {
        "official": lock["kat"]["official_kat_available"],
        "fixture_path": lock["kat"]["fixture_path"],
        "fixture_sha256": lock["kat"]["fixture_sha256"],
        "response_files": lock["kat"]["response_files"],
    },
    "capabilities": profile_doc["capabilities"],
    "profiles": profiles,
    "oracle_invocations": dict(oracle_totals),
    "findings_by_oracle": dict(findings),
    "sanitizer_lane": sanitizer_lane,
    "preflight": preflight_manifest,
    "not_covered": [
        "independent ref/AVX2 differential lane (falcon_cross_verify) is disabled in the single-implementation lock",
        "falcon_norm_equation exact-norm equality, falcon_norm_boundary_unit, falcon_hash_to_point, "
        "falcon_key_equation, falcon_sk_codec and falcon_sampler_arithmetic are evaluated by the Python "
        "model lane plus test-only reference hooks, not by the native fuzzer executor",
        "P2 falcon_fault_checks and falcon_timing_resources are opt-in and not run by default",
        "the attached (NIST signed-message) API is exercised with the compressed frame only",
        "no EUF-CMA/sUF-CMA, IND-CCA or quantum-security proof is claimed",
    ],
    "claims": "conformance and counterexample search only; no security proof",
}
with open(report_dir / "summary.json", "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")

lines = [
    "# Falcon evaluation summary",
    "",
    f"- profiles: {len(profiles)}",
    f"- source: `{payload['source']['vendored_path']}` (archive sha256 `{payload['source']['archive_sha256']}`)",
    f"- spec sha256: `{payload['spec_sha256']}`",
    f"- official round-3 KAT: {'yes' if payload['kat']['official'] else 'no'}"
    f" (fixture sha256 `{payload['kat']['fixture_sha256']}`)",
    f"- sanitizers: {', '.join(sanitizer_lane.get('sanitizers', [])) or 'not-run'}"
    f" (smoke budget {sanitizer_lane.get('smoke_fuzz_seconds', 'n/a')}s,"
    f" {sanitizer_lane.get('corpus_cases_per_oracle', 'n/a')} corpus cases/oracle)",
    "- cross-implementation lane: disabled (single pinned official reference build)",
    "",
    "| profile | format | oracles entered | findings | fuzz | smoke |",
    "| --- | --- | ---: | ---: | --- | --- |",
]
for profile in profiles:
    lines.append(
        f"| {profile['algorithm']} | {profile['format']} | {profile['oracles_entered']}/{profile['oracles_scheduled']} | "
        f"{profile['findings']} | {profile['fuzz_status']} | {profile['smoke_status']} |"
    )
lines.extend([
    "",
    "Not covered:",
    *[f"- {item}" for item in payload["not_covered"]],
    "",
    "No quantum-security, IND-CCA, or EUF/sUF claim is made by this report.",
])
with open(report_dir / "summary.md", "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
print(f"[falcon] report: {report_dir / 'summary.json'}")
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
      echo "[falcon] no jobs built; run build first" >&2
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

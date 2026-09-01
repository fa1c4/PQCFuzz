#!/usr/bin/env bash
# PQCFuzz evaluation driver for PQMagic Aigis-Enc / Aigis-Sig.
#
# Mirrors scripts/pqcfuzz_eval.sh's liboqs workflow:
#   1. builds PQMagic twice (SM3 and SHAKE) with sanitizer-friendly flags,
#   2. renames the SHAKE archive symbols so both hash variants can be linked
#      into one differential binary,
#   3. generates jobs from src/config/pair_alg.aigis.json,
#   4. builds one libFuzzer binary per job/oracle-suite,
#   5. preflights each oracle with a seed corpus and runs the campaign.
#
# Usage:
#   scripts/pqcfuzz_aigis_eval.sh build            # build PQMagic + all fuzzers
#   scripts/pqcfuzz_aigis_eval.sh preflight        # single -runs=1 per oracle
#   scripts/pqcfuzz_aigis_eval.sh run              # campaign per job
#   scripts/pqcfuzz_aigis_eval.sh all              # build + preflight + run
#
# Environment:
#   ORACLE_SUITE=fips|metamorphic   (default fips)
#   ORACLE_SET=all|security         (default all)
#   TARGET_RUNTIME=pqmagic          (metamorphic single-target runtime)
#   MAX_TOTAL_TIME=seconds          (campaign budget, default 120)
#   INPUT_TIMEOUT_SECONDS=30
#   RSS_LIMIT_MB=2048
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

PQMAGIC_SRC="${REPO_ROOT}/third_party/PQMagic"
WORKSPACE_ROOT_ABS="${REPO_ROOT}/workspace"
WORKSPACE_ROOT_REL="workspace"
BUILD_ROOT="${WORKSPACE_ROOT_ABS}/build"
SM3_BUILD_DIR="${BUILD_ROOT}/pqmagic-sm3"
SHAKE_BUILD_DIR="${BUILD_ROOT}/pqmagic-shake"
SM3_ARCHIVE="${SM3_BUILD_DIR}/libpqmagic_std.a"
SHAKE_ARCHIVE="${SHAKE_BUILD_DIR}/libpqmagic_std.a"
SHAKE_RENAMED_ARCHIVE="${SHAKE_BUILD_DIR}/libpqmagic_shake_renamed.a"
PQMAGIC_PREFIX="pqmagic_shake_"
PQMAGIC_CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined"
FUZZER_SANITIZER_FLAGS="-fsanitize=fuzzer,address,undefined"

PAIR_ALG="${PAIR_ALG:-src/config/pair_alg.aigis.json}"
ORACLE_SUITE="${ORACLE_SUITE:-fips}"
ORACLE_SET="${ORACLE_SET:-all}"
TARGET_RUNTIME="${TARGET_RUNTIME:-pqmagic}"
TARGET_VERSION="${TARGET_VERSION:-}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-120}"
INPUT_TIMEOUT_SECONDS="${INPUT_TIMEOUT_SECONDS:-30}"
RSS_LIMIT_MB="${RSS_LIMIT_MB:-2048}"
JOBS=1

build_pqmagic() {
  local build_dir="$1" hash_opt="$2"
  cmake -S "$PQMAGIC_SRC" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DPQMAGIC_DISABLE_DEFAULT_OPTS=ON \
    -DCMAKE_C_FLAGS="$PQMAGIC_CFLAGS" \
    -DCMAKE_CXX_FLAGS="$PQMAGIC_CFLAGS" \
    -DENABLE_KYBER=OFF -DENABLE_ML_KEM=OFF -DENABLE_DILITHIUM=OFF \
    -DENABLE_ML_DSA=OFF -DENABLE_SLH_DSA=OFF -DENABLE_SPHINCS_A=OFF \
    -DENABLE_AIGIS_ENC=ON -DENABLE_AIGIS_SIG=ON \
    "$hash_opt" \
    -DAIGIS_ENC_MODES="1;2;3;4" -DAIGIS_SIG_MODES="1;2;3" \
    -DENABLE_TEST=OFF -DENABLE_BENCH=OFF
  cmake --build "$build_dir" --target pqmagic_static_target --parallel 32
}

build_libs() {
  mkdir -p "$BUILD_ROOT"
  build_pqmagic "$SM3_BUILD_DIR" -DUSE_SM3=ON
  build_pqmagic "$SHAKE_BUILD_DIR" -DUSE_SHAKE=ON
  python3 scripts/rename_pqmagic_symbols.py "$SHAKE_ARCHIVE" "$PQMAGIC_PREFIX" "$SHAKE_RENAMED_ARCHIVE"
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

oracle_specs_for_job() {
  local job_file="$1"
  python3 - "$job_file" <<'PY'
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

algorithm_enum_for_job() {
  local job_file="$1"
  python3 - "$job_file" <<'PY'
import json
import sys

sys.path.insert(0, "src")
from replay.replay_one import ALGORITHM_ENUM_BY_NAME

with open(sys.argv[1], encoding="utf-8") as fh:
    job = json.load(fh)
print(ALGORITHM_ENUM_BY_NAME.get(job["algorithm"], 0))
PY
}

left_impl_for_job() {
  local job_file="$1"
  python3 - "$job_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    job = json.load(fh)
if "pair" in job:
    print(job["pair"]["left"]["implementation_id"])
else:
    print(job["target"]["implementation_id"])
PY
}

right_impl_for_job() {
  local job_file="$1"
  python3 - "$job_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    job = json.load(fh)
if "pair" in job:
    print(job["pair"]["right"]["implementation_id"])
else:
    print("")
PY
}

job_pair_id() {
  local job_file="$1"
  python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['pair_id'])" "$job_file"
}

oracle_suite_for_job() {
  local job_file="$1"
  python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('oracle_suite','fips'))" "$job_file"
}

relation_mode_for_job() {
  local job_file="$1"
  python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('relation_mode','cross-implementation'))" "$job_file"
}

generate_jobs() {
  local extra=()
  if [ "$ORACLE_SUITE" = "metamorphic" ]; then
    extra+=(--oracle-suite metamorphic --relation-mode single-target --target-runtime "$TARGET_RUNTIME")
    [ -n "$TARGET_VERSION" ] && extra+=(--target-version "$TARGET_VERSION")
  fi
  python3 src/jobs/generate_jobs.py --pair-alg "$PAIR_ALG" \
    --algorithm-family AIGIS-ENC "${extra[@]}"
  python3 src/jobs/generate_jobs.py --pair-alg "$PAIR_ALG" \
    --algorithm-family AIGIS-SIG "${extra[@]}"
}

common_sources() {
  cat <<EOF
src/adapters/status.cc
src/adapters/rng_control.cc
src/adapters/liboqs/rng_control.cc
src/adapters/liboqs/kem_adapter.cc
src/adapters/liboqs/sig_adapter.cc
src/adapters/pqclean/kem_adapter.cc
src/adapters/pqclean/sig_adapter.cc
src/adapters/pqmagic/kem_adapter.cc
src/adapters/pqmagic/sig_adapter.cc
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
src/mutators/aigis_enc_layout.cc
src/mutators/aigis_enc_mutator.cc
src/mutators/aigis_sig_layout.cc
src/mutators/aigis_sig_mutator.cc
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
EOF
}

build_target() {
  local job_file="$1"
  local job_id primitive algorithm left_impl right_impl source algorithm_enum oracle_csv
  job_id=$(basename "$job_file" .json)
  primitive=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['primitive_type'])" "$job_file")
  algorithm=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['algorithm'])" "$job_file")
  left_impl=$(left_impl_for_job "$job_file")
  right_impl=$(right_impl_for_job "$job_file")
  algorithm_enum=$(algorithm_enum_for_job "$job_file")
  oracle_csv=$(oracle_specs_for_job "$job_file" | cut -d: -f1 | paste -sd, -)
  [ -n "$oracle_csv" ] || { echo "no scheduled oracles for ${job_file}" >&2; return 1; }

  if [ "$primitive" = "kem" ]; then
    source=src/fuzzers/kem_pair_fuzzer.cc
  else
    source=src/fuzzers/sig_pair_fuzzer.cc
  fi

  local build_dir="${WORKSPACE_ROOT_ABS}/build/${job_id}"
  local out_bin="${build_dir}/pqcfuzz_${job_id}"
  local config_file="${WORKSPACE_ROOT_ABS}/tmp/${job_id}/generated_config.json"
  mkdir -p "$build_dir"

  local sources=()
  while IFS= read -r src_file; do
    [ -n "$src_file" ] && sources+=("$src_file")
  done < <(common_sources)

  local project_id="pqmagic"
  local suite relation_mode right_args
  suite=$(oracle_suite_for_job "$job_file")
  relation_mode=$(relation_mode_for_job "$job_file")
  if [ -n "$right_impl" ]; then
    right_args=(
      -DPQCFUZZ_RIGHT_PROJECT_ID="\"${project_id}\""
      -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"${right_impl}\""
    )
  else
    right_args=(
      -DPQCFUZZ_RIGHT_PROJECT_ID="\"${project_id}\""
      -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"${left_impl}\""
    )
  fi
  clang++ -std=c++17 -O1 -g -fno-omit-frame-pointer -Isrc \
    -I"$SM3_BUILD_DIR" -I"$SHAKE_BUILD_DIR" \
    "$FUZZER_SANITIZER_FLAGS" \
    -DPQCFUZZ_HAVE_PQMAGIC \
    -DPQCFUZZ_JOB_ID="\"${job_id}\"" \
    -DPQCFUZZ_PAIR_ID="\"$(job_pair_id "$job_file")\"" \
    -DPQCFUZZ_RESULT_DIR="\"${WORKSPACE_ROOT_REL}/results/${job_id}\"" \
    -DPQCFUZZ_GENERATED_CONFIG_PATH="\"${config_file}\"" \
    -DPQCFUZZ_ORACLE_SUITE="\"${suite}\"" \
    -DPQCFUZZ_RELATION_MODE="\"${relation_mode}\"" \
    -DPQCFUZZ_LEFT_PROJECT_ID="\"${project_id}\"" \
    -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"${left_impl}\"" \
    -DPQCFUZZ_EXPECTED_IMPLEMENTATION_ID="\"${left_impl}\"" \
    -DPQCFUZZ_EXPECTED_ALGORITHM="\"${algorithm}\"" \
    -DPQCFUZZ_FIXED_ALGORITHM_ID="${algorithm_enum}" \
    -DPQCFUZZ_ALLOWED_ORACLE_IDS="\"${oracle_csv}\"" \
    "${right_args[@]}" \
    -DPQCFUZZ_PUBLIC_KEY_EXCHANGE=0 -DPQCFUZZ_CIPHERTEXT_EXCHANGE=0 \
    -DPQCFUZZ_SECRET_KEY_EXCHANGE=0 -DPQCFUZZ_SECRET_KEY_FORMAT_COMPATIBLE=0 \
    -DPQCFUZZ_SIGNATURE_EXCHANGE=0 \
    "$source" "${sources[@]}" "$SM3_ARCHIVE" "$SHAKE_RENAMED_ARCHIVE" \
    -lcrypto -ldl -lpthread -lm -o "$out_bin"
  echo "$out_bin"
}

make_seed_corpus() {
  local corpus_dir="$1" job_file="$2" algorithm_enum="$3"
  local spec oracle_enum oracle_name
  mkdir -p "$corpus_dir"
  while IFS=: read -r oracle_enum oracle_name; do
    [ -n "$oracle_enum" ] || continue
    make_seed "${corpus_dir}/seed-pqcfuzz-${oracle_name}.bin" "$algorithm_enum" "$oracle_enum"
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
    echo "[preflight] FAIL: oracles without executions: $(echo "$missing" | tr '\n' ' ')" >&2
    return 1
  fi
}

preflight_job() {
  local job_file="$1"
  local job_id=$(basename "$job_file" .json)
  local build_dir="${WORKSPACE_ROOT_ABS}/build/${job_id}"
  local binary="${build_dir}/pqcfuzz_${job_id}"
  local corpus_dir="${WORKSPACE_ROOT_ABS}/runs/${job_id}/corpus"
  local result_dir="${WORKSPACE_ROOT_ABS}/results/${job_id}"
  local algorithm_enum
  algorithm_enum=$(algorithm_enum_for_job "$job_file")
  mkdir -p "$corpus_dir" "$result_dir"
  make_seed_corpus "$corpus_dir" "$job_file" "$algorithm_enum"
  if [ ! -x "$binary" ]; then
    binary=$(build_target "$job_file")
  fi
  ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 \
    timeout $((INPUT_TIMEOUT_SECONDS + 60)) "$binary" "$corpus_dir" -runs=1 \
    >"${WORKSPACE_ROOT_ABS}/runs/${job_id}/preflight.log" 2>&1 || true
  if ! verify_oracle_coverage "$job_file" "$result_dir"; then
    echo "[preflight] ${job_id} FAILED coverage gate" >&2
    return 1
  fi
  echo "[preflight] ${job_id} done (all scheduled oracles executed)"
}

run_job() {
  local job_file="$1"
  local job_id=$(basename "$job_file" .json)
  local build_dir="${WORKSPACE_ROOT_ABS}/build/${job_id}"
  local binary="${build_dir}/pqcfuzz_${job_id}"
  local corpus_dir="${WORKSPACE_ROOT_ABS}/runs/${job_id}/corpus"
  local crash_dir="${WORKSPACE_ROOT_ABS}/crashes/${job_id}"
  local result_dir="${WORKSPACE_ROOT_ABS}/results/${job_id}"
  local log_file="${WORKSPACE_ROOT_ABS}/runs/${job_id}/fuzz-${job_id}.log"
  local status_file="${WORKSPACE_ROOT_ABS}/runs/${job_id}/status.txt"
  local status rc
  mkdir -p "$corpus_dir" "$crash_dir" "$result_dir"
  ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 \
    timeout --preserve-status $((MAX_TOTAL_TIME + INPUT_TIMEOUT_SECONDS + 60)) \
    "$binary" "$corpus_dir" "-artifact_prefix=${crash_dir}/" \
    "-max_total_time=${MAX_TOTAL_TIME}" "-timeout=${INPUT_TIMEOUT_SECONDS}" \
    "-rss_limit_mb=${RSS_LIMIT_MB}" >"$log_file" 2>&1
  rc=$?
  if grep -q "DONE" "$log_file"; then
    status="ok"
  elif [ "$rc" -eq 0 ]; then
    status="no_done"
  elif [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] || [ "$rc" -eq 143 ]; then
    status="timeout_or_killed"
  else
    status="crash_or_error(rc=$rc)"
  fi
  echo "$status" > "$status_file"
  echo "[run] ${job_id} finished status=${status}; see ${log_file}"
}

build_replay() {
  local job_file="$1"
  local job_id primitive algorithm left_impl right_impl
  job_id=$(basename "$job_file" .json)
  primitive=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['primitive_type'])" "$job_file")
  algorithm=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['algorithm'])" "$job_file")
  left_impl=$(left_impl_for_job "$job_file")
  right_impl=$(right_impl_for_job "$job_file")
  local build_dir="${WORKSPACE_ROOT_ABS}/build/${job_id}"
  local out_bin="${build_dir}/replay_oracle"
  local config_file="${WORKSPACE_ROOT_ABS}/tmp/${job_id}/generated_config.json"
  local sources=()
  while IFS= read -r src_file; do
    [ -n "$src_file" ] && sources+=("$src_file")
  done < <(common_sources)
  local right_args
  if [ -n "$right_impl" ]; then
    right_args=(
      -DPQCFUZZ_RIGHT_PROJECT_ID="\"pqmagic\""
      -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"${right_impl}\""
    )
  else
    right_args=(
      -DPQCFUZZ_RIGHT_PROJECT_ID="\"pqmagic\""
      -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"${left_impl}\""
    )
  fi
  clang++ -std=c++17 -O1 -g -fno-omit-frame-pointer -Isrc \
    -I"$SM3_BUILD_DIR" -I"$SHAKE_BUILD_DIR" \
    -fsanitize=address,undefined \
    -DPQCFUZZ_HAVE_PQMAGIC \
    -DPQCFUZZ_JOB_ID="\"${job_id}\"" \
    -DPQCFUZZ_PAIR_ID="\"$(job_pair_id "$job_file")\"" \
    -DPQCFUZZ_RESULT_DIR="\"${WORKSPACE_ROOT_REL}/results/${job_id}\"" \
    -DPQCFUZZ_GENERATED_CONFIG_PATH="\"${config_file}\"" \
    -DPQCFUZZ_LEFT_PROJECT_ID="\"pqmagic\"" \
    -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"${left_impl}\"" \
    -DPQCFUZZ_EXPECTED_IMPLEMENTATION_ID="\"${left_impl}\"" \
    -DPQCFUZZ_EXPECTED_ALGORITHM="\"${algorithm}\"" \
    "${right_args[@]}" \
    src/replay/replay_oracle.cc "${sources[@]}" \
    "$SM3_ARCHIVE" "$SHAKE_RENAMED_ARCHIVE" \
    -lcrypto -ldl -lpthread -lm -o "$out_bin"
  echo "$out_bin"
}

cmd_build() {
  [ -s "$SM3_ARCHIVE" ] || build_libs
  [ -s "$SHAKE_RENAMED_ARCHIVE" ] || python3 scripts/rename_pqmagic_symbols.py "$SHAKE_ARCHIVE" "$PQMAGIC_PREFIX" "$SHAKE_RENAMED_ARCHIVE"
  generate_jobs
  local job_files=()
  for job_file in workspace/jobs/job_aigis*.json; do
    [ -f "$job_file" ] || continue
    job_filter_matches "$job_file" || continue
    job_files+=("$job_file")
  done
  local build_workers="${BUILD_WORKERS:-8}"
  local idx=0 pids=()
  for job_file in "${job_files[@]}"; do
    idx=$((idx + 1))
    (build_target "$job_file" && build_replay "$job_file") > "/tmp/aigis_build_${idx}.log" 2>&1 &
    pids+=($!)
    if [ "${#pids[@]}" -ge "$build_workers" ]; then
      wait "${pids[0]}"; pids=("${pids[@]:1}")
    fi
  done
  for pid in "${pids[@]}"; do wait "$pid"; done
}

cmd_preflight() {
  for job_file in workspace/jobs/job_aigis*.json; do
    [ -f "$job_file" ] || continue
    job_filter_matches "$job_file" || continue
    preflight_job "$job_file"
  done
}

cmd_run() {
  for job_file in workspace/jobs/job_aigis*.json; do
    [ -f "$job_file" ] || continue
    job_filter_matches "$job_file" || continue
    run_job "$job_file"
  done
}

job_filter_matches() {
  local job_file="$1"
  [ -z "${JOB_FILTER:-}" ] && return 0
  [[ "$job_file" == *"${JOB_FILTER}"* ]]
}

cmd_run_parallel() {
  local workers="${WORKERS:-8}"
  local pids=() job_id
  for job_file in workspace/jobs/job_aigis*.json; do
    [ -f "$job_file" ] || continue
    job_filter_matches "$job_file" || continue
    job_id=$(basename "$job_file" .json)
    (run_job "$job_file" > "${WORKSPACE_ROOT_ABS}/runs/${job_id}/driver.log" 2>&1) &
    pids+=($!)
    if [ "${#pids[@]}" -ge "$workers" ]; then
      wait "${pids[0]}"
      pids=("${pids[@]:1}")
    fi
  done
  for pid in "${pids[@]}"; do wait "$pid"; done
}

cmd_clean_results() {
  for job_file in workspace/jobs/job_aigis*.json; do
    [ -f "$job_file" ] || continue
    local job_id=$(basename "$job_file" .json)
    rm -rf \
      "${WORKSPACE_ROOT_ABS}/results/${job_id}" \
      "${WORKSPACE_ROOT_ABS}/crashes/${job_id}" \
      "${WORKSPACE_ROOT_ABS}/runs/${job_id}"
  done
  echo "cleaned aigis result/crash/run directories"
}

case "${1:-all}" in
  build-libs) build_libs ;;
  build) cmd_build ;;
  preflight) cmd_preflight ;;
  run) cmd_run ;;
  run-parallel) cmd_run_parallel ;;
  clean-results) cmd_clean_results ;;
  all)
    build_libs
    cmd_build
    cmd_preflight
    cmd_run
    ;;
  *)
    echo "usage: $0 {build-libs|build|preflight|run|run-parallel|clean-results|all}" >&2
    exit 2
    ;;
esac

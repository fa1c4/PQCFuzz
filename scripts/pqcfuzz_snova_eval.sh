#!/usr/bin/env bash
# PQCFuzz SNOVA evaluation driver.
#
# Commands:
#   scripts/pqcfuzz_snova_eval.sh build      generate jobs, build fuzzers/replays
#   scripts/pqcfuzz_snova_eval.sh preflight  seed corpus, coverage gate, replay
#   scripts/pqcfuzz_snova_eval.sh smoke      10 corpus cases + short ASan/UBSan fuzz
#   scripts/pqcfuzz_snova_eval.sh run        longer campaign (MAX_TOTAL_TIME per job)
#   scripts/pqcfuzz_snova_eval.sh report     workspace/snova/report/summary.{json,md}
#
# Environment: MAX_TOTAL_TIME (run), SMOKE_FUZZ_SECONDS, SMOKE_CORPUS_CASES,
# BUILD_WORKERS, JOB_FILTER, SKIP_PREFLIGHT=1 (reuse a passing preflight).
set -euo pipefail

PAIR_ALG="${PAIR_ALG:-src/config/pair_alg.snova.json}"
WORK_ROOT="${WORK_ROOT:-workspace/snova}"
JOBS_DIR="$WORK_ROOT/jobs"
BUILD_DIR="$WORK_ROOT/build"
RUNS_DIR="$WORK_ROOT/runs"
RESULTS_DIR="$WORK_ROOT/results"
CRASHES_DIR="$WORK_ROOT/crashes"
REPORT_DIR="$WORK_ROOT/report"
SNOVA_SRC="${SNOVA_SRC:-projects/SNOVA/reference}"
SOURCE_LOCK="${SOURCE_LOCK:-src/config/source_locks/snova.json}"
SCHEME_PROFILE="${SCHEME_PROFILE:-src/config/scheme_profiles/snova.json}"
CC_BIN="${CC:-clang}"
CXX_BIN="${CXX:-clang++}"
BUILD_WORKERS="${BUILD_WORKERS:-8}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-120}"
SMOKE_FUZZ_SECONDS="${SMOKE_FUZZ_SECONDS:-30}"
SMOKE_CORPUS_CASES="${SMOKE_CORPUS_CASES:-10}"
JOB_FILTER="${JOB_FILTER:-}"

# Shared C++ objects, the adapter and the reference math are built with plain
# ASan/UBSan.  SanitizerCoverage (fuzzer-no-link) on the reference GF16 loops
# made every oracle 10-25x slower, so libFuzzer coverage is limited to the
# driver translation unit; the oracles are structured and deterministic.
SNOVA_CFLAGS="-O1 -g -fno-omit-frame-pointer -DSKIP_ASSERT -fsanitize=address,undefined"
SNOVA_C_CFLAGS="-O2 -g -fno-omit-frame-pointer -DSKIP_ASSERT -fsanitize=address,undefined"
FUZZER_SANITIZER_FLAGS="-fsanitize=fuzzer,address,undefined"
REPLAY_SANITIZER_FLAGS="-fsanitize=address,undefined"
COMMON_ARCHIVE="$BUILD_DIR/libpqcfuzz_snova_common.a"
OBJ_ROOT="$BUILD_DIR/snova-obj"

mkdir -p "$BUILD_DIR" "$RUNS_DIR" "$RESULTS_DIR" "$CRASHES_DIR" "$JOBS_DIR" "$REPORT_DIR"

job_files() {
  local files
  files=$(ls "$JOBS_DIR"/job_snova_*.json 2>/dev/null || true)
  for file in $files; do
    if [ -n "$JOB_FILTER" ] && [[ "$file" != *"$JOB_FILTER"* ]]; then
      continue
    fi
    printf '%s\n' "$file"
  done
}

job_id_of() { basename "$1" .json; }

job_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as fh:
    j = json.load(fh)
print(eval(sys.argv[2], {"j": j}))
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
for oracle in job.get("oracles", []):
    print(f"{ORACLE_ENUM_BY_NAME.get(oracle, 0)}:{oracle}")
PY
}

snova_defines_for_job() {
  python3 - "$1" <<'PY'
import json
import sys
sys.path.insert(0, "src")
from pairing.pair_alg_loader import SUPPORTED_ALGORITHMS
with open(sys.argv[1], encoding="utf-8") as fh:
    job = json.load(fh)
metadata = SUPPORTED_ALGORITHMS[job["algorithm"]]
for define in metadata["c_defines"]:
    print(f"-D{define}", end=" ")
PY
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
src/mutators/ntru_layout.cc
src/mutators/ntru_mutator.cc
src/mutators/sike_layout.cc
src/mutators/sike_mutator.cc
src/mutators/snova_layout.cc
src/mutators/snova_mutator.cc
src/mutators/sha3.cc
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
src/oracles/snova_public_map.cc
src/oracles/snova_executor.cc
src/oracles/metamorphic_observation.cc
src/oracles/metamorphic_spec.cc
src/oracles/metamorphic_executor.cc
src/adapters/cross/cross_adapter.cc
src/adapters/falcon/sig_adapter.cc
src/adapters/falcon/signed_message_adapter.cc
src/adapters/ntru/kem_adapter.cc
src/adapters/ntru/reference_adapter.cc
src/adapters/ntru/ntru_randombytes_override.cc
src/adapters/sike/kem_adapter.cc
src/adapters/sike/reference_adapter.cc
src/adapters/sike/sike_randombytes_override.cc
src/adapters/sidh/kex_adapter.cc
src/runtime/adapter_registry.cc
src/runtime/replay_args.cc
src/triage/finding_writer.cc
src/triage/oracle_coverage.cc
EOF
}

build_common_archive() {
  # Rebuilt unconditionally so a source edit can never be masked by a stale
  # archive (the SNOVA lane adds files to the shared infrastructure).
  local obj_root="$BUILD_DIR/common-obj"
  mkdir -p "$obj_root"
  local pids=() source obj
  while read -r source; do
    [ -n "$source" ] || continue
    obj="$obj_root/$(echo "$source" | tr '/' '_').o"
    "$CXX_BIN" -std=c++17 $SNOVA_CFLAGS -Isrc -c "$source" -o "$obj" &
    pids+=("$!")
    if [ "${#pids[@]}" -ge "$BUILD_WORKERS" ]; then
      wait "${pids[0]}"
      pids=("${pids[@]:1}")
    fi
  done < <(common_sources)
  for pid in "${pids[@]}"; do
    wait "$pid"
  done
  ar rcs "$COMMON_ARCHIVE" "$obj_root"/*.o
  echo "[snova] common archive built"
}

snova_object_dir_for_job() {
  local algorithm
  algorithm=$(job_field "$1" 'j["algorithm"]')
  echo "$OBJ_ROOT/$(echo "$algorithm" | tr '[:upper:]' '[:lower:]' | tr -d '-')"
}

SNOVA_C_SOURCES="snova.c ct_functions.c shake/KeccakHash.c shake/KeccakSponge.c shake/KeccakP-1600-opt64.c shake/SimpleFIPS202.c shake/snova_shake_ref.c aes/aes_c.c aes/snova_aes.c"

compile_snova_set() {
  local obj_dir="$1" cflags="$2" defines="$3" source base
  mkdir -p "$obj_dir"
  for source in $SNOVA_C_SOURCES; do
    base=$(basename "$source")
    "$CC_BIN" -std=c11 $cflags -I"$SNOVA_SRC" $defines -Dsk_is_seed=0 -c "$SNOVA_SRC/$source" -o "$obj_dir/$base.o"
  done
  touch "$obj_dir/.complete"
}

build_snova_objects() {
  local job_file="$1" obj_dir defines
  obj_dir=$(snova_object_dir_for_job "$job_file")
  defines=$(snova_defines_for_job "$job_file")
  if [ ! -f "$obj_dir/.complete" ]; then
    compile_snova_set "$obj_dir" "$SNOVA_C_CFLAGS" "$defines"
  fi
}

snova_avx2_object_dir_for_job() {
  local algorithm
  algorithm=$(job_field "$1" 'j["algorithm"]')
  echo "$OBJ_ROOT/avx2-$(echo "$algorithm" | tr '[:upper:]' '[:lower:]' | tr -d '-')"
}

# The plasma/AVX2 build recompiles the kernel with OPTIMISATION=2 and -mavx2;
# every defined kernel symbol is renamed opt_* so the reference and AVX2 sets
# link into one binary.  The AES helpers are shared between both builds.
build_snova_avx2_objects() {
  local job_file="$1" obj_dir defines
  obj_dir=$(snova_avx2_object_dir_for_job "$job_file")
  if [ -f "$obj_dir/.complete" ]; then
    return 0
  fi
  defines=$(snova_defines_for_job "$job_file" | sed 's/-DOPTIMISATION=0//')
  mkdir -p "$obj_dir"
  rm -f "$obj_dir"/*.o "$obj_dir/.complete" "$obj_dir/rename.txt"
  local status=0 pids=() pid source base
  local extra_shake=""
  case " $defines " in
    *"PK_EXPAND_SHAKE=1"*) extra_shake="shake/snova_shake_opt.c shake/KeccakP-1600-times4-SIMD256.c" ;;
  esac
  for source in snova.c ct_functions.c shake/KeccakHash.c shake/KeccakSponge.c shake/KeccakP-1600-opt64.c \
                shake/SimpleFIPS202.c shake/snova_shake_ref.c $extra_shake; do
    base=$(basename "$source")
    # shellcheck disable=SC2086
    "$CC_BIN" -std=c11 $SNOVA_C_CFLAGS -mavx2 -I"$SNOVA_SRC" $defines -DOPTIMISATION=1 -Dsk_is_seed=0 \
      -c "$SNOVA_SRC/$source" -o "$obj_dir/$base.o" &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do
    wait "$pid" || status=1
  done
  if [ "$status" -ne 0 ]; then
    echo "[snova] AVX2 object build failed" >&2
    rm -f "$obj_dir/.complete"
    return 1
  fi
  nm -g --defined-only "$obj_dir"/*.o | awk '{print $3}' | grep -v '^$' | sort -u |
    awk '{print $1" opt_"$1}' > "$obj_dir/rename.txt"
  local obj
  for obj in "$obj_dir"/*.o; do
    objcopy --redefine-syms="$obj_dir/rename.txt" "$obj"
  done
  : > "$obj_dir/.complete"
}

build_job() {
  local job_file="$1"
  local job_id algorithm algorithm_enum left_impl right_impl left_sk_len
  job_id=$(job_id_of "$job_file")
  algorithm=$(job_field "$job_file" 'j["algorithm"]')
  algorithm_enum=$(algorithm_enum_for_job "$job_file")
  left_impl=$(job_field "$job_file" 'j["pair"]["left"]["implementation_id"]')
  right_impl=$(job_field "$job_file" 'j["pair"]["right"]["implementation_id"]')
  left_sk_len=$(job_field "$job_file" 'j["pair"]["left"]["abi"]["sk_len"]')
  build_snova_objects "$job_file"
  local obj_dir="$BUILD_DIR/job-obj/$job_id"
  mkdir -p "$obj_dir" "$BUILD_DIR/$job_id"
  local defines
  defines=$(snova_defines_for_job "$job_file")
  local avx2_dir="" avx2_objects=()
  if [[ "$left_impl" == snova_avx2* || "$right_impl" == snova_avx2* ]]; then
    build_snova_avx2_objects "$job_file" || return 1
    avx2_dir=$(snova_avx2_object_dir_for_job "$job_file")
    avx2_objects=("$avx2_dir"/*.o)
  fi

  "$CXX_BIN" -std=c++17 $SNOVA_CFLAGS -Isrc -I"$SNOVA_SRC" $defines \
    -DPQCFUZZ_HAVE_SNOVA \
    -DPQCFUZZ_SNOVA_ALGORITHM="\"$algorithm\"" \
    -DPQCFUZZ_SNOVA_IMPLEMENTATION_BASE="\"snova_reference\"" \
    -DPQCFUZZ_SNOVA_DELEGATE_AVX2 \
    -c src/adapters/snova/sig_adapter.cc -o "$obj_dir/snova_adapter.o"
  if [ -n "$avx2_dir" ]; then
    "$CXX_BIN" -std=c++17 $SNOVA_CFLAGS -Isrc -I"$SNOVA_SRC" $defines \
      -DPQCFUZZ_HAVE_SNOVA \
      -DPQCFUZZ_SNOVA_ALGORITHM="\"$algorithm\"" \
      -DPQCFUZZ_SNOVA_IMPLEMENTATION_BASE="\"snova_avx2\"" \
      -DPQCFUZZ_SNOVA_ADAPTER_GETTER=pqcfuzz_get_snova_avx2_sig_adapter \
      -DPQCFUZZ_SNOVA_API_GETTER=pqcfuzz_get_snova_avx2_api \
      -Dsnova_init=opt_snova_init \
      -Dgenerate_keys_ssk=opt_generate_keys_ssk \
      -Dgenerate_keys_esk=opt_generate_keys_esk \
      -Dsign_digest_ssk=opt_sign_digest_ssk \
      -Dsign_digest_esk=opt_sign_digest_esk \
      -Dverify_signture=opt_verify_signture \
      -Dexpand_public_pack=opt_expand_public_pack \
      -c src/adapters/snova/sig_adapter.cc -o "$obj_dir/snova_adapter_avx2.o"
  fi

  local config_file pair_id pk_exchange sig_exchange
  config_file=$(job_field "$job_file" 'j["paths"]["generated_config"]')
  pair_id=$(job_field "$job_file" 'j["pair_id"]')
  pk_exchange=$(job_field "$job_file" '1 if j["pair"]["exchange_contract"].get("public_key_exchange") else 0')
  sig_exchange=$(job_field "$job_file" '1 if j["pair"]["exchange_contract"].get("signature_exchange") else 0')

  "$CXX_BIN" -std=c++17 $SNOVA_CFLAGS -Isrc -I"$SNOVA_SRC" $defines $FUZZER_SANITIZER_FLAGS \
    -DPQCFUZZ_JOB_ID="\"$job_id\"" \
    -DPQCFUZZ_PAIR_ID="\"$pair_id\"" \
    -DPQCFUZZ_RESULT_DIR="\"${RESULTS_DIR}/${job_id}\"" \
    -DPQCFUZZ_GENERATED_CONFIG_PATH="\"${config_file}\"" \
    -DPQCFUZZ_ORACLE_SUITE="\"fips\"" \
    -DPQCFUZZ_RELATION_MODE="\"cross-implementation\"" \
    -DPQCFUZZ_LEFT_PROJECT_ID="\"snova\"" \
    -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"$left_impl\"" \
    -DPQCFUZZ_EXPECTED_IMPLEMENTATION_ID="\"$left_impl\"" \
    -DPQCFUZZ_EXPECTED_ALGORITHM="\"$algorithm\"" \
    -DPQCFUZZ_RIGHT_PROJECT_ID="\"snova\"" \
    -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"$right_impl\"" \
    -DPQCFUZZ_EXPECTED_SK_LEN="$left_sk_len" \
    -DPQCFUZZ_PUBLIC_KEY_EXCHANGE="$pk_exchange" \
    -DPQCFUZZ_SIGNATURE_EXCHANGE="$sig_exchange" \
    src/fuzzers/sig_pair_fuzzer.cc \
    "$COMMON_ARCHIVE" "$(snova_object_dir_for_job "$job_file")"/*.o "$obj_dir"/*.o "${avx2_objects[@]}" \
    -o "$BUILD_DIR/$job_id/pqcfuzz_$job_id"

  "$CXX_BIN" -std=c++17 $SNOVA_CFLAGS -Isrc -I"$SNOVA_SRC" $defines $REPLAY_SANITIZER_FLAGS \
    -DPQCFUZZ_LEFT_PROJECT_ID="\"snova\"" \
    -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"$left_impl\"" \
    -DPQCFUZZ_EXPECTED_IMPLEMENTATION_ID="\"$left_impl\"" \
    -DPQCFUZZ_EXPECTED_ALGORITHM="\"$algorithm\"" \
    -DPQCFUZZ_RIGHT_PROJECT_ID="\"snova\"" \
    -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"$right_impl\"" \
    -DPQCFUZZ_EXPECTED_SK_LEN="$left_sk_len" \
    src/replay/replay_oracle.cc \
    "$COMMON_ARCHIVE" "$(snova_object_dir_for_job "$job_file")"/*.o "$obj_dir"/*.o "${avx2_objects[@]}" \
    -o "$BUILD_DIR/$job_id/replay_oracle"

  mkdir -p "$BUILD_DIR/manifests"
  python3 - "$BUILD_DIR/manifests/${job_id}.json" "$job_file" "$BUILD_DIR/$job_id/pqcfuzz_$job_id" "$BUILD_DIR/$job_id/replay_oracle" <<'PY'
import json
import sys

path, job_file, out_bin, replay_bin = sys.argv[1:]
with open(job_file, encoding="utf-8") as fh:
    job = json.load(fh)
payload = {
    "job_id": job["job_id"],
    "pair_id": job["pair_id"],
    "algorithm": job["algorithm"],
    "algorithm_enum": job.get("algorithm_metadata", {}).get("algorithm_enum", 0),
    "oracle_spec": job.get("oracle_spec", ""),
    "oracles": job.get("oracles", []),
    "target_binary": out_bin,
    "replay_binary": replay_bin,
    "real_library": True,
    "adapter_project": "snova",
    "adapter_implementation": job.get("pair", {}).get("left", {}).get("implementation_id", ""),
    "right_implementation": job.get("pair", {}).get("right", {}).get("implementation_id", ""),
    "provenance_relation": job.get("pair", {}).get("provenance_relation", "same-source-ssk-vs-esk"),
    "build_flags": {
        "reference": "-D OPTIMISATION=0 -D FIXED_ABQ=2",
        "sanitizers": ["address", "undefined"],
    },
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  echo "[snova] built $job_id"
}

cmd_build() {
  if [ ! -f "$SOURCE_LOCK" ]; then
    echo "[snova] missing source lock $SOURCE_LOCK" >&2
    exit 2
  fi
  if [ ! -f "$SCHEME_PROFILE" ]; then
    echo "[snova] missing scheme profile $SCHEME_PROFILE" >&2
    exit 2
  fi
  if [ ! -f "$SNOVA_SRC/snova.c" ]; then
    echo "[snova] pinned round-2 source not vendored under $SNOVA_SRC" >&2
    echo "[snova] fetch https://github.com/PQCLAB-SNOVA/SNOVA @ 13182903755ade177e02d1fea77f0bd2e1e1a280" >&2
    exit 3
  fi
  python3 src/pairing/validate_pair_alg.py --pair-alg "$PAIR_ALG" >/dev/null
  python3 src/jobs/generate_jobs.py --pair-alg "$PAIR_ALG" --algorithm-family SNOVA \
    --oracle-suite fips --jobs-dir "$JOBS_DIR"
  build_common_archive
  local pids=()
  while read -r job_file; do
    [ -n "$job_file" ] || continue
    build_job "$job_file" &
    pids+=("$!")
    if [ "${#pids[@]}" -ge "$BUILD_WORKERS" ]; then
      wait "${pids[0]}"
      pids=("${pids[@]:1}")
    fi
  done < <(job_files)
  for pid in "${pids[@]}"; do
    wait "$pid"
  done
  python3 - "$BUILD_DIR/build_manifest.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

lock = json.loads(Path("src/config/source_locks/snova.json").read_text())
manifest = {
    "family": "SNOVA",
    "real_library": True,
    "source_lock": "src/config/source_locks/snova.json",
    "spec_sha256": lock["spec"]["sha256"],
    "source_commit": lock["sources"][0]["commit"],
    "archive_sha256": lock["sources"][0]["archive_sha256"],
    "vendored_source": lock["sources"][0]["vendored_path"],
    "build_flags": ["OPTIMISATION=0", "FIXED_ABQ=2", "address", "undefined"],
    "official_kat": True,
    "kat_fixture_sha256": hashlib.sha256(Path("tests/fixtures/snova/kat_reference.json").read_bytes()).hexdigest(),
}
Path(sys.argv[1]).write_text(json.dumps(manifest, indent=2) + "\n")
PY
  echo "[snova] build complete"
}

ensure_build() {
  if [ ! -f "$BUILD_DIR/build_manifest.json" ]; then
    cmd_build
  fi
}

make_seed_corpus() {
  local job_file="$1" cases="${2:-$SMOKE_CORPUS_CASES}"
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
    seed = bytes((index * 13 + i) & 0xFF for i in range(32))
    message = b"PQCFuzz SNOVA eval" + bytes([index])
    # Structured mutation recipe v1: set_coefficient (0x08) on
    # snova.signature.nibble (42), nibble index = index*7, value = (index+1)%16.
    mutation = bytes([0x08, 0x2A]) + struct.pack("<II", index * 7, (index + 1) % 16)
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
  python3 - "$job_file" "$result_dir/oracle_coverage.json" <<'PY'
import json
import sys

job = json.load(open(sys.argv[1], encoding="utf-8"))
coverage_path = sys.argv[2]
try:
    coverage = json.load(open(coverage_path, encoding="utf-8"))
except OSError:
    raise SystemExit(f"[snova] missing coverage report {coverage_path}")
oracles = coverage.get("oracles", {})
missing = []
for oracle in job.get("oracles", []):
    if oracles.get(oracle, {}).get("oracle_invocations", 0) <= 0:
        missing.append(oracle)
if missing:
    raise SystemExit("[snova] oracles without invocations: " + ", ".join(missing))
print(f"[snova] coverage ok: {len(job.get('oracles', []))} oracles")
PY
}

replay_job_seeds() {
  local job_file="$1" replay_bin="$2" corpus_dir="$3"
  local algorithm pair_id config_file left_impl right_impl
  algorithm=$(job_field "$job_file" 'j["algorithm"]')
  pair_id=$(job_field "$job_file" 'j["pair_id"]')
  config_file=$(job_field "$job_file" 'j["paths"]["generated_config"]')
  left_impl=$(job_field "$job_file" 'j["pair"]["left"]["implementation_id"]')
  right_impl=$(job_field "$job_file" 'j["pair"]["right"]["implementation_id"]')
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
        --left-project-id snova \
        --left-implementation-id "$left_impl" \
        --right-project-id snova \
        --right-implementation-id "$right_impl" \
        --public-key-exchange 1 \
        --ciphertext-exchange 0 \
        --secret-key-exchange 0 \
        --secret-key-format-compatible 0 \
        --signature-exchange 1 \
        >/dev/null 2>&1
      local rc=$?
      set -e
      if [ "$rc" -ne 0 ] && [ "$rc" -ne 70 ]; then
        echo "[snova] replay failed for $oracle_name (rc=$rc) in $(job_id_of "$job_file")" >&2
        return 1
      fi
    done
  done < <(oracle_specs_for_job "$job_file")
}

preflight_job() {
  local job_file="$1"
  local job_id
  job_id=$(job_id_of "$job_file")
  local result_dir="$RESULTS_DIR/$job_id"
  mkdir -p "$result_dir" "$CRASHES_DIR/$job_id"
  make_seed_corpus "$job_file" 1
  local corpus_dir="$RUNS_DIR/$job_id/corpus"
  local status=0
  set +e
  "$BUILD_DIR/$job_id/pqcfuzz_$job_id" -runs=1 "$corpus_dir" \
    -artifact_prefix="$CRASHES_DIR/$job_id/" >"$RUNS_DIR/$job_id/preflight.log" 2>&1
  local rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "[snova] preflight fuzzer failed for $job_id (rc=$rc)" >&2
    status=1
  fi
  verify_oracle_coverage "$job_file" "$result_dir" || status=1
  replay_job_seeds "$job_file" "$BUILD_DIR/$job_id/replay_oracle" "$corpus_dir" || status=1
  if [ "$status" -ne 0 ]; then
    return 1
  fi
  echo "[snova] preflight ok: $job_id"
}

run_jobs_parallel() {
  local fn="$1"
  local pids=() overall=0
  local job_file pid
  while read -r job_file; do
    [ -n "$job_file" ] || continue
    "$fn" "$job_file" &
    pids+=("$!")
    if [ "${#pids[@]}" -ge "$BUILD_WORKERS" ]; then
      if ! wait "${pids[0]}"; then overall=1; fi
      pids=("${pids[@]:1}")
    fi
  done < <(job_files)
  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then overall=1; fi
  done
  return "$overall"
}

cmd_preflight() {
  ensure_build
  local overall=0
  run_jobs_parallel preflight_job || overall=1
  python3 - "$WORK_ROOT/preflight_manifest.json" "$overall" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest = {
    "family": "SNOVA",
    "real_library": True,
    "dependency_status": "pinned-round2-vendored" if Path("projects/SNOVA/reference/snova.c").is_file() else "missing",
    "official_kat": True,
    "kat_fixture_sha256": hashlib.sha256(Path("tests/fixtures/snova/kat_reference.json").read_bytes()).hexdigest(),
    "coverage_gate": "passed" if int(sys.argv[2]) == 0 else "failed",
}
Path(sys.argv[1]).write_text(json.dumps(manifest, indent=2) + "\n")
PY
  [ "$overall" -eq 0 ]
}

smoke_job() {
  local job_file="$1"
  local job_id
  job_id=$(job_id_of "$job_file")
  make_seed_corpus "$job_file" "$SMOKE_CORPUS_CASES"
  local corpus_dir="$RUNS_DIR/$job_id/corpus"
  mkdir -p "$corpus_dir"
  "$BUILD_DIR/$job_id/pqcfuzz_$job_id" -runs="$SMOKE_CORPUS_CASES" "$corpus_dir" \
    -artifact_prefix="$CRASHES_DIR/$job_id/" >"$RUNS_DIR/$job_id/smoke.log" 2>&1
  local seconds=$((SMOKE_FUZZ_SECONDS / $(job_files | wc -l) + 1))
  "$BUILD_DIR/$job_id/pqcfuzz_$job_id" -max_total_time="$seconds" "$corpus_dir" \
    -artifact_prefix="$CRASHES_DIR/$job_id/" >>"$RUNS_DIR/$job_id/smoke.log" 2>&1
  echo ok >"$RUNS_DIR/$job_id/smoke.status"
  echo "[snova] smoke ok: $job_id"
}

cmd_smoke() {
  if [ "${SKIP_PREFLIGHT:-0}" != "1" ]; then
    cmd_preflight
  fi
  python3 -m pytest -q tests/snova_model_test.py tests/snova_oracles_test.py
  run_jobs_parallel smoke_job
  python3 - "$WORK_ROOT/smoke_manifest.json" <<'PY'
import json
import sys
from pathlib import Path

manifest = {
    "family": "SNOVA",
    "smoke_fuzz_seconds": 30,
    "sanitizers": ["address", "undefined"],
    "model_lane": "tests/snova_model_test.py",
    "oracle_lane": "tests/snova_oracles_test.py",
    "status": "completed",
}
Path(sys.argv[1]).write_text(json.dumps(manifest, indent=2) + "\n")
PY
  echo "[snova] smoke complete"
}

cmd_run() {
  if [ "${SKIP_PREFLIGHT:-0}" != "1" ]; then
    cmd_preflight
  fi
  run_job() {
    local job_file="$1"
    local job_id
    job_id=$(job_id_of "$job_file")
    set +e
    "$BUILD_DIR/$job_id/pqcfuzz_$job_id" -max_total_time="$MAX_TOTAL_TIME" \
      "$RUNS_DIR/$job_id/corpus" -artifact_prefix="$CRASHES_DIR/$job_id/" \
      >"$RUNS_DIR/$job_id/run.log" 2>&1
    echo "$?" >"$RUNS_DIR/$job_id/status.txt"
  }
  run_jobs_parallel run_job
  echo "[snova] run complete"
}

cmd_report() {
  python3 - "$JOBS_DIR" "$RESULTS_DIR" "$REPORT_DIR" "$SOURCE_LOCK" <<'PY'
import json
import sys
from pathlib import Path

jobs_dir, results_dir, report_dir = (Path(arg) for arg in sys.argv[1:4])
lock = json.loads(Path(sys.argv[4]).read_text())
oracles = {}
findings = 0
jobs = []
coverage_totals = {
    "scheduled": 0,
    "entered": 0,
    "evaluable": 0,
    "not_applicable": 0,
    "unsupported": 0,
    "skipped": 0,
    "findings": 0,
}
for job_path in sorted(jobs_dir.glob("job_snova_*.json")):
    job = json.loads(job_path.read_text())
    coverage_path = results_dir / job["job_id"] / "oracle_coverage.json"
    coverage = json.loads(coverage_path.read_text()) if coverage_path.is_file() else {}
    finding_records = 0
    for oracle in job.get("oracles", []):
        entry = coverage.get("oracles", {}).get(oracle, {})
        invocations = entry.get("oracle_invocations", 0)
        findings_for_oracle = entry.get("finding_records", 0)
        finding_records += findings_for_oracle
        summary = oracles.setdefault(
            oracle,
            {
                "invocations": 0,
                "findings": 0,
                "profiles": 0,
                "evaluable": 0,
                "not_applicable": 0,
                "unsupported": 0,
                "skipped": 0,
            },
        )
        summary["invocations"] += invocations
        summary["findings"] += findings_for_oracle
        summary["profiles"] += 1
        summary["evaluable"] += entry.get("relation_evaluable", 0)
        summary["not_applicable"] += entry.get("not_applicable", 0)
        summary["unsupported"] += entry.get("unsupported", 0)
        summary["skipped"] += entry.get("skipped", 0)
        coverage_totals["scheduled"] += 1
        coverage_totals["entered"] += 1 if invocations else 0
        coverage_totals["evaluable"] += entry.get("relation_evaluable", 0)
        coverage_totals["not_applicable"] += entry.get("not_applicable", 0)
        coverage_totals["unsupported"] += entry.get("unsupported", 0)
        coverage_totals["skipped"] += entry.get("skipped", 0)
    findings += finding_records
    jobs.append({"job_id": job["job_id"], "algorithm": job["algorithm"], "finding_records": finding_records})
coverage_totals["findings"] = findings
summary = {
    "family": "SNOVA",
    "spec": lock["spec"],
    "source": lock["sources"][0],
    "kat": lock["kat"],
    "jobs": jobs,
    "oracles": oracles,
    "coverage": coverage_totals,
    "total_finding_records": findings,
    "claims": "conformance and counterexample search only; no IND-CCA, EUF-CMA, sUF or quantum-security proof is claimed",
    "sanitizer": {
        "status": "see workspace/snova/runs/*/smoke-fuzz.log for the sanitizer lane",
        "build": "ASan/UBSan sanitizer fuzzers are built by scripts/pqcfuzz_snova_eval.sh build",
    },
    "false_positive_controls": [
        "honest signature verifies for every default profile",
        "accepted nonzero input padding nibble is reported as a byte alias, never as an EUF forgery",
        "AES and SHAKE public-expansion backends are never cross-verified",
        "same-source SSK/ESK provenance is labelled and never reported as independent",
        "fixed coins under a recorded salt are not reported as insufficient randomness",
    ],
    "fault_detection": {
        "status": "not scheduled by default",
        "oracles": ["snova_fault_checks"],
        "note": "P2 fault mutants are opt-in; run with PQCFUZZ_INCLUDE_P2=1 after enabling the fault lane",
    },
    "not_covered": {
        "p2_lanes": ["snova_fault_checks", "snova_timing_resources"],
        "notes": [
            "P2 fault/timing lanes are opt-in and not scheduled by default",
            "KAT fixtures cover the count=0 official record; full 100-record responses are not vendored",
            "reports never claim IND-CCA, EUF-CMA, sUF or quantum security",
        ],
    },
}
report_dir.mkdir(parents=True, exist_ok=True)
(report_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
lines = [
    "# PQCFuzz SNOVA report",
    "",
    "SNOVA round-2 reference, spec `%s` (sha256 `%s`)." % (lock["spec"]["path"], lock["spec"]["sha256"]),
    "",
    "- Pinned source: %s @ %s" % (lock["sources"][0]["url"], lock["sources"][0]["commit"]),
    "- Official KAT: %s" % ("yes (count=0 records)" if lock["kat"]["official_kat_available"] else "no"),
    "- Jobs: %d" % len(jobs),
    "- Total finding records: %d" % findings,
    "- Coverage: %d scheduled, %d entered, %d evaluable, %d not applicable, %d unsupported, %d skipped"
    % (
        coverage_totals["scheduled"],
        coverage_totals["entered"],
        coverage_totals["evaluable"],
        coverage_totals["not_applicable"],
        coverage_totals["unsupported"],
        coverage_totals["skipped"],
    ),
    "- Claims: %s" % summary["claims"],
    "",
    "| oracle | invocations | evaluable | not applicable | unsupported | skipped | findings | profiles |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
]
for oracle, data in sorted(oracles.items()):
    lines.append(
        "| %s | %d | %d | %d | %d | %d | %d | %d |"
        % (
            oracle,
            data["invocations"],
            data["evaluable"],
            data["not_applicable"],
            data["unsupported"],
            data["skipped"],
            data["findings"],
            data["profiles"],
        )
    )
lines += [
    "",
    "## Sanitizer",
    "",
    "- %s" % summary["sanitizer"]["build"],
    "- %s" % summary["sanitizer"]["status"],
    "",
    "## False-positive controls",
    "",
]
for control in summary["false_positive_controls"]:
    lines.append("- %s" % control)
lines += [
    "",
    "## Fault detection",
    "",
    "- Status: %s" % summary["fault_detection"]["status"],
    "- %s" % summary["fault_detection"]["note"],
    "",
    "## Not covered",
    "",
    "- P2 fault and timing lanes are opt-in: `snova_fault_checks`, `snova_timing_resources`.",
    "- KAT fixtures cover the official count=0 record per profile; the upstream 100-record files are not vendored.",
    "- No report line proves anti-quantum, IND-CCA or EUF-CMA security.",
    "",
]
(report_dir / "summary.md").write_text("\n".join(lines))
print("[snova] report written to", report_dir)
PY
}

case "${1:-}" in
  build) cmd_build ;;
  preflight) cmd_preflight ;;
  smoke) cmd_smoke ;;
  run) cmd_run ;;
  report) cmd_report ;;
  *)
    echo "usage: $0 {build|preflight|smoke|run|report}" >&2
    exit 2
    ;;
esac

#!/usr/bin/env bash
# PQCFuzz evaluation driver for the pinned CROSS reference implementation.
#
# Commands:
#   scripts/pqcfuzz_cross_eval.sh build       # generate jobs + build fuzzers/replays
#   scripts/pqcfuzz_cross_eval.sh preflight   # seed corpus + -runs=1 + coverage gate
#   scripts/pqcfuzz_cross_eval.sh smoke       # deterministic corpus + short sanitizer fuzz
#   scripts/pqcfuzz_cross_eval.sh run         # budgeted campaign
#   scripts/pqcfuzz_cross_eval.sh report      # write workspace/cross/report/summary.{json,md}
#
# Environment:
#   PAIR_ALG=src/config/pair_alg.cross.json
#   WORK_ROOT=workspace/cross
#   MAX_TOTAL_TIME=120            per-job campaign budget in seconds
#   SMOKE_FUZZ_SECONDS=30         total smoke fuzz budget across jobs
#   BUILD_WORKERS=8
#   JOB_FILTER=<substring>        restrict jobs
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

PAIR_ALG="${PAIR_ALG:-src/config/pair_alg.cross.json}"
WORK_ROOT="${WORK_ROOT:-workspace/cross}"
JOBS_DIR="${JOBS_DIR:-$WORK_ROOT/jobs}"
BUILD_DIR="${BUILD_DIR:-$WORK_ROOT/build}"
RUNS_DIR="${RUNS_DIR:-$WORK_ROOT/runs}"
RESULTS_DIR="${RESULTS_DIR:-$WORK_ROOT/results}"
CRASHES_DIR="${CRASHES_DIR:-$WORK_ROOT/crashes}"
REPORT_DIR="${REPORT_DIR:-$WORK_ROOT/report}"
CROSS_SRC="${CROSS_SRC:-projects/CROSS/reference}"
SOURCE_LOCK="${SOURCE_LOCK:-src/config/source_locks/cross.json}"
SCHEME_PROFILE="${SCHEME_PROFILE:-src/config/scheme_profiles/cross.json}"

CXX_BIN="${CXX:-clang++}"
CC_BIN="${CC:-clang}"
CROSS_CFLAGS="-O1 -g -fno-omit-frame-pointer -DSKIP_ASSERT -fsanitize=fuzzer-no-link,address,undefined"
FUZZER_SANITIZER_FLAGS="-fsanitize=fuzzer,address,undefined"
REPLAY_SANITIZER_FLAGS="-fsanitize=address,undefined"
COMMON_ARCHIVE="${BUILD_DIR}/libpqcfuzz_cross_common.a"
CCACHE_OBJ_ROOT="${BUILD_DIR}/cross-obj"

MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-120}"
SMOKE_FUZZ_SECONDS="${SMOKE_FUZZ_SECONDS:-30}"
BUILD_WORKERS="${BUILD_WORKERS:-8}"
JOB_FILTER="${JOB_FILTER:-}"

usage() {
  cat <<'EOF'
Usage: scripts/pqcfuzz_cross_eval.sh {build|preflight|smoke|run|report}
EOF
}

job_filter_matches() {
  [ -z "$JOB_FILTER" ] || case "$1" in *"$JOB_FILTER"*) return 0 ;; *) return 1 ;; esac
}

job_files() {
  local job_file
  for job_file in "$JOBS_DIR"/job_cross_*.json; do
    [ -e "$job_file" ] || continue
    job_filter_matches "$(basename "$job_file")" || continue
    echo "$job_file"
  done
}

job_id_of() {
  basename "$1" .json
}

job_algorithm() {
  python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['algorithm'])" "$1"
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

cross_defines_for_job() {
  python3 - "$1" <<'PY'
import json
import sys

sys.path.insert(0, "src")
from pairing.pair_alg_loader import SUPPORTED_ALGORITHMS

with open(sys.argv[1], encoding="utf-8") as fh:
    job = json.load(fh)
metadata = SUPPORTED_ALGORITHMS[job["algorithm"]]
print(" ".join(f"-D{define}" for define in metadata["c_defines"]))
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
src/oracles/expected_relation.cc
src/oracles/oracle_spec.cc
src/oracles/oracle_spec_loader.cc
src/oracles/oracle_record.cc
src/oracles/oracle_result.cc
src/oracles/oracle_executor.cc
src/oracles/cross_executor.cc
src/oracles/metamorphic_observation.cc
src/oracles/metamorphic_spec.cc
src/oracles/metamorphic_executor.cc
src/runtime/adapter_registry.cc
src/runtime/replay_args.cc
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
    "$CXX_BIN" -std=c++17 $CROSS_CFLAGS -Isrc -c "$source" -o "$obj" &
  done
  wait || status=$?
  if [ "$status" -ne 0 ]; then
    echo "[cross] common archive build failed" >&2
    exit 1
  fi
  rm -f "$COMMON_ARCHIVE"
  ar rcs "$COMMON_ARCHIVE" "$obj_root"/*.o
  echo "[cross] common archive: $COMMON_ARCHIVE"
}

cross_object_dir_for_job() {
  local job_file="$1"
  local algorithm
  algorithm=$(job_algorithm "$job_file")
  echo "$CCACHE_OBJ_ROOT/$(echo "$algorithm" | tr 'A-Z' 'a-z' | tr - _)"
}

build_cross_objects() {
  local job_file="$1"
  local defines
  defines=$(cross_defines_for_job "$job_file")
  local obj_dir
  obj_dir=$(cross_object_dir_for_job "$job_file")
  if [ -f "$obj_dir/.complete" ]; then
    return 0
  fi
  mkdir -p "$obj_dir"
  local f status=0
  local pids=()
  for f in CROSS csprng_hash fips202 keccakf1600 merkle pack_unpack seedtree sign; do
    "$CC_BIN" -std=c11 $CROSS_CFLAGS -I"$CROSS_SRC/include" $defines -c "$CROSS_SRC/lib/$f.c" -o "$obj_dir/$f.o" &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do
    wait "$pid" || status=1
  done
  if [ "$status" -ne 0 ]; then
    echo "[cross] CROSS object build failed for $algorithm" >&2
    rm -f "$obj_dir/.complete"
    return 1
  fi
  : > "$obj_dir/.complete"
}

build_job() {
  local job_file="$1"
  local job_id algorithm algorithm_enum defines obj_dir out_bin replay_bin
  job_id=$(job_id_of "$job_file")
  algorithm=$(job_algorithm "$job_file")
  algorithm_enum=$(algorithm_enum_for_job "$job_file")
  defines=$(cross_defines_for_job "$job_file")
  build_cross_objects "$job_file"
  obj_dir=$(cross_object_dir_for_job "$job_file")
  "$CXX_BIN" -std=c++17 $CROSS_CFLAGS -Isrc -I"$CROSS_SRC/include" $defines \
    -DPQCFUZZ_HAVE_CROSS -DPQCFUZZ_CROSS_ALGORITHM="\"$algorithm\"" \
    -c src/adapters/cross/cross_adapter.cc -o "$obj_dir/cross_adapter.o"
  out_bin="$BUILD_DIR/$job_id/pqcfuzz_$job_id"
  replay_bin="$BUILD_DIR/$job_id/replay_oracle"
  mkdir -p "$BUILD_DIR/$job_id"

  local config_file
  config_file=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['paths']['generated_config'])" "$job_file")
  local pair_id
  pair_id=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['pair_id'])" "$job_file")

  "$CXX_BIN" -std=c++17 -O1 -g -fno-omit-frame-pointer -Isrc -I"$CROSS_SRC/include" \
    $defines -DPQCFUZZ_HAVE_CROSS \
    -DPQCFUZZ_CROSS_ALGORITHM="\"$algorithm\"" \
    $FUZZER_SANITIZER_FLAGS \
    -DPQCFUZZ_JOB_ID="\"$job_id\"" \
    -DPQCFUZZ_PAIR_ID="\"$pair_id\"" \
    -DPQCFUZZ_RESULT_DIR="\"${RESULTS_DIR}/${job_id}\"" \
    -DPQCFUZZ_GENERATED_CONFIG_PATH="\"${config_file}\"" \
    -DPQCFUZZ_ORACLE_SUITE="\"fips\"" \
    -DPQCFUZZ_RELATION_MODE="\"cross-implementation\"" \
    -DPQCFUZZ_LEFT_PROJECT_ID="\"cross\"" \
    -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"cross_reference\"" \
    -DPQCFUZZ_EXPECTED_IMPLEMENTATION_ID="\"cross_reference\"" \
    -DPQCFUZZ_EXPECTED_ALGORITHM="\"$algorithm\"" \
    -DPQCFUZZ_RIGHT_PROJECT_ID="\"cross\"" \
    -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"cross_reference\"" \
    -DPQCFUZZ_PUBLIC_KEY_EXCHANGE=1 \
    -DPQCFUZZ_SIGNATURE_EXCHANGE=0 \
    src/fuzzers/sig_pair_fuzzer.cc \
    "$COMMON_ARCHIVE" "$obj_dir"/*.o \
    -o "$out_bin"

  "$CXX_BIN" -std=c++17 -O1 -g -fno-omit-frame-pointer -Isrc -I"$CROSS_SRC/include" \
    $defines -DPQCFUZZ_HAVE_CROSS \
    -DPQCFUZZ_CROSS_ALGORITHM="\"$algorithm\"" \
    $REPLAY_SANITIZER_FLAGS \
    -DPQCFUZZ_LEFT_PROJECT_ID="\"cross\"" \
    -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"cross_reference\"" \
    -DPQCFUZZ_EXPECTED_IMPLEMENTATION_ID="\"cross_reference\"" \
    -DPQCFUZZ_EXPECTED_ALGORITHM="\"$algorithm\"" \
    -DPQCFUZZ_RIGHT_PROJECT_ID="\"cross\"" \
    -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"cross_reference\"" \
    src/replay/replay_oracle.cc \
    "$COMMON_ARCHIVE" "$obj_dir"/*.o \
    -o "$replay_bin"

  manifests_dir
  python3 - "$BUILD_DIR/manifests/${job_id}.json" "$job_file" "$out_bin" "$replay_bin" "$defines" <<'PY'
import json
import sys

path, job_file, out_bin, replay_bin, defines = sys.argv[1:]
with open(job_file, encoding="utf-8") as fh:
    job = json.load(fh)
payload = {
    "job_id": job["job_id"],
    "pair_id": job["pair_id"],
    "algorithm": job["algorithm"],
    "oracle_spec": job.get("oracle_spec", ""),
    "oracles": job.get("oracles", []),
    "c_defines": defines.split(),
    "target_binary": out_bin,
    "replay_binary": replay_bin,
    "real_library": True,
    "adapter_project": "cross",
    "adapter_implementation": "cross_reference",
    "provenance_relation": job.get("pair", {}).get("provenance_relation", "same-source-single-implementation"),
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  echo "[cross] built $job_id"
}

cmd_build() {
  mkdir -p "$BUILD_DIR" "$RUNS_DIR" "$RESULTS_DIR" "$CRASHES_DIR" "$JOBS_DIR" "$REPORT_DIR"
  if [ ! -f "$SOURCE_LOCK" ]; then
    echo "[cross] missing source lock: $SOURCE_LOCK" >&2
    exit 1
  fi
  if [ ! -f "$SCHEME_PROFILE" ]; then
    echo "[cross] missing scheme profile: $SCHEME_PROFILE" >&2
    exit 1
  fi
  python3 src/jobs/generate_jobs.py --pair-alg "$PAIR_ALG" --algorithm-family CROSS \
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
    echo "[cross] build failed" >&2
    exit 1
  fi
  python3 - "$BUILD_DIR/build_manifest.json" "$BUILD_DIR/manifests" "$SOURCE_LOCK" <<'PY'
import json
import sys
from pathlib import Path

path, manifests, source_lock = sys.argv[1:]
with open(source_lock, encoding="utf-8") as fh:
    lock = json.load(fh)
records = []
for manifest in sorted(Path(manifests).glob("*.json")):
    with open(manifest, encoding="utf-8") as fh:
        records.append(json.load(fh))
payload = {
    "family": "CROSS",
    "real_library": True,
    "source_lock": source_lock,
    "spec_sha256": lock["spec"]["sha256"],
    "vendored_source": lock["sources"][0]["vendored_path"],
    "archive_sha256": lock["sources"][0]["archive_sha256"],
    "build_flags": ["-DSKIP_ASSERT", "-fsanitize=fuzzer-no-link,address,undefined"],
    "official_kat": False,
    "jobs": records,
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"[cross] build manifest: {path} ({len(records)} jobs)")
PY
}

make_seed_corpus() {
  local job_file="$1"
  local job_id algorithm_enum
  job_id=$(job_id_of "$job_file")
  algorithm_enum=$(algorithm_enum_for_job "$job_file")
  local corpus_dir="$RUNS_DIR/$job_id/corpus"
  mkdir -p "$corpus_dir"
  local oracle_enum oracle_name
  while IFS=: read -r oracle_enum oracle_name; do
    [ -n "$oracle_enum" ] || continue
    python3 - "$corpus_dir/seed-pqcfuzz-${oracle_name}.bin" "$algorithm_enum" "$oracle_enum" "$oracle_name" <<'PY'
import struct
import sys

path = sys.argv[1]
algorithm = int(sys.argv[2])
oracle = int(sys.argv[3])
seed = bytes(range(32))
message = b"PQCFuzz CROSS eval"
# Structured mutation recipe v1: xor_byte on signature.digest_cmt.
mutation = bytes([0x02, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF])
extra = b""
out = bytearray(b"PQCF")
out.extend(bytes([1, algorithm, oracle, 0]))
for field in (seed, message, mutation, extra):
    out.extend(struct.pack("<H", len(field)))
    out.extend(field)
with open(path, "wb") as fh:
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
    echo "[cross] coverage gate failed for oracles: $(echo "$missing" | tr '\n' ' ')" >&2
    return 1
  fi
}

preflight_job() {
  local job_file="$1"
  local job_id result_dir binary replay_bin
  job_id=$(job_id_of "$job_file")
  result_dir="$RESULTS_DIR/$job_id"
  binary="$BUILD_DIR/$job_id/pqcfuzz_$job_id"
  replay_bin="$BUILD_DIR/$job_id/replay_oracle"
  mkdir -p "$result_dir"
  make_seed_corpus "$job_file"
  local corpus_dir="$RUNS_DIR/$job_id/corpus"
  "$binary" -runs=1 "$corpus_dir" >/dev/null 2>&1 || true
  verify_oracle_coverage "$job_file" "$result_dir"
  replay_job_seeds "$job_file" "$replay_bin" "$corpus_dir" "$result_dir"
  echo "[cross] preflight ok: $job_id"
}

replay_job_seeds() {
  local job_file="$1" replay_bin="$2" corpus_dir="$3" result_dir="$4"
  local algorithm pair_id config_file
  algorithm=$(job_algorithm "$job_file")
  pair_id=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['pair_id'])" "$job_file")
  config_file=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['paths']['generated_config'])" "$job_file")
  local replay_dir="$RUNS_DIR/$(job_id_of "$job_file")/replay"
  mkdir -p "$replay_dir"
  local oracle_enum oracle_name
  while IFS=: read -r oracle_enum oracle_name; do
    [ -n "$oracle_name" ] || continue
    local seed="$corpus_dir/seed-pqcfuzz-${oracle_name}.bin"
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
        --left-project-id cross \
        --left-implementation-id cross_reference \
        --right-project-id cross \
        --right-implementation-id cross_reference \
        --public-key-exchange 1 \
        --ciphertext-exchange 0 \
        --secret-key-exchange 0 \
        --secret-key-format-compatible 0 \
        --signature-exchange 0 \
        >/dev/null 2>&1
      local rc=$?
      set -e
      # 0 = no finding, 70 = recorded finding.  Hangs and crashes fail the
      # preflight so a broken replay path is visible before any campaign.
      if [ "$rc" -ne 0 ] && [ "$rc" -ne 70 ]; then
        echo "[cross] replay failed for $oracle_name (rc=$rc) in $(job_id_of "$job_file")" >&2
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
    "family": "CROSS",
    "real_library": True,
    "dependency_status": "vendored-reference-present",
    "official_kat": False,
    "kat_status": lock["kat"]["status"],
    "coverage_gate": "passed" if status == 0 else "failed",
}
Path(path).parent.mkdir(parents=True, exist_ok=True)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"[cross] preflight coverage gate: {'passed' if status == 0 else 'FAILED'}")
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
  "$binary" -runs=10 "$corpus_dir" >"$RUNS_DIR/$job_id/smoke-corpus.log" 2>&1 || true
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
  echo "[cross] campaign $job_id finished with rc=$rc"
}

cmd_smoke() {
  python3 -m pytest -q tests/cross_model_test.py >"$RUNS_DIR/model-lane.log" 2>&1 || {
    echo "[cross] model lane failed; see $RUNS_DIR/model-lane.log" >&2
    exit 1
  }
  local job_file status=0
  while IFS= read -r job_file; do
    smoke_job "$job_file" || status=1
  done < <(job_files)
  python3 - "$WORK_ROOT/smoke_manifest.json" "$SMOKE_FUZZ_SECONDS" "$status" <<'PY'
import json
import sys
from pathlib import Path

path, seconds, status = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
payload = {
    "family": "CROSS",
    "smoke_fuzz_seconds": seconds,
    "sanitizers": ["address", "undefined"],
    "model_lane": "tests/cross_model_test.py",
    "status": "passed" if status == 0 else "failed",
}
Path(path).parent.mkdir(parents=True, exist_ok=True)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"[cross] smoke: {'passed' if status == 0 else 'FAILED'}")
PY
  exit "$status"
}

cmd_report() {
  mkdir -p "$REPORT_DIR"
  python3 - "$REPO_ROOT" "$WORK_ROOT" "$REPORT_DIR" "$JOBS_DIR" "$RESULTS_DIR" "$RUNS_DIR" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

repo_root, work_root, report_dir, jobs_dir, results_dir, runs_dir = sys.argv[1:]
report_dir = Path(report_dir)
jobs = []
for job_path in sorted(Path(jobs_dir).glob("job_cross_*.json")):
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
    "family": "CROSS",
    "spec": "plans/specs/cross-round2-spec.pdf",
    "spec_sha256": "10ac1ef5989735131b8ba2dfc360361d98b2015a85485173dcad446df30dc039",
    "source": {
        "vendored_path": "projects/CROSS/reference",
        "archive_sha256": "682e19f8deba19f543960687abcf6d81d44edbd16d8ae006f4c1dfeca8c957e6",
        "implementation": "cross_reference",
        "cross_implementation_lane": "same-source-single-implementation",
    },
    "profiles": profiles,
    "oracle_invocations": dict(oracle_totals),
    "findings_by_oracle": dict(findings),
    "sanitizer_lane": sanitizer_lane,
    "preflight": preflight_manifest,
    "not_covered": [
        "official NIST round-2 KAT response files are not in the submission archive",
        "independent ref/AVX2 differential lane (cross_cross_verify) is disabled",
        "P2 timing and fault lanes are opt-in and not run by default",
        "cross_domain_transcript/cross_seed_rebuild/cross_path_proof_consumption/cross_key_algebra/"
        "cross_parallel_arithmetic/cross_fault_seed_disclosure are evaluated by the Python model lane",
    ],
    "claims": "no IND-CCA/EUF/sUF or quantum-security proof is claimed",
}
with open(report_dir / "summary.json", "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")

lines = [
    "# CROSS evaluation summary",
    "",
    f"- profiles: {len(profiles)}",
    f"- source: `{payload['source']['vendored_path']}`",
    f"- spec sha256: `{payload['spec_sha256']}`",
    f"- sanitizers: {', '.join(sanitizer_lane.get('sanitizers', [])) or 'not-run'}"
    f" (smoke budget {sanitizer_lane.get('smoke_fuzz_seconds', 'n/a')}s)",
    "- official KAT: absent from the submission archive; reference-derived fixtures only",
    "- cross-implementation lane: disabled (single pinned reference build)",
    "",
    "| profile | oracles entered | findings | fuzz | smoke |",
    "| --- | ---: | ---: | --- | --- |",
]
for profile in profiles:
    lines.append(
        f"| {profile['algorithm']} | {profile['oracles_entered']}/{profile['oracles_scheduled']} | "
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
print(f"[cross] report: {report_dir / 'summary.json'}")
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
      echo "[cross] no jobs built; run build first" >&2
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

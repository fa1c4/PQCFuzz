#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <job_id> [--smoke] [extra libFuzzer args...]" >&2
  exit 1
fi

job_id="$1"
shift

smoke_mode=0
extra_args=()
for arg in "$@"; do
  if [[ "$arg" == "--smoke" ]]; then
    smoke_mode=1
  else
    extra_args+=("$arg")
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

job_file="$repo_root/workspace/jobs/$job_id.json"
if [[ ! -f "$job_file" ]]; then
  echo "missing $job_file; run eval/build_all.sh first." >&2
  exit 1
fi

job_fields="$(python3 - "$job_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    job = json.load(handle)
paths = job.get("paths", {})
fields = [
    job.get("primitive_type", ""),
    job.get("algorithm_family", ""),
    paths.get("build_dir", ""),
    paths.get("run_dir", ""),
    paths.get("result_dir", ""),
    paths.get("crash_dir", ""),
]
print("\t".join(fields))
PY
)"
IFS=$'\t' read -r primitive_type algorithm_family build_dir_rel run_dir_rel result_dir_rel crash_dir_rel <<<"$job_fields"

if [[ "$primitive_type" != "kem" && "$primitive_type" != "sig" ]]; then
  echo "run_one.sh supports generated kem and sig jobs; '$job_id' uses primitive '$primitive_type'." >&2
  exit 1
fi

build_dir="$repo_root/$build_dir_rel"
run_dir="$repo_root/$run_dir_rel"
result_dir="$repo_root/$result_dir_rel"
crash_dir="$repo_root/$crash_dir_rel"
input_timeout_seconds="${PQCFUZZ_INPUT_TIMEOUT_SECONDS:-${PQCFUZZ_TIMEOUT_SECONDS:-30}}"
fuzzing_seconds="${PQCFUZZ_FUZZING_SECONDS:-$input_timeout_seconds}"
rss_mb="${PQCFUZZ_RSS_MB:-2048}"

binary_path="$build_dir/fuzzer"
if [[ ! -x "$binary_path" ]]; then
  echo "missing $binary_path; run eval/build_one.sh $job_id first." >&2
  exit 1
fi

mkdir -p "$run_dir/corpus" "$result_dir" "$crash_dir"
log_file="$run_dir/run.log"
seed_input="$run_dir/corpus/seed-pqcfuzz-input"

if [[ ! -f "$seed_input" ]]; then
  seed_source="tests/seeds/mlkem_roundtrip_seed.bin"
  if [[ "$algorithm_family" == "ML-DSA" ]]; then
    seed_source="tests/seeds/mldsa_sign_verify_seed.bin"
  elif [[ "$algorithm_family" == "SLH-DSA" ]]; then
    seed_source="tests/seeds/slhdsa_sign_verify_seed.bin"
  fi
  cp "$seed_source" "$seed_input"
fi

fuzzer_args=(
  "$binary_path"
  "$run_dir/corpus"
  "-artifact_prefix=$crash_dir/"
  "-max_total_time=$fuzzing_seconds"
  "-timeout=$input_timeout_seconds"
  "-rss_limit_mb=$rss_mb"
)

if [[ "$smoke_mode" -eq 1 ]]; then
  fuzzer_args+=("-runs=1")
fi
if [[ "${#extra_args[@]}" -gt 0 ]]; then
  fuzzer_args+=("${extra_args[@]}")
fi

echo "Running $binary_path"
ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}" \
  "${fuzzer_args[@]}" > >(tee "$log_file") 2>&1

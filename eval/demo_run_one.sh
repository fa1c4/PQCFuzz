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

jobs_file="$repo_root/differential_fuzzer/data/fuzzer_jobs.json"
if [[ ! -f "$jobs_file" ]]; then
  echo "missing $jobs_file; run python3 differential_fuzzer/diff_fuzzer.py first." >&2
  exit 1
fi

job_json="$(jq -c --arg job_id "$job_id" '.[] | select(.job_id == $job_id)' "$jobs_file")"
if [[ -z "$job_json" ]]; then
  echo "unknown job_id '$job_id'" >&2
  exit 1
fi

primitive_type="$(jq -r '.primitive_type' <<<"$job_json")"
if [[ "$primitive_type" != "kpke" ]]; then
  echo "run_one.sh currently supports only kpke jobs; '$job_id' uses primitive '$primitive_type'." >&2
  exit 1
fi

build_dir="$repo_root/$(jq -r '.build_dir' <<<"$job_json")"
run_dir="$repo_root/$(jq -r '.run_dir' <<<"$job_json")"
result_dir="$repo_root/$(jq -r '.result_dir' <<<"$job_json")"
crash_dir="$repo_root/$(jq -r '.crash_dir' <<<"$job_json")"
timeout_seconds="$(jq -r '.resource_defaults.timeout_seconds' <<<"$job_json")"
rss_mb="$(jq -r '.resource_defaults.rss_mb' <<<"$job_json")"

binary_path="$build_dir/fuzzer"
if [[ ! -x "$binary_path" ]]; then
  echo "missing $binary_path; run eval/build_one.sh $job_id first." >&2
  exit 1
fi

mkdir -p "$run_dir/corpus" "$result_dir" "$crash_dir"
log_file="$run_dir/run.log"
seed_input="$run_dir/corpus/seed-kpke-input"

if [[ ! -f "$seed_input" ]]; then
  printf '\x00\x00\x00\x00\x00' >"$seed_input"
fi

fuzzer_args=(
  "$binary_path"
  "$run_dir/corpus"
  "-artifact_prefix=$crash_dir/"
  "-max_total_time=$timeout_seconds"
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

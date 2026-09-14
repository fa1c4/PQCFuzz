#!/usr/bin/env bash
# Build dedicated fault-injection replay binaries for a generated job.
#
# The binary links src/runtime/alloc_fault_injector.cc and uses
# -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc so allocation sites can be
# failed deterministically with PQCFUZZ_ALLOC_FAIL_AT / PQCFUZZ_ALLOC_FAIL_COUNT.
# RNG failure modes are selected through the RngTape::Mode used by the oracle
# that exercises them.
#
# Usage: scripts/pqcfuzz_build_fault_binaries.sh <job_id> [build_dir]
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <job_id> [build_dir]" >&2
  exit 1
fi

job_id="$1"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

job_file="$repo_root/workspace/jobs/$job_id.json"
if [[ ! -f "$job_file" ]]; then
  echo "missing $job_file; run scripts/pqcfuzz_eval.sh or eval/build_all.sh first" >&2
  exit 1
fi

fields="$(python3 - "$job_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    job = json.load(handle)
paths = job.get("paths", {})
pair = job.get("pair", {})
target = job.get("target", {})
left = pair.get("left", target)
right = pair.get("right", {})
exchange = pair.get("exchange_contract", job.get("exchange_contract", {}))
print("\t".join([
    job.get("fuzzer_source", ""),
    paths.get("generated_config", ""),
    paths.get("result_dir", ""),
    job.get("pair_id", ""),
    job.get("algorithm", ""),
    job.get("oracle_suite", "fips"),
    job.get("relation_mode", "cross-implementation"),
    left.get("project_id", ""),
    left.get("implementation_id", ""),
    right.get("project_id", ""),
    right.get("implementation_id", ""),
    "1" if exchange.get("public_key_exchange", False) else "0",
    "1" if exchange.get("ciphertext_exchange", False) else "0",
    "1" if exchange.get("secret_key_exchange", False) else "0",
    "1" if exchange.get("secret_key_format_compatible", False) else "0",
    "1" if exchange.get("signature_exchange", False) else "0",
]))
PY
)"
IFS=$'\t' read -r fuzzer_source generated_config_rel result_dir_rel pair_id algorithm oracle_suite relation_mode \
  left_project left_impl right_project right_impl pk_exchange ct_exchange sk_exchange sk_compat sig_exchange <<<"$fields"

build_dir="${2:-$repo_root/workspace/build/$job_id}"
mkdir -p "$build_dir"

cxx_bin="${CXX:-$(command -v clang++ || command -v c++)}"

sources=(
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
  src/adapters/randombytes_override.cc
  src/adapters/reference/pqclean_randombytes_override.cc
  src/mutators/envelope.cc
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
  src/oracles/oracle_record.cc
  src/oracles/oracle_result.cc
  src/oracles/oracle_executor.cc
  src/oracles/metamorphic_observation.cc
  src/oracles/metamorphic_spec.cc
  src/oracles/metamorphic_executor.cc
  src/runtime/adapter_registry.cc
  src/runtime/alloc_fault_injector.cc
  src/runtime/isolated_worker.cc
  src/runtime/replay_args.cc
  src/triage/finding_writer.cc
  src/triage/oracle_coverage.cc
)

reference_archive="$repo_root/workspace/build/reference/libpqcfuzz_pqclean_reference.a"
reference_flags=()
if [[ -f "$reference_archive" ]]; then
  reference_flags+=(-DPQCFUZZ_HAVE_PQCLEAN_REFERENCE "$reference_archive")
fi

"$cxx_bin" -std=c++17 -O1 -g -fno-omit-frame-pointer -Isrc \
  -DPQCFUZZ_JOB_ID="\"$job_id\"" \
  -DPQCFUZZ_PAIR_ID="\"$pair_id\"" \
  -DPQCFUZZ_RESULT_DIR="\"$result_dir_rel\"" \
  -DPQCFUZZ_GENERATED_CONFIG_PATH="\"$generated_config_rel\"" \
  -DPQCFUZZ_LEFT_PROJECT_ID="\"$left_project\"" \
  -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"$left_impl\"" \
  -DPQCFUZZ_RIGHT_PROJECT_ID="\"$right_project\"" \
  -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"$right_impl\"" \
  -DPQCFUZZ_RELATION_MODE="\"$relation_mode\"" \
  -DPQCFUZZ_ORACLE_SUITE="\"$oracle_suite\"" \
  -DPQCFUZZ_PUBLIC_KEY_EXCHANGE="$pk_exchange" \
  -DPQCFUZZ_CIPHERTEXT_EXCHANGE="$ct_exchange" \
  -DPQCFUZZ_SECRET_KEY_EXCHANGE="$sk_exchange" \
  -DPQCFUZZ_SECRET_KEY_FORMAT_COMPATIBLE="$sk_compat" \
  -DPQCFUZZ_SIGNATURE_EXCHANGE="$sig_exchange" \
  src/replay/replay_oracle.cc "${sources[@]}" "${reference_flags[@]}" \
  -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc \
  -o "$build_dir/replay_oracle_fault"

"$cxx_bin" -std=c++17 -O1 -g -fno-omit-frame-pointer -Isrc \
  src/replay/alloc_probe.cc "${sources[@]}" \
  src/oracles/alloc_failure_oracle.cc "${reference_flags[@]}" \
  -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc \
  -o "$build_dir/alloc_probe"
echo "built $build_dir/replay_oracle_fault"
echo "built $build_dir/alloc_probe"
echo "allocation failures: PQCFUZZ_ALLOC_FAIL_AT=<n> PQCFUZZ_ALLOC_FAIL_COUNT=<k>"

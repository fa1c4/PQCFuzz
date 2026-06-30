#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <job_id>" >&2
  exit 1
fi

job_id="$1"
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
pair = job.get("pair", {})
target = job.get("target", {})
left = pair.get("left", target)
right = pair.get("right", {})
exchange = pair.get("exchange_contract", job.get("exchange_contract", {}))
fields = [
    job.get("primitive_type", ""),
    job.get("fuzzer_source", ""),
    paths.get("generated_config", ""),
    paths.get("build_dir", ""),
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
]
print("\t".join(fields))
PY
)"
IFS=$'\t' read -r primitive_type fuzzer_source generated_config_rel build_dir_rel result_dir_rel pair_id algorithm oracle_suite relation_mode left_project_id left_implementation_id right_project_id right_implementation_id public_key_exchange ciphertext_exchange secret_key_exchange secret_key_format_compatible signature_exchange <<<"$job_fields"

if [[ "$primitive_type" != "kem" && "$primitive_type" != "sig" ]]; then
  echo "build_one.sh supports generated kem and sig jobs; '$job_id' uses primitive '$primitive_type'." >&2
  exit 1
fi

build_dir="$repo_root/$build_dir_rel"
mkdir -p "$build_dir" "$repo_root/$result_dir_rel"

cxx_bin="${CXX:-$(command -v clang++ || command -v c++)}"
if [[ -z "$cxx_bin" ]]; then
  echo "missing C++ compiler." >&2
  exit 1
fi

sanitizers="${PQCFUZZ_SANITIZERS:-address,undefined}"
case "$sanitizers" in
  address,undefined|undefined,address)
    replay_sanitize_flag="-fsanitize=address,undefined"
    fuzzer_sanitize_flag="-fsanitize=fuzzer,address,undefined"
    ;;
  memory)
    replay_sanitize_flag="-fsanitize=memory"
    fuzzer_sanitize_flag="-fsanitize=fuzzer,memory"
    ;;
  none|"")
    replay_sanitize_flag=""
    fuzzer_sanitize_flag="-fsanitize=fuzzer"
    ;;
  *)
    echo "unsupported PQCFUZZ_SANITIZERS='$sanitizers' (expected address,undefined, memory, or none)" >&2
    exit 2
    ;;
esac

deps=(
  src/adapters/status.cc
  src/adapters/liboqs/kem_adapter.cc
  src/adapters/liboqs/sig_adapter.cc
  src/adapters/liboqs/rng_control.cc
  src/adapters/pqclean/kem_adapter.cc
  src/adapters/pqclean/sig_adapter.cc
  src/adapters/pqclean/randombytes_override.cc
  src/adapters/rng_control.cc
  src/mutators/envelope.cc
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
  src/oracles/oracle_executor.cc
  src/oracles/metamorphic_observation.cc
  src/oracles/metamorphic_spec.cc
  src/oracles/metamorphic_executor.cc
  src/runtime/adapter_registry.cc
  src/runtime/replay_args.cc
  src/triage/finding_writer.cc
)

common_defines=(
  -DPQCFUZZ_JOB_ID="\"$job_id\"" \
  -DPQCFUZZ_PAIR_ID="\"$pair_id\"" \
  -DPQCFUZZ_RESULT_DIR="\"$result_dir_rel\"" \
  -DPQCFUZZ_GENERATED_CONFIG_PATH="\"$generated_config_rel\"" \
  -DPQCFUZZ_LEFT_PROJECT_ID="\"$left_project_id\"" \
  -DPQCFUZZ_LEFT_IMPLEMENTATION_ID="\"$left_implementation_id\"" \
  -DPQCFUZZ_RIGHT_PROJECT_ID="\"$right_project_id\"" \
  -DPQCFUZZ_RIGHT_IMPLEMENTATION_ID="\"$right_implementation_id\"" \
  -DPQCFUZZ_RELATION_MODE="\"$relation_mode\"" \
  -DPQCFUZZ_ORACLE_SUITE="\"$oracle_suite\"" \
  -DPQCFUZZ_PUBLIC_KEY_EXCHANGE="$public_key_exchange" \
  -DPQCFUZZ_CIPHERTEXT_EXCHANGE="$ciphertext_exchange" \
  -DPQCFUZZ_SECRET_KEY_EXCHANGE="$secret_key_exchange" \
  -DPQCFUZZ_SECRET_KEY_FORMAT_COMPATIBLE="$secret_key_format_compatible" \
  -DPQCFUZZ_SIGNATURE_EXCHANGE="$signature_exchange"
)

"$cxx_bin" -std=c++17 -O1 -g -Isrc $fuzzer_sanitize_flag \
  "${common_defines[@]}" \
  "$fuzzer_source" "${deps[@]}" -o "$build_dir/fuzzer"

"$cxx_bin" -std=c++17 -O1 -g -Isrc $replay_sanitize_flag \
  "${common_defines[@]}" \
  src/replay/replay_oracle.cc "${deps[@]}" -o "$build_dir/replay_oracle"

echo "built $build_dir_rel/fuzzer"
echo "built $build_dir_rel/replay_oracle"

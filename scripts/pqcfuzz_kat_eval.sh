#!/usr/bin/env bash
# Build and run the NIST ACVP KAT oracles against the pinned PQClean reference
# adapters.  Results are written through the standard oracle-coverage and
# finding-artifact pipeline under workspace/results/kat/.
#
# Usage:
#   scripts/pqcfuzz_kat_eval.sh build
#   scripts/pqcfuzz_kat_eval.sh run [ML-KEM-512 ML-KEM-768 ML-KEM-1024]
#   scripts/pqcfuzz_kat_eval.sh all
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

build_dir="${KAT_BUILD_DIR:-$repo_root/workspace/build/kat}"
result_root="${KAT_RESULT_ROOT:-$repo_root/workspace/results/kat}"
reference_archive="$repo_root/workspace/build/reference/libpqcfuzz_pqclean_reference.a"
kat_oracles=(fips203_kat_keygen fips203_kat_encaps fips203_kat_decaps)

build_runner() {
  if [[ ! -f "$reference_archive" ]]; then
    "$repo_root/scripts/build_pqclean_reference.sh"
  fi
  mkdir -p "$build_dir"
  local cxx_bin="${CXX:-$(command -v clang++ || command -v c++)}"
  "$cxx_bin" -std=c++17 -O2 -g -Isrc -DPQCFUZZ_HAVE_PQCLEAN_REFERENCE \
    src/replay/kat_oracle.cc \
    src/oracles/kat_executor.cc \
    src/adapters/status.cc \
    src/adapters/reference/reference_adapter.cc \
    src/adapters/reference/pqclean_randombytes_override.cc \
    src/adapters/rng_control.cc \
    src/adapters/liboqs/rng_control.cc \
    src/adapters/liboqs/kem_adapter.cc \
    src/adapters/liboqs/sig_adapter.cc \
    src/adapters/pqclean/kem_adapter.cc \
    src/adapters/pqclean/sig_adapter.cc \
    src/adapters/pqmagic/kem_adapter.cc \
    src/adapters/pqmagic/sig_adapter.cc \
    src/adapters/randombytes_override.cc \
    src/mutators/envelope.cc \
    src/mutators/maul.cc \
    src/mutators/ml_kem_layout.cc \
    src/mutators/ml_kem_mutator.cc \
    src/mutators/ml_dsa_layout.cc \
    src/mutators/ml_dsa_mutator.cc \
    src/mutators/slh_dsa_layout.cc \
    src/mutators/slh_dsa_mutator.cc \
    src/mutators/aigis_enc_layout.cc \
    src/mutators/aigis_enc_mutator.cc \
    src/mutators/aigis_sig_layout.cc \
    src/mutators/aigis_sig_mutator.cc \
    src/oracles/expected_relation.cc \
    src/oracles/oracle_spec.cc \
    src/oracles/oracle_spec_loader.cc \
    src/oracles/oracle_record.cc \
    src/oracles/oracle_result.cc \
    src/oracles/oracle_executor.cc \
    src/oracles/metamorphic_observation.cc \
    src/oracles/metamorphic_spec.cc \
    src/oracles/metamorphic_executor.cc \
    src/adapters/cross/cross_adapter.cc
    src/runtime/adapter_registry.cc \
    src/triage/finding_writer.cc \
    src/triage/oracle_coverage.cc \
    "$reference_archive" \
    -o "$build_dir/kat_oracle"
  echo "built $build_dir/kat_oracle"
}

run_kat() {
  local algorithms=("$@")
  if [[ ${#algorithms[@]} -eq 0 ]]; then
    algorithms=(ML-KEM-512 ML-KEM-768 ML-KEM-1024 SLH-DSA-SHA2-128s SLH-DSA-SHAKE-128s)
  fi
  local failures=0
  for algorithm in "${algorithms[@]}"; do
    local result_dir="$result_root/$algorithm"
    mkdir -p "$result_dir"
    local oracles=("${kat_oracles[@]}")
    if [[ "$algorithm" == SLH-DSA-* ]]; then
      oracles=(fips205_kat_keygen)
    fi
    for oracle_id in "${oracles[@]}"; do
      if ! "$build_dir/kat_oracle" \
          --result-dir "$result_dir" \
          --algorithm "$algorithm" \
          --oracle-id "$oracle_id"; then
        failures=$((failures + 1))
      fi
    done
    echo "coverage: $result_dir/oracle_coverage.json"
  done
  if [[ $failures -ne 0 ]]; then
    echo "$failures KAT oracle run(s) reported mismatches" >&2
    return 1
  fi
}

case "${1:-all}" in
  build) build_runner ;;
  run) shift || true; run_kat "$@" ;;
  all) build_runner; run_kat "${@:2}" ;;
  *) echo "usage: $0 build|run|all [algorithms...]" >&2; exit 2 ;;
esac

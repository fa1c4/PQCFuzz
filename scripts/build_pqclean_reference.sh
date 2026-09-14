#!/usr/bin/env bash
# Build the pinned PQClean clean-reference archive used by reference adapters,
# KAT oracles, and deterministic-hook tests.
#
# Usage: scripts/build_pqclean_reference.sh [output_dir]
#
# Environment:
#   PQClean_DIR     source tree (default: third_party/PQClean)
#   PQClean_COMMIT  expected pinned commit (default below)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

pqclean_dir="${PQClean_DIR:-$repo_root/third_party/PQClean}"
expected_commit="${PQClean_COMMIT:-0586a824fc0d49df0b6b6e9179d8d15d06d0974f}"

if [[ ! -d "$pqclean_dir" ]]; then
  mkdir -p "$(dirname "$pqclean_dir")"
  git clone --depth 1 https://github.com/PQClean/PQClean.git "$pqclean_dir"
fi

actual_commit="$(git -C "$pqclean_dir" rev-parse HEAD 2>/dev/null || true)"
if [[ "$actual_commit" != "$expected_commit" ]]; then
  echo "warning: PQClean is at ${actual_commit:-unknown}, expected $expected_commit" >&2
fi

out_dir="${1:-$repo_root/workspace/build/reference}"
obj_dir="$out_dir/obj"
rm -rf "$obj_dir"
mkdir -p "$obj_dir"

cc="${CC:-cc}"
common_flags=(-O2 -fPIC -I"$pqclean_dir/common")

sources=(
  "$pqclean_dir/common/fips202.c"
  "$pqclean_dir/crypto_kem/ml-kem-512/clean/cbd.c"
  "$pqclean_dir/crypto_kem/ml-kem-512/clean/indcpa.c"
  "$pqclean_dir/crypto_kem/ml-kem-512/clean/kem.c"
  "$pqclean_dir/crypto_kem/ml-kem-512/clean/ntt.c"
  "$pqclean_dir/crypto_kem/ml-kem-512/clean/poly.c"
  "$pqclean_dir/crypto_kem/ml-kem-512/clean/polyvec.c"
  "$pqclean_dir/crypto_kem/ml-kem-512/clean/reduce.c"
  "$pqclean_dir/crypto_kem/ml-kem-512/clean/symmetric-shake.c"
  "$pqclean_dir/crypto_kem/ml-kem-512/clean/verify.c"
  "$pqclean_dir/crypto_kem/ml-kem-768/clean/cbd.c"
  "$pqclean_dir/crypto_kem/ml-kem-768/clean/indcpa.c"
  "$pqclean_dir/crypto_kem/ml-kem-768/clean/kem.c"
  "$pqclean_dir/crypto_kem/ml-kem-768/clean/ntt.c"
  "$pqclean_dir/crypto_kem/ml-kem-768/clean/poly.c"
  "$pqclean_dir/crypto_kem/ml-kem-768/clean/polyvec.c"
  "$pqclean_dir/crypto_kem/ml-kem-768/clean/reduce.c"
  "$pqclean_dir/crypto_kem/ml-kem-768/clean/symmetric-shake.c"
  "$pqclean_dir/crypto_kem/ml-kem-768/clean/verify.c"
  "$pqclean_dir/crypto_kem/ml-kem-1024/clean/cbd.c"
  "$pqclean_dir/crypto_kem/ml-kem-1024/clean/indcpa.c"
  "$pqclean_dir/crypto_kem/ml-kem-1024/clean/kem.c"
  "$pqclean_dir/crypto_kem/ml-kem-1024/clean/ntt.c"
  "$pqclean_dir/crypto_kem/ml-kem-1024/clean/poly.c"
  "$pqclean_dir/crypto_kem/ml-kem-1024/clean/polyvec.c"
  "$pqclean_dir/crypto_kem/ml-kem-1024/clean/reduce.c"
  "$pqclean_dir/crypto_kem/ml-kem-1024/clean/symmetric-shake.c"
  "$pqclean_dir/crypto_kem/ml-kem-1024/clean/verify.c"
  "$pqclean_dir/crypto_sign/ml-dsa-44/clean/ntt.c"
  "$pqclean_dir/crypto_sign/ml-dsa-44/clean/packing.c"
  "$pqclean_dir/crypto_sign/ml-dsa-44/clean/poly.c"
  "$pqclean_dir/crypto_sign/ml-dsa-44/clean/polyvec.c"
  "$pqclean_dir/crypto_sign/ml-dsa-44/clean/reduce.c"
  "$pqclean_dir/crypto_sign/ml-dsa-44/clean/rounding.c"
  "$pqclean_dir/crypto_sign/ml-dsa-44/clean/sign.c"
  "$pqclean_dir/crypto_sign/ml-dsa-44/clean/symmetric-shake.c"
  "$pqclean_dir/crypto_sign/ml-dsa-65/clean/ntt.c"
  "$pqclean_dir/crypto_sign/ml-dsa-65/clean/packing.c"
  "$pqclean_dir/crypto_sign/ml-dsa-65/clean/poly.c"
  "$pqclean_dir/crypto_sign/ml-dsa-65/clean/polyvec.c"
  "$pqclean_dir/crypto_sign/ml-dsa-65/clean/reduce.c"
  "$pqclean_dir/crypto_sign/ml-dsa-65/clean/rounding.c"
  "$pqclean_dir/crypto_sign/ml-dsa-65/clean/sign.c"
  "$pqclean_dir/crypto_sign/ml-dsa-65/clean/symmetric-shake.c"
  "$pqclean_dir/crypto_sign/ml-dsa-87/clean/ntt.c"
  "$pqclean_dir/crypto_sign/ml-dsa-87/clean/packing.c"
  "$pqclean_dir/crypto_sign/ml-dsa-87/clean/poly.c"
  "$pqclean_dir/crypto_sign/ml-dsa-87/clean/polyvec.c"
  "$pqclean_dir/crypto_sign/ml-dsa-87/clean/reduce.c"
  "$pqclean_dir/crypto_sign/ml-dsa-87/clean/rounding.c"
  "$pqclean_dir/crypto_sign/ml-dsa-87/clean/sign.c"
  "$pqclean_dir/crypto_sign/ml-dsa-87/clean/symmetric-shake.c"
)

# SLH-DSA (SPHINCS+ simple) parameter sets share one source layout.
sphincs_dirs=(
  sphincs-sha2-128s-simple sphincs-sha2-128f-simple
  sphincs-sha2-192s-simple sphincs-sha2-192f-simple
  sphincs-sha2-256s-simple sphincs-sha2-256f-simple
  sphincs-shake-128s-simple sphincs-shake-128f-simple
  sphincs-shake-192s-simple sphincs-shake-192f-simple
  sphincs-shake-256s-simple sphincs-shake-256f-simple
)
for sphincs_dir in "${sphincs_dirs[@]}"; do
  base="$pqclean_dir/crypto_sign/$sphincs_dir/clean"
  sources+=(
    "$base/address.c"
    "$base/fors.c"
    "$base/merkle.c"
    "$base/sign.c"
    "$base/utils.c"
    "$base/utilsx1.c"
    "$base/wots.c"
    "$base/wotsx1.c"
  )
  if [[ "$sphincs_dir" == *sha2* ]]; then
    sources+=("$base/context_sha2.c" "$base/hash_sha2.c" "$base/thash_sha2_simple.c")
  else
    sources+=("$base/context_shake.c" "$base/hash_shake.c" "$base/thash_shake_simple.c")
  fi
done
sources+=("$pqclean_dir/common/sha2.c")

objects=()
for source in "${sources[@]}"; do
  if [[ ! -f "$source" ]]; then
    echo "missing PQClean source: $source" >&2
    exit 1
  fi
  object="$obj_dir/$(echo "${source#"$pqclean_dir"/}" | tr '/' '_').o"
  "$cc" "${common_flags[@]}" -c "$source" -o "$object"
  objects+=("$object")
done

archive="$out_dir/libpqcfuzz_pqclean_reference.a"
rm -f "$archive"
ar rcs "$archive" "${objects[@]}"
echo "built $archive"
echo "commit: ${actual_commit:-unknown}"

#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <job_id>" >&2
  exit 1
fi

job_id="$1"
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
  echo "build_one.sh currently supports only kpke jobs; '$job_id' uses primitive '$primitive_type'." >&2
  exit 1
fi

left_impl="$(jq -r '.left.implementation_id' <<<"$job_json")"
right_impl="$(jq -r '.right.implementation_id' <<<"$job_json")"
if [[ "$left_impl" != "liboqs_mlkem768_kpke_native_ref" || "$right_impl" != "pqclean_mlkem768_kpke_clean" ]]; then
  echo "build_one.sh only supports liboqs_mlkem768_kpke_native_ref vs pqclean_mlkem768_kpke_clean in v1." >&2
  exit 1
fi

left_project_id="$(jq -r '.left.project_id' <<<"$job_json")"
right_project_id="$(jq -r '.right.project_id' <<<"$job_json")"
left_pk_len="$(jq -r '.left.abi.pk_len' <<<"$job_json")"
left_sk_len="$(jq -r '.left.abi.sk_len' <<<"$job_json")"
left_ct_len="$(jq -r '.left.abi.ct_len' <<<"$job_json")"
left_msg_len="$(jq -r '.left.abi.msg_len' <<<"$job_json")"
right_pk_len="$(jq -r '.right.abi.pk_len' <<<"$job_json")"
right_sk_len="$(jq -r '.right.abi.sk_len' <<<"$job_json")"
right_ct_len="$(jq -r '.right.abi.ct_len' <<<"$job_json")"
right_msg_len="$(jq -r '.right.abi.msg_len' <<<"$job_json")"

generated_harness_rel="$(jq -r '.generated_harness' <<<"$job_json")"
generated_harness="$repo_root/$generated_harness_rel"
if [[ ! -f "$generated_harness" ]]; then
  echo "missing $generated_harness; run python3 differential_fuzzer/diff_fuzzer.py first." >&2
  exit 1
fi

build_dir_rel="$(jq -r '.build_dir' <<<"$job_json")"
build_dir="$repo_root/$build_dir_rel"
mkdir -p "$build_dir"

upstream_root="$repo_root/workspace/build/upstreams"
liboqs_build="$upstream_root/liboqs-mlkem768"
pqclean_build="$upstream_root/pqclean-mlkem768"
mkdir -p "$upstream_root" "$pqclean_build/obj"

clang_bin="${CC:-$(command -v clang)}"
clangxx_bin="${CXX:-$(command -v clang++)}"
cmake_bin="${CMAKE:-$(command -v cmake)}"
ar_bin="$(command -v llvm-ar || command -v ar)"

if [[ -z "$clang_bin" || -z "$clangxx_bin" || -z "$cmake_bin" || -z "$ar_bin" ]]; then
  echo "missing required toolchain components (clang, clang++, cmake, ar)." >&2
  exit 1
fi

parallel_jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
c_sanitize_flags=(-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined)
cxx_sanitize_flags=(-std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined)
link_sanitize_flags=(-std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined)

echo "Configuring instrumented liboqs build in $liboqs_build"
"$cmake_bin" -S "$repo_root/projects/liboqs" -B "$liboqs_build" \
  -DCMAKE_C_COMPILER="$clang_bin" \
  -DCMAKE_ASM_COMPILER="$clang_bin" \
  -DBUILD_SHARED_LIBS=OFF \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_MINIMAL_BUILD=KEM_ml_kem_768 \
  -DCMAKE_C_FLAGS="${c_sanitize_flags[*]}" \
  -DCMAKE_ASM_FLAGS="-fno-omit-frame-pointer"

echo "Building liboqs static archive"
"$cmake_bin" --build "$liboqs_build" --target oqs --parallel "$parallel_jobs"

liboqs_archive="$liboqs_build/lib/liboqs.a"
if [[ ! -f "$liboqs_archive" ]]; then
  echo "expected liboqs archive not found at $liboqs_archive" >&2
  exit 1
fi

pqclean_archive="$pqclean_build/libpqclean_mlkem768_kpke.a"
pqclean_obj_dir="$pqclean_build/obj"
pqclean_src_dir="$repo_root/projects/PQClean/crypto_kem/ml-kem-768/clean"
pqclean_common_dir="$repo_root/projects/PQClean/common"
pqclean_sources=(
  "$pqclean_src_dir/cbd.c"
  "$pqclean_src_dir/indcpa.c"
  "$pqclean_src_dir/ntt.c"
  "$pqclean_src_dir/poly.c"
  "$pqclean_src_dir/polyvec.c"
  "$pqclean_src_dir/reduce.c"
  "$pqclean_src_dir/symmetric-shake.c"
  "$pqclean_src_dir/verify.c"
  "$pqclean_common_dir/fips202.c"
)
pqclean_objects=()

echo "Building PQClean kpke static archive"
for src in "${pqclean_sources[@]}"; do
  obj="$pqclean_obj_dir/$(basename "${src%.c}").o"
  "$clang_bin" "${c_sanitize_flags[@]}" -std=c99 \
    -I"$pqclean_src_dir" \
    -I"$pqclean_common_dir" \
    -c "$src" -o "$obj"
  pqclean_objects+=("$obj")
done
"$ar_bin" rcs "$pqclean_archive" "${pqclean_objects[@]}"

adapter_src="$build_dir/generated_kpke_adapters.cpp"
adapter_obj="$build_dir/generated_kpke_adapters.o"
harness_obj="$build_dir/generated_harness.o"
binary_path="$build_dir/fuzzer"

cat >"$adapter_src" <<EOF
#include <cstddef>
#include <cstdint>

#include "differential_fuzzer/adapters/adapter_interface.h"

extern "C" {
void PQCP_MLKEM_NATIVE_MLKEM768_C_indcpa_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
void PQCP_MLKEM_NATIVE_MLKEM768_C_indcpa_enc(uint8_t *ct, const uint8_t *msg, const uint8_t *pk, const uint8_t *coins);
void PQCP_MLKEM_NATIVE_MLKEM768_C_indcpa_dec(uint8_t *msg, const uint8_t *ct, const uint8_t *sk);

void PQCLEAN_MLKEM768_CLEAN_indcpa_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
void PQCLEAN_MLKEM768_CLEAN_indcpa_enc(uint8_t *ct, const uint8_t *msg, const uint8_t *pk, const uint8_t *coins);
void PQCLEAN_MLKEM768_CLEAN_indcpa_dec(uint8_t *msg, const uint8_t *ct, const uint8_t *sk);
}

static constexpr std::size_t kSeedLen = 32;

static int LeftKeygenDerand(uint8_t *pk, uint8_t *sk, const uint8_t *seed, std::size_t seed_len) {
  if (seed_len != kSeedLen) {
    return 1;
  }
  PQCP_MLKEM_NATIVE_MLKEM768_C_indcpa_keypair_derand(pk, sk, seed);
  return 0;
}

static int LeftEncrypt(uint8_t *ct, const uint8_t *msg, const uint8_t *pk, const uint8_t *coins, std::size_t coins_len) {
  if (coins_len != kSeedLen) {
    return 1;
  }
  PQCP_MLKEM_NATIVE_MLKEM768_C_indcpa_enc(ct, msg, pk, coins);
  return 0;
}

static int LeftDecrypt(uint8_t *msg, const uint8_t *ct, const uint8_t *sk) {
  PQCP_MLKEM_NATIVE_MLKEM768_C_indcpa_dec(msg, ct, sk);
  return 0;
}

static int RightKeygenDerand(uint8_t *pk, uint8_t *sk, const uint8_t *seed, std::size_t seed_len) {
  if (seed_len != kSeedLen) {
    return 1;
  }
  PQCLEAN_MLKEM768_CLEAN_indcpa_keypair_derand(pk, sk, seed);
  return 0;
}

static int RightEncrypt(uint8_t *ct, const uint8_t *msg, const uint8_t *pk, const uint8_t *coins, std::size_t coins_len) {
  if (coins_len != kSeedLen) {
    return 1;
  }
  PQCLEAN_MLKEM768_CLEAN_indcpa_enc(ct, msg, pk, coins);
  return 0;
}

static int RightDecrypt(uint8_t *msg, const uint8_t *ct, const uint8_t *sk) {
  PQCLEAN_MLKEM768_CLEAN_indcpa_dec(msg, ct, sk);
  return 0;
}

static const pqcdf_kpke_adapter kLeftAdapter = {
    "${left_project_id}",
    "${left_impl}",
    static_cast<std::size_t>(${left_pk_len}),
    static_cast<std::size_t>(${left_sk_len}),
    static_cast<std::size_t>(${left_ct_len}),
    static_cast<std::size_t>(${left_msg_len}),
    1,
    nullptr,
    nullptr,
    LeftKeygenDerand,
    LeftEncrypt,
    LeftDecrypt,
};

static const pqcdf_kpke_adapter kRightAdapter = {
    "${right_project_id}",
    "${right_impl}",
    static_cast<std::size_t>(${right_pk_len}),
    static_cast<std::size_t>(${right_sk_len}),
    static_cast<std::size_t>(${right_ct_len}),
    static_cast<std::size_t>(${right_msg_len}),
    1,
    nullptr,
    nullptr,
    RightKeygenDerand,
    RightEncrypt,
    RightDecrypt,
};

extern "C" const pqcdf_kpke_adapter *pqcdf_get_left_kpke_adapter(void) { return &kLeftAdapter; }
extern "C" const pqcdf_kpke_adapter *pqcdf_get_right_kpke_adapter(void) { return &kRightAdapter; }
EOF

echo "Compiling generated harness and adapter shims"
"$clangxx_bin" "${cxx_sanitize_flags[@]}" -I"$repo_root" -c "$generated_harness" -o "$harness_obj"
"$clangxx_bin" "${cxx_sanitize_flags[@]}" -I"$repo_root" -c "$adapter_src" -o "$adapter_obj"

echo "Linking final fuzzer"
"$clangxx_bin" "${link_sanitize_flags[@]}" -o "$binary_path" \
  "$harness_obj" \
  "$adapter_obj" \
  "$pqclean_archive" \
  "$liboqs_archive" \
  -lcrypto -ldl -lpthread -lm

echo "Built $binary_path"

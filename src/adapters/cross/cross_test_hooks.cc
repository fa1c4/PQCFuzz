#include "adapters/cross/cross_test_hooks.h"

#ifdef PQCFUZZ_HAVE_CROSS

#include <cstring>

extern "C" {
#include "csprng_hash.h"
#include "pack_unpack.h"
#include "parameters.h"
}

namespace pqcfuzz {
namespace {

bool CopyCoefficientsY(const uint16_t *coeffs, size_t count, uint8_t *out) {
  if (coeffs == nullptr || out == nullptr || count > N) {
    return false;
  }
  FP_ELEM dense[N] = {0};
  for (size_t i = 0; i < count; ++i) {
    dense[i] = (FP_ELEM)coeffs[i];
  }
  pack_fp_vec(out, dense);
  return true;
}

bool CopyCoefficientsV(const uint16_t *coeffs, size_t count, uint8_t *out) {
  if (coeffs == nullptr || out == nullptr) {
    return false;
  }
#ifdef RSDP
  if (count > N) {
    return false;
  }
  FZ_ELEM dense[N] = {0};
  for (size_t i = 0; i < count; ++i) {
    dense[i] = (FZ_ELEM)coeffs[i];
  }
  pack_fz_vec(out, dense);
  return true;
#else
  if (count > M) {
    return false;
  }
  FZ_ELEM dense[M] = {0};
  for (size_t i = 0; i < count; ++i) {
    dense[i] = (FZ_ELEM)coeffs[i];
  }
  pack_fz_rsdp_g_vec(out, dense);
  return true;
#endif
}

bool CopyCoefficientsSyn(const uint16_t *coeffs, size_t count, uint8_t *out) {
  if (coeffs == nullptr || out == nullptr || count > N - K) {
    return false;
  }
  FP_ELEM dense[N - K] = {0};
  for (size_t i = 0; i < count; ++i) {
    dense[i] = (FP_ELEM)coeffs[i];
  }
  pack_fp_syn(out, dense);
  return true;
}

}  // namespace

size_t CrossHookPackY(uint8_t *out, size_t out_len, const uint16_t *coeffs, size_t count) {
  if (out_len < DENSELY_PACKED_FP_VEC_SIZE || !CopyCoefficientsY(coeffs, count, out)) {
    return 0;
  }
  return DENSELY_PACKED_FP_VEC_SIZE;
}

int CrossHookUnpackY(uint16_t *out, size_t count, const uint8_t *in, size_t in_len) {
  if (out == nullptr || in == nullptr || in_len < DENSELY_PACKED_FP_VEC_SIZE || count > N) {
    return 0;
  }
  FP_ELEM dense[N] = {0};
  if (unpack_fp_vec(dense, in) == 0) {
    return 0;
  }
  for (size_t i = 0; i < count; ++i) {
    out[i] = dense[i];
  }
  return 1;
}

size_t CrossHookPackV(uint8_t *out, size_t out_len, const uint16_t *coeffs, size_t count) {
#ifdef RSDP
  constexpr size_t kPackedSize = DENSELY_PACKED_FZ_VEC_SIZE;
#else
  constexpr size_t kPackedSize = DENSELY_PACKED_FZ_RSDP_G_VEC_SIZE;
#endif
  if (out_len < kPackedSize) {
    return 0;
  }
  return CopyCoefficientsV(coeffs, count, out) ? kPackedSize : 0;
}

int CrossHookUnpackV(uint16_t *out, size_t count, const uint8_t *in, size_t in_len) {
#ifdef RSDP
  constexpr size_t kPackedSize = DENSELY_PACKED_FZ_VEC_SIZE;
#else
  constexpr size_t kPackedSize = DENSELY_PACKED_FZ_RSDP_G_VEC_SIZE;
#endif
  if (out == nullptr || in == nullptr || in_len < kPackedSize) {
    return 0;
  }
#ifdef RSDP
  if (count > N) {
    return 0;
  }
  FZ_ELEM dense[N] = {0};
  if (unpack_fz_vec(dense, in) == 0) {
    return 0;
  }
  for (size_t i = 0; i < count; ++i) {
    out[i] = dense[i];
  }
  return 1;
#else
  if (count > M) {
    return 0;
  }
  FZ_ELEM dense[M] = {0};
  if (unpack_fz_rsdp_g_vec(dense, in) == 0) {
    return 0;
  }
  for (size_t i = 0; i < count; ++i) {
    out[i] = dense[i];
  }
  return 1;
#endif
}

size_t CrossHookPackSyndrome(uint8_t *out, size_t out_len, const uint16_t *coeffs, size_t count) {
  if (out_len < DENSELY_PACKED_FP_SYN_SIZE || !CopyCoefficientsSyn(coeffs, count, out)) {
    return 0;
  }
  return DENSELY_PACKED_FP_SYN_SIZE;
}

int CrossHookUnpackSyndrome(uint16_t *out, size_t count, const uint8_t *in, size_t in_len) {
  if (out == nullptr || in == nullptr || in_len < DENSELY_PACKED_FP_SYN_SIZE || count > N - K) {
    return 0;
  }
  FP_ELEM dense[N - K] = {0};
  if (unpack_fp_syn(dense, in) == 0) {
    return 0;
  }
  for (size_t i = 0; i < count; ++i) {
    out[i] = dense[i];
  }
  return 1;
}

size_t CrossHookExpandFixedWeight(uint8_t *out, size_t out_len, const uint8_t *digest, size_t digest_len) {
  if (out == nullptr || digest == nullptr || out_len < T || digest_len < HASH_DIGEST_LENGTH) {
    return 0;
  }
  expand_digest_to_fixed_weight(out, digest);
  return T;
}

size_t CrossHookYBytes() {
  return DENSELY_PACKED_FP_VEC_SIZE;
}

size_t CrossHookVBytes() {
  return DENSELY_PACKED_FZ_VEC_SIZE;
}

size_t CrossHookSynBytes() {
  return DENSELY_PACKED_FP_SYN_SIZE;
}

size_t CrossHookTreeNodesToStore() {
  return TREE_NODES_TO_STORE;
}

size_t CrossHookT() {
  return T;
}

size_t CrossHookW() {
  return W;
}

}  // namespace pqcfuzz

#endif  // PQCFUZZ_HAVE_CROSS

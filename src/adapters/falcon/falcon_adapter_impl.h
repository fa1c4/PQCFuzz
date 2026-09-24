#ifndef PQCFUZZ_ADAPTERS_FALCON_ADAPTER_IMPL_H
#define PQCFUZZ_ADAPTERS_FALCON_ADAPTER_IMPL_H

// Shared Falcon adapter helpers.  The official reference headers are only
// included in builds that define PQCFUZZ_HAVE_FALCON, so translation units can
// stay in the generic compile lists without requiring the vendored source.
#ifdef PQCFUZZ_HAVE_FALCON

#include <cstddef>
#include <cstdint>
#include <vector>

#include "adapters/adapter_interface.h"
#include "adapters/rng_control.h"
#include "adapters/status.h"
#include "falcon.h"

namespace pqcfuzz {
namespace falcon_internal {

constexpr size_t kPlatformSeedBytes = 48;

inline void FillSeedFromTapeOrSystem(uint8_t *out) {
  if (pqcfuzz_rng_is_active()) {
    if (!pqcfuzz_rng_fill_bytes(out, kPlatformSeedBytes)) {
      for (size_t i = 0; i < kPlatformSeedBytes; ++i) {
        out[i] = 0;
      }
    }
    return;
  }
  shake256_context rng;
  if (shake256_init_prng_from_system(&rng) != 0) {
    for (size_t i = 0; i < kPlatformSeedBytes; ++i) {
      out[i] = 0;
    }
    return;
  }
  shake256_extract(&rng, out, kPlatformSeedBytes);
}

inline void SeedRngFromBytes(shake256_context *rng, const uint8_t *seed, size_t seed_len) {
  shake256_init(rng);
  shake256_inject(rng, seed, seed_len);
  shake256_flip(rng);
}

}  // namespace falcon_internal

template <unsigned LOGN>
pqcfuzz_status FalconKeygenT(uint8_t *pk, uint8_t *sk) {
  if (pk == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  uint8_t seed[falcon_internal::kPlatformSeedBytes];
  falcon_internal::FillSeedFromTapeOrSystem(seed);
  shake256_context rng;
  falcon_internal::SeedRngFromBytes(&rng, seed, sizeof seed);
  std::vector<uint8_t> tmp(FALCON_TMPSIZE_KEYGEN(LOGN));
  const int rc = falcon_keygen_make(&rng, LOGN, sk, FALCON_PRIVKEY_SIZE(LOGN), pk, FALCON_PUBKEY_SIZE(LOGN),
                                    tmp.data(), tmp.size());
  return rc == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

template <unsigned LOGN>
pqcfuzz_status FalconKeygenSeededT(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len) {
  if (pk == nullptr || sk == nullptr || seed == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  shake256_context rng;
  falcon_internal::SeedRngFromBytes(&rng, seed, seed_len);
  std::vector<uint8_t> tmp(FALCON_TMPSIZE_KEYGEN(LOGN));
  const int rc = falcon_keygen_make(&rng, LOGN, sk, FALCON_PRIVKEY_SIZE(LOGN), pk, FALCON_PUBKEY_SIZE(LOGN),
                                    tmp.data(), tmp.size());
  return rc == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

template <unsigned LOGN, int SIGTYPE>
pqcfuzz_status FalconSignT(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len) {
  (void)ctx;
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  if (sig == nullptr || sig_len == nullptr || sk == nullptr || (msg == nullptr && msg_len != 0)) {
    return PQCFUZZ_INVALID_INPUT;
  }
  uint8_t seed[falcon_internal::kPlatformSeedBytes];
  falcon_internal::FillSeedFromTapeOrSystem(seed);
  shake256_context rng;
  falcon_internal::SeedRngFromBytes(&rng, seed, sizeof seed);
  std::vector<uint8_t> tmp(FALCON_TMPSIZE_SIGNDYN(LOGN));
  const int rc = falcon_sign_dyn(&rng, sig, sig_len, SIGTYPE, sk, FALCON_PRIVKEY_SIZE(LOGN), msg, msg_len,
                                 tmp.data(), tmp.size());
  return rc == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

template <unsigned LOGN, int SIGTYPE>
pqcfuzz_status FalconSignSeededT(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len,
    const uint8_t *seed,
    size_t seed_len) {
  (void)ctx;
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  if (sig == nullptr || sig_len == nullptr || sk == nullptr || seed == nullptr ||
      (msg == nullptr && msg_len != 0)) {
    return PQCFUZZ_INVALID_INPUT;
  }
  shake256_context rng;
  falcon_internal::SeedRngFromBytes(&rng, seed, seed_len);
  std::vector<uint8_t> tmp(FALCON_TMPSIZE_SIGNDYN(LOGN));
  const int rc = falcon_sign_dyn(&rng, sig, sig_len, SIGTYPE, sk, FALCON_PRIVKEY_SIZE(LOGN), msg, msg_len,
                                 tmp.data(), tmp.size());
  return rc == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

template <unsigned LOGN, int SIGTYPE>
pqcfuzz_status FalconVerifyT(
    const uint8_t *sig,
    size_t sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *pk,
    const uint8_t *ctx,
    size_t ctx_len) {
  (void)ctx;
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  if (sig == nullptr || pk == nullptr || (msg == nullptr && msg_len != 0) || sig_len < 41) {
    return PQCFUZZ_REJECT;
  }
  int effective_type = SIGTYPE;
  if (SIGTYPE == FALCON_SIG_COMPRESSED) {
    // The pinned reference compressed verifier accepts both the exact
    // compressed length and the full zero-padded form only through header
    // inference (sig_type = 0).  The header is pre-checked so a CT signature
    // is not silently accepted by a compressed profile.
    if ((sig[0] & 0xF0) != 0x30 || (sig[0] & 0x0F) != static_cast<int>(LOGN)) {
      return PQCFUZZ_REJECT;
    }
    effective_type = 0;
  }
  std::vector<uint8_t> tmp(FALCON_TMPSIZE_VERIFY(LOGN));
  const int rc = falcon_verify(sig, sig_len, effective_type, pk, FALCON_PUBKEY_SIZE(LOGN), msg, msg_len, tmp.data(),
                               tmp.size());
  return rc == 0 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
}

}  // namespace pqcfuzz

#endif  // PQCFUZZ_HAVE_FALCON

#endif  // PQCFUZZ_ADAPTERS_FALCON_ADAPTER_IMPL_H

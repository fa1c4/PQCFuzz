#include "adapters/cross/cross_adapter.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

#include "adapters/rng_control.h"

#ifdef PQCFUZZ_HAVE_CROSS
extern "C" {
#include "api.h"
#include "csprng_hash.h"
}
#endif

#ifndef PQCFUZZ_CROSS_ALGORITHM
#define PQCFUZZ_CROSS_ALGORITHM "CROSS-RSDP-1-FAST"
#endif

#ifndef PQCFUZZ_CROSS_IMPLEMENTATION_ID
#define PQCFUZZ_CROSS_IMPLEMENTATION_ID "cross_reference"
#endif

namespace {

#ifdef PQCFUZZ_HAVE_CROSS

// The KAT tooling seeds platform_csprng_state with 48 bytes of entropy and the
// CSPRNG domain-separation constant (PQCgenKAT_sign.c).  Deterministic tapes
// reuse the same path so a fixed tape reproduces signatures exactly.
constexpr size_t kPlatformSeedBytes = 48;

pqcfuzz_status SeedPlatformFromSeed(const uint8_t *seed, size_t seed_len) {
  if (seed == nullptr || seed_len == 0) {
    return PQCFUZZ_INVALID_INPUT;
  }
  csprng_initialize(&platform_csprng_state, seed, static_cast<uint32_t>(seed_len), CSPRNG_DOMAIN_SEP_CONST);
  return PQCFUZZ_OK;
}

pqcfuzz_status SeedPlatformFromTapeOrEntropy() {
  uint8_t seed[kPlatformSeedBytes];
  if (pqcfuzz::pqcfuzz_rng_is_active()) {
    if (!pqcfuzz_rng_fill_bytes(seed, sizeof(seed))) {
      // The void RNG contract cannot report failure; mirror the liboqs hook by
      // suppressing fallback entropy so pqcfuzz_rng_failure_observed() stays
      // meaningful and the injected failure is observable.
      std::memset(seed, 0, sizeof(seed));
    }
    return SeedPlatformFromSeed(seed, sizeof(seed));
  }
  std::random_device entropy;
  for (size_t i = 0; i < sizeof(seed); i += sizeof(unsigned int)) {
    const unsigned int value = entropy();
    const size_t remaining = sizeof(seed) - i;
    const size_t chunk = remaining < sizeof(unsigned int) ? remaining : sizeof(unsigned int);
    std::memcpy(seed + i, &value, chunk);
  }
  return SeedPlatformFromSeed(seed, sizeof(seed));
}

pqcfuzz_status CrossKeygen(uint8_t *pk, uint8_t *sk) {
  if (pk == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  const pqcfuzz_status seeded = SeedPlatformFromTapeOrEntropy();
  if (seeded != PQCFUZZ_OK) {
    return seeded;
  }
  CROSS_keygen(reinterpret_cast<sk_t *>(sk), reinterpret_cast<pk_t *>(pk));
  return PQCFUZZ_OK;
}

pqcfuzz_status CrossSign(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len) {
  if (sig == nullptr || sig_len == nullptr || sk == nullptr || (msg == nullptr && msg_len != 0)) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  if (*sig_len < sizeof(CROSS_sig_t)) {
    return PQCFUZZ_INVALID_INPUT;
  }
  const pqcfuzz_status seeded = SeedPlatformFromTapeOrEntropy();
  if (seeded != PQCFUZZ_OK) {
    return seeded;
  }
  CROSS_sign(reinterpret_cast<const sk_t *>(sk), reinterpret_cast<const char *>(msg),
             static_cast<uint64_t>(msg_len), reinterpret_cast<CROSS_sig_t *>(sig));
  *sig_len = sizeof(CROSS_sig_t);
  return PQCFUZZ_OK;
}

pqcfuzz_status CrossVerify(
    const uint8_t *sig,
    size_t sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *pk,
    const uint8_t *ctx,
    size_t ctx_len) {
  if (sig == nullptr || pk == nullptr || (msg == nullptr && msg_len != 0)) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  if (sig_len != sizeof(CROSS_sig_t)) {
    return PQCFUZZ_REJECT;
  }
  const int ok = CROSS_verify(reinterpret_cast<const pk_t *>(pk), reinterpret_cast<const char *>(msg),
                              static_cast<uint64_t>(msg_len), reinterpret_cast<const CROSS_sig_t *>(sig));
  return ok == 1 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
}

pqcfuzz_status CrossKeygenSeeded(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len) {
  if (pk == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  const pqcfuzz_status seeded = SeedPlatformFromSeed(seed, seed_len);
  if (seeded != PQCFUZZ_OK) {
    return seeded;
  }
  CROSS_keygen(reinterpret_cast<sk_t *>(sk), reinterpret_cast<pk_t *>(pk));
  return PQCFUZZ_OK;
}

pqcfuzz_status CrossSignSeeded(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len,
    const uint8_t *seed,
    size_t seed_len) {
  if (sig == nullptr || sig_len == nullptr || sk == nullptr || (msg == nullptr && msg_len != 0)) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  if (*sig_len < sizeof(CROSS_sig_t)) {
    return PQCFUZZ_INVALID_INPUT;
  }
  const pqcfuzz_status seeded = SeedPlatformFromSeed(seed, seed_len);
  if (seeded != PQCFUZZ_OK) {
    return seeded;
  }
  CROSS_sign(reinterpret_cast<const sk_t *>(sk), reinterpret_cast<const char *>(msg),
             static_cast<uint64_t>(msg_len), reinterpret_cast<CROSS_sig_t *>(sig));
  *sig_len = sizeof(CROSS_sig_t);
  return PQCFUZZ_OK;
}

const pqcfuzz_sig_adapter kCrossAdapter = {
    "cross",
    PQCFUZZ_CROSS_IMPLEMENTATION_ID,
    PQCFUZZ_CROSS_ALGORITHM,
    sizeof(pk_t),
    sizeof(sk_t),
    sizeof(CROSS_sig_t),
    0,  // supports_context
    1,  // supports_seeded_sign
    0,  // supports_deterministic_sign
    CrossKeygen,
    CrossSign,
    CrossVerify,
    CrossSignSeeded,
    1,  // verify_checks_length
    0,  // sign_accepts_extended_context
    0,  // verify_accepts_extended_context
    "nist-round2-submission-2.0",
    CrossKeygenSeeded,
};

#endif  // PQCFUZZ_HAVE_CROSS

}  // namespace

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_cross_sig_adapter(const char *implementation_id) {
#ifdef PQCFUZZ_HAVE_CROSS
  if (implementation_id != nullptr && std::strcmp(implementation_id, PQCFUZZ_CROSS_IMPLEMENTATION_ID) == 0) {
    return &kCrossAdapter;
  }
#else
  (void)implementation_id;
#endif
  return nullptr;
}

extern "C" int pqcfuzz_cross_seed_platform_rng(const uint8_t *seed, size_t seed_len) {
#ifdef PQCFUZZ_HAVE_CROSS
  return SeedPlatformFromSeed(seed, seed_len) == PQCFUZZ_OK ? 0 : 1;
#else
  (void)seed;
  (void)seed_len;
  return 1;
#endif
}

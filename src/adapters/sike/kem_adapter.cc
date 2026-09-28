#include "adapters/sike/kem_adapter.h"

#ifdef PQCFUZZ_HAVE_SIKE

#include <cstring>
#include <vector>

#include "adapters/rng_control.h"
#include "adapters/status.h"

// The pinned PQCrypto-SIDH parameter translation unit defines the suffixed
// entry points; the build selects them with the macros below.  The API header
// supplies CRYPTO_* lengths for the selected parameter set.
#ifndef PQCFUZZ_SIKE_API_HEADER
#define PQCFUZZ_SIKE_API_HEADER "P434_api.h"
#endif
extern "C" {
#include PQCFUZZ_SIKE_API_HEADER
}

#ifndef PQCFUZZ_SIKE_KEYPAIR
#define PQCFUZZ_SIKE_KEYPAIR crypto_kem_keypair
#endif
#ifndef PQCFUZZ_SIKE_ENC
#define PQCFUZZ_SIKE_ENC crypto_kem_enc
#endif
#ifndef PQCFUZZ_SIKE_DEC
#define PQCFUZZ_SIKE_DEC crypto_kem_dec
#endif

#ifndef PQCFUZZ_SIKE_ALGORITHM
#define PQCFUZZ_SIKE_ALGORITHM "SIKE"
#endif

#ifndef PQCFUZZ_SIKE_IMPLEMENTATION_ID
#define PQCFUZZ_SIKE_IMPLEMENTATION_ID "sike_reference"
#endif

// The generic and AMD64 builds of the same parameter set are linked into one
// binary with renamed optimized symbols; each translation unit exports its own
// getter and the reference getter delegates to the optimized one when present.
#ifndef PQCFUZZ_SIKE_ADAPTER_GETTER
#define PQCFUZZ_SIKE_ADAPTER_GETTER pqcfuzz_get_sike_kem_adapter
#endif

namespace {

// Worst-case tape consumption of one keygen call (s prefix + sk3 scalar) is
// bounded by MSG_BYTES + SECRETKEY_B_BYTES; 96 bytes covers every parameter
// set.  A non-repeating tape prevents accidental reuse of an early block.
constexpr size_t kDerandCoins = 96;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  if (pk == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return PQCFUZZ_SIKE_KEYPAIR(pk, sk) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
  if (ct == nullptr || ss == nullptr || pk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return PQCFUZZ_SIKE_ENC(ct, ss, pk) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  if (ss == nullptr || ct == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  // The pinned wrapper always returns 0; the semantic outcome is the selected
  // secret, which the fallback oracles compare against the exact H formula.
  return PQCFUZZ_SIKE_DEC(ss, ct, sk) == 0 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
}

pqcfuzz_status KeygenDerand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
  if (pk == nullptr || sk == nullptr || coins == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  pqcfuzz::ScopedRngOverride tape({coins, kDerandCoins, false});
  return PQCFUZZ_SIKE_KEYPAIR(pk, sk) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status EncapsDerand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {
  if (ct == nullptr || ss == nullptr || pk == nullptr || coins == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  pqcfuzz::ScopedRngOverride tape({coins, kDerandCoins, false});
  return PQCFUZZ_SIKE_ENC(ct, ss, pk) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

const pqcfuzz_kem_adapter kAdapter = {
    "sike",
    PQCFUZZ_SIKE_IMPLEMENTATION_ID,
    PQCFUZZ_SIKE_ALGORITHM,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
    CRYPTO_CIPHERTEXTBYTES,
    CRYPTO_BYTES,
    Keygen,
    Encaps,
    Decaps,
    KeygenDerand,
    EncapsDerand,
    "microsoft/PQCrypto-SIDH@98a028a",
};

}  // namespace

#if defined(PQCFUZZ_SIKE_DELEGATE_OPTIMIZED)
extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_sike_optimized_kem_adapter(const char *implementation_id)
    __attribute__((weak));
#endif

extern "C" const pqcfuzz_kem_adapter *PQCFUZZ_SIKE_ADAPTER_GETTER(const char *implementation_id) {
  if (implementation_id == nullptr) {
    return nullptr;
  }
  if (std::strcmp(kAdapter.implementation_id, implementation_id) == 0) {
    return &kAdapter;
  }
#if defined(PQCFUZZ_SIKE_DELEGATE_OPTIMIZED)
  if (pqcfuzz_get_sike_optimized_kem_adapter != nullptr) {
    const pqcfuzz_kem_adapter *optimized = pqcfuzz_get_sike_optimized_kem_adapter(implementation_id);
    if (optimized != nullptr) {
      return optimized;
    }
  }
#endif
  return nullptr;
}

#else

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_sike_kem_adapter(const char *implementation_id) {
  (void)implementation_id;
  return nullptr;
}

#endif  // PQCFUZZ_HAVE_SIKE

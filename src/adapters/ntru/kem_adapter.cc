#include "adapters/ntru/kem_adapter.h"

#ifdef PQCFUZZ_HAVE_NTRU

#include <cstring>
#include <vector>

#include "adapters/rng_control.h"
#include "adapters/status.h"

extern "C" {
#include "api.h"
#include "params.h"
}

#ifndef PQCFUZZ_NTRU_ALGORITHM
#define PQCFUZZ_NTRU_ALGORITHM "NTRU"
#endif

#ifndef PQCFUZZ_NTRU_IMPLEMENTATION_ID
#define PQCFUZZ_NTRU_IMPLEMENTATION_ID "ntru_reference"
#endif

// Second implementations of the same upstream (reference vs optimized) are
// linked into one binary with distinct symbols; each translation unit exports
// its own getter and the reference getter delegates to the optimized one when
// that weak symbol is present.
#ifndef PQCFUZZ_NTRU_ADAPTER_GETTER
#define PQCFUZZ_NTRU_ADAPTER_GETTER pqcfuzz_get_ntru_kem_adapter
#endif

namespace {

constexpr size_t kDerandCoins = 48;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  if (pk == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return crypto_kem_keypair(pk, sk) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
  if (ct == nullptr || ss == nullptr || pk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return crypto_kem_enc(ct, ss, pk) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  if (ss == nullptr || ct == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return crypto_kem_dec(ss, ct, sk) == 0 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
}

pqcfuzz_status KeygenDerand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
  if (pk == nullptr || sk == nullptr || coins == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  pqcfuzz::ScopedRngOverride tape({coins, kDerandCoins, false});
  return crypto_kem_keypair(pk, sk) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status EncapsDerand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {
  if (ct == nullptr || ss == nullptr || pk == nullptr || coins == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  pqcfuzz::ScopedRngOverride tape({coins, kDerandCoins, false});
  return crypto_kem_enc(ct, ss, pk) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

const pqcfuzz_kem_adapter kAdapter = {
    "ntru",
    PQCFUZZ_NTRU_IMPLEMENTATION_ID,
    PQCFUZZ_NTRU_ALGORITHM,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
    CRYPTO_CIPHERTEXTBYTES,
    CRYPTO_BYTES,
    Keygen,
    Encaps,
    Decaps,
    KeygenDerand,
    EncapsDerand,
    "NIST-PQ-Submission-NTRU-20201016",
};

}  // namespace

#if defined(PQCFUZZ_NTRU_DELEGATE_OPTIMIZED)
extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_ntru_optimized_adapter(const char *implementation_id)
    __attribute__((weak));
#endif

extern "C" const pqcfuzz_kem_adapter *PQCFUZZ_NTRU_ADAPTER_GETTER(const char *implementation_id) {
  if (implementation_id == nullptr) {
    return nullptr;
  }
  if (std::strcmp(kAdapter.implementation_id, implementation_id) == 0) {
    return &kAdapter;
  }
#if defined(PQCFUZZ_NTRU_DELEGATE_OPTIMIZED)
  if (pqcfuzz_get_ntru_optimized_adapter != nullptr) {
    const pqcfuzz_kem_adapter *optimized = pqcfuzz_get_ntru_optimized_adapter(implementation_id);
    if (optimized != nullptr) {
      return optimized;
    }
  }
#endif
  return nullptr;
}

#else

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_ntru_kem_adapter(const char *implementation_id) {
  (void)implementation_id;
  return nullptr;
}

#endif  // PQCFUZZ_HAVE_NTRU

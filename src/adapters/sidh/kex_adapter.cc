#include "adapters/sidh/kex_adapter.h"

#ifdef PQCFUZZ_HAVE_SIDH

#include <cstring>

#include "adapters/rng_control.h"
#include "adapters/status.h"

#ifndef PQCFUZZ_SIDH_API_HEADER
#define PQCFUZZ_SIDH_API_HEADER "P434_api.h"
#endif
extern "C" {
#include PQCFUZZ_SIDH_API_HEADER
}

#ifndef PQCFUZZ_SIDH_RANDOM_MOD_A
#define PQCFUZZ_SIDH_RANDOM_MOD_A random_mod_order_A
#endif
#ifndef PQCFUZZ_SIDH_RANDOM_MOD_B
#define PQCFUZZ_SIDH_RANDOM_MOD_B random_mod_order_B
#endif
#ifndef PQCFUZZ_SIDH_KEYGEN_A
#define PQCFUZZ_SIDH_KEYGEN_A EphemeralKeyGeneration_A
#endif
#ifndef PQCFUZZ_SIDH_KEYGEN_B
#define PQCFUZZ_SIDH_KEYGEN_B EphemeralKeyGeneration_B
#endif
#ifndef PQCFUZZ_SIDH_DERIVE_A
#define PQCFUZZ_SIDH_DERIVE_A EphemeralSecretAgreement_A
#endif
#ifndef PQCFUZZ_SIDH_DERIVE_B
#define PQCFUZZ_SIDH_DERIVE_B EphemeralSecretAgreement_B
#endif

#ifndef PQCFUZZ_SIDH_ALGORITHM
#define PQCFUZZ_SIDH_ALGORITHM "SIDH"
#endif
#ifndef PQCFUZZ_SIDH_IMPLEMENTATION_ID
#define PQCFUZZ_SIDH_IMPLEMENTATION_ID "sidh_reference"
#endif

namespace {

constexpr size_t kDerandCoins = 96;

pqcfuzz_status KeygenA(uint8_t *pk_a, uint8_t *sk_a) {
  if (pk_a == nullptr || sk_a == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (PQCFUZZ_SIDH_RANDOM_MOD_A(sk_a) != 0) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return PQCFUZZ_SIDH_KEYGEN_A(sk_a, pk_a) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status KeygenB(uint8_t *pk_b, uint8_t *sk_b) {
  if (pk_b == nullptr || sk_b == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (PQCFUZZ_SIDH_RANDOM_MOD_B(sk_b) != 0) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return PQCFUZZ_SIDH_KEYGEN_B(sk_b, pk_b) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

// derive_a(out, peer_pk_b, own_sk_a)
pqcfuzz_status DeriveA(uint8_t *shared, const uint8_t *peer_pk_b, const uint8_t *own_sk_a) {
  if (shared == nullptr || peer_pk_b == nullptr || own_sk_a == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return PQCFUZZ_SIDH_DERIVE_A(own_sk_a, peer_pk_b, shared) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

// derive_b(out, peer_pk_a, own_sk_b)
pqcfuzz_status DeriveB(uint8_t *shared, const uint8_t *peer_pk_a, const uint8_t *own_sk_b) {
  if (shared == nullptr || peer_pk_a == nullptr || own_sk_b == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return PQCFUZZ_SIDH_DERIVE_B(own_sk_b, peer_pk_a, shared) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status KeygenAScalar(uint8_t *pk_a, const uint8_t *scalar_a) {
  if (pk_a == nullptr || scalar_a == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return PQCFUZZ_SIDH_KEYGEN_A(scalar_a, pk_a) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status KeygenBScalar(uint8_t *pk_b, const uint8_t *scalar_b) {
  if (pk_b == nullptr || scalar_b == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return PQCFUZZ_SIDH_KEYGEN_B(scalar_b, pk_b) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

const pqcfuzz_kex_adapter kAdapter = {
    "sidh",
    PQCFUZZ_SIDH_IMPLEMENTATION_ID,
    PQCFUZZ_SIDH_ALGORITHM,
    SIDH_PUBLICKEYBYTES,
    SIDH_SECRETKEYBYTES_A,
    SIDH_SECRETKEYBYTES_B,
    SIDH_BYTES,
    KeygenA,
    KeygenB,
    DeriveA,
    DeriveB,
    KeygenAScalar,
    KeygenBScalar,
    SIDH_SECRETKEYBYTES_A,
    SIDH_SECRETKEYBYTES_B,
    "microsoft/PQCrypto-SIDH@98a028a",
};

}  // namespace

extern "C" const pqcfuzz_kex_adapter *pqcfuzz_get_sidh_kex_adapter(const char *implementation_id) {
  if (implementation_id == nullptr) {
    return nullptr;
  }
  if (std::strcmp(kAdapter.implementation_id, implementation_id) == 0) {
    return &kAdapter;
  }
  return nullptr;
}

#else

extern "C" const pqcfuzz_kex_adapter *pqcfuzz_get_sidh_kex_adapter(const char *implementation_id) {
  (void)implementation_id;
  return nullptr;
}

#endif  // PQCFUZZ_HAVE_SIDH

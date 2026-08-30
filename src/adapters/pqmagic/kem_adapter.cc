#include "adapters/pqmagic/kem_adapter.h"

#include <cstring>

#ifdef PQCFUZZ_HAVE_PQMAGIC
extern "C" {
// SM3 (default) build symbols.
int pqmagic_aigis_enc_1_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_aigis_enc_1_std_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqmagic_aigis_enc_1_std_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqmagic_aigis_enc_2_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_aigis_enc_2_std_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqmagic_aigis_enc_2_std_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqmagic_aigis_enc_3_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_aigis_enc_3_std_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqmagic_aigis_enc_3_std_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqmagic_aigis_enc_4_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_aigis_enc_4_std_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqmagic_aigis_enc_4_std_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
// SHAKE build symbols (renamed by scripts/rename_pqmagic_symbols.py).
int pqmagic_shake_pqmagic_aigis_enc_1_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_enc_1_std_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqmagic_shake_pqmagic_aigis_enc_1_std_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_enc_2_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_enc_2_std_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqmagic_shake_pqmagic_aigis_enc_2_std_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_enc_3_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_enc_3_std_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqmagic_shake_pqmagic_aigis_enc_3_std_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_enc_4_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_enc_4_std_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqmagic_shake_pqmagic_aigis_enc_4_std_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
}
#endif

namespace {

pqcfuzz_status UnsupportedKeygen(uint8_t *, uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}

pqcfuzz_status UnsupportedEncaps(uint8_t *, uint8_t *, const uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}

pqcfuzz_status UnsupportedDecaps(uint8_t *, const uint8_t *, const uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}

#ifdef PQCFUZZ_HAVE_PQMAGIC
#define PQMAGIC_KEM_BINDINGS(MODE)                                             \
  pqcfuzz_status Sm3Enc##MODE##Keygen(uint8_t *pk, uint8_t *sk) {             \
    return pqcfuzz_normalize_return_code(pqmagic_aigis_enc_##MODE##_std_keypair(pk, sk)); \
  }                                                                            \
  pqcfuzz_status Sm3Enc##MODE##Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) { \
    return pqcfuzz_normalize_return_code(pqmagic_aigis_enc_##MODE##_std_enc(ct, ss, pk)); \
  }                                                                            \
  pqcfuzz_status Sm3Enc##MODE##Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) { \
    return pqcfuzz_normalize_return_code(pqmagic_aigis_enc_##MODE##_std_dec(ss, ct, sk)); \
  }                                                                            \
  pqcfuzz_status ShakeEnc##MODE##Keygen(uint8_t *pk, uint8_t *sk) {           \
    return pqcfuzz_normalize_return_code(pqmagic_shake_pqmagic_aigis_enc_##MODE##_std_keypair(pk, sk)); \
  }                                                                            \
  pqcfuzz_status ShakeEnc##MODE##Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) { \
    return pqcfuzz_normalize_return_code(pqmagic_shake_pqmagic_aigis_enc_##MODE##_std_enc(ct, ss, pk)); \
  }                                                                            \
  pqcfuzz_status ShakeEnc##MODE##Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) { \
    return pqcfuzz_normalize_return_code(pqmagic_shake_pqmagic_aigis_enc_##MODE##_std_dec(ss, ct, sk)); \
  }
PQMAGIC_KEM_BINDINGS(1)
PQMAGIC_KEM_BINDINGS(2)
PQMAGIC_KEM_BINDINGS(3)
PQMAGIC_KEM_BINDINGS(4)
#undef PQMAGIC_KEM_BINDINGS
#else
#define Sm3Enc1Keygen UnsupportedKeygen
#define Sm3Enc1Encaps UnsupportedEncaps
#define Sm3Enc1Decaps UnsupportedDecaps
#define Sm3Enc2Keygen UnsupportedKeygen
#define Sm3Enc2Encaps UnsupportedEncaps
#define Sm3Enc2Decaps UnsupportedDecaps
#define Sm3Enc3Keygen UnsupportedKeygen
#define Sm3Enc3Encaps UnsupportedEncaps
#define Sm3Enc3Decaps UnsupportedDecaps
#define Sm3Enc4Keygen UnsupportedKeygen
#define Sm3Enc4Encaps UnsupportedEncaps
#define Sm3Enc4Decaps UnsupportedDecaps
#define ShakeEnc1Keygen UnsupportedKeygen
#define ShakeEnc1Encaps UnsupportedEncaps
#define ShakeEnc1Decaps UnsupportedDecaps
#define ShakeEnc2Keygen UnsupportedKeygen
#define ShakeEnc2Encaps UnsupportedEncaps
#define ShakeEnc2Decaps UnsupportedDecaps
#define ShakeEnc3Keygen UnsupportedKeygen
#define ShakeEnc3Encaps UnsupportedEncaps
#define ShakeEnc3Decaps UnsupportedDecaps
#define ShakeEnc4Keygen UnsupportedKeygen
#define ShakeEnc4Encaps UnsupportedEncaps
#define ShakeEnc4Decaps UnsupportedDecaps
#endif

#define PQMAGIC_KEM_ADAPTER(MODE, PROJECT_ID, PK, SK, CT, SS, HASH_PREFIX, HASH_NAME) \
  {                                                                        \
      PROJECT_ID, "pqmagic_aigis_enc_" #MODE "_std_" HASH_NAME,             \
      "AIGIS-ENC-" #MODE, PK, SK, CT, SS,                                  \
      HASH_PREFIX##Enc##MODE##Keygen, HASH_PREFIX##Enc##MODE##Encaps,      \
      HASH_PREFIX##Enc##MODE##Decaps,                                      \
  }

const pqcfuzz_kem_adapter kSm3Enc1 = PQMAGIC_KEM_ADAPTER(1, "pqmagic", 672, 1568, 736, 32, Sm3, "sm3");
const pqcfuzz_kem_adapter kSm3Enc2 = PQMAGIC_KEM_ADAPTER(2, "pqmagic", 896, 2208, 992, 32, Sm3, "sm3");
const pqcfuzz_kem_adapter kSm3Enc3 = PQMAGIC_KEM_ADAPTER(3, "pqmagic", 992, 2304, 1056, 32, Sm3, "sm3");
const pqcfuzz_kem_adapter kSm3Enc4 = PQMAGIC_KEM_ADAPTER(4, "pqmagic", 1440, 3168, 1568, 32, Sm3, "sm3");
const pqcfuzz_kem_adapter kShakeEnc1 = PQMAGIC_KEM_ADAPTER(1, "pqmagic", 672, 1568, 736, 32, Shake, "shake");
const pqcfuzz_kem_adapter kShakeEnc2 = PQMAGIC_KEM_ADAPTER(2, "pqmagic", 896, 2208, 992, 32, Shake, "shake");
const pqcfuzz_kem_adapter kShakeEnc3 = PQMAGIC_KEM_ADAPTER(3, "pqmagic", 992, 2304, 1056, 32, Shake, "shake");
const pqcfuzz_kem_adapter kShakeEnc4 = PQMAGIC_KEM_ADAPTER(4, "pqmagic", 1440, 3168, 1568, 32, Shake, "shake");

#undef PQMAGIC_KEM_ADAPTER

}  // namespace

const pqcfuzz_kem_adapter *pqcfuzz_get_pqmagic_adapter(const char *implementation_id) {
  if (implementation_id == nullptr) {
    return nullptr;
  }
  if (std::strcmp(implementation_id, kSm3Enc1.implementation_id) == 0) {
    return &kSm3Enc1;
  }
  if (std::strcmp(implementation_id, kSm3Enc2.implementation_id) == 0) {
    return &kSm3Enc2;
  }
  if (std::strcmp(implementation_id, kSm3Enc3.implementation_id) == 0) {
    return &kSm3Enc3;
  }
  if (std::strcmp(implementation_id, kSm3Enc4.implementation_id) == 0) {
    return &kSm3Enc4;
  }
  if (std::strcmp(implementation_id, kShakeEnc1.implementation_id) == 0) {
    return &kShakeEnc1;
  }
  if (std::strcmp(implementation_id, kShakeEnc2.implementation_id) == 0) {
    return &kShakeEnc2;
  }
  if (std::strcmp(implementation_id, kShakeEnc3.implementation_id) == 0) {
    return &kShakeEnc3;
  }
  if (std::strcmp(implementation_id, kShakeEnc4.implementation_id) == 0) {
    return &kShakeEnc4;
  }
  return nullptr;
}

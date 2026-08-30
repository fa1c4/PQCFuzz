#include "adapters/pqmagic/sig_adapter.h"

#include <cstring>

#ifdef PQCFUZZ_HAVE_PQMAGIC
extern "C" {
// SM3 (default) build symbols.
int pqmagic_aigis_sig1_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_aigis_sig1_std_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctx_len, const uint8_t *sk);
int pqmagic_aigis_sig1_std_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctx_len, const uint8_t *pk);
int pqmagic_aigis_sig1_std(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
                           const uint8_t *ctx, size_t ctx_len, const uint8_t *sk);
int pqmagic_aigis_sig2_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_aigis_sig2_std_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctx_len, const uint8_t *sk);
int pqmagic_aigis_sig2_std_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctx_len, const uint8_t *pk);
int pqmagic_aigis_sig2_std(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
                           const uint8_t *ctx, size_t ctx_len, const uint8_t *sk);
int pqmagic_aigis_sig3_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_aigis_sig3_std_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctx_len, const uint8_t *sk);
int pqmagic_aigis_sig3_std_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctx_len, const uint8_t *pk);
int pqmagic_aigis_sig3_std(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
                           const uint8_t *ctx, size_t ctx_len, const uint8_t *sk);
// SHAKE build symbols (renamed by scripts/rename_pqmagic_symbols.py).
int pqmagic_shake_pqmagic_aigis_sig1_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_sig1_std_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                                   const uint8_t *ctx, size_t ctx_len, const uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_sig1_std_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                                const uint8_t *ctx, size_t ctx_len, const uint8_t *pk);
int pqmagic_shake_pqmagic_aigis_sig1_std(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctx_len, const uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_sig2_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_sig2_std_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                                   const uint8_t *ctx, size_t ctx_len, const uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_sig2_std_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                                const uint8_t *ctx, size_t ctx_len, const uint8_t *pk);
int pqmagic_shake_pqmagic_aigis_sig2_std(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctx_len, const uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_sig3_std_keypair(uint8_t *pk, uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_sig3_std_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                                   const uint8_t *ctx, size_t ctx_len, const uint8_t *sk);
int pqmagic_shake_pqmagic_aigis_sig3_std_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                                const uint8_t *ctx, size_t ctx_len, const uint8_t *pk);
int pqmagic_shake_pqmagic_aigis_sig3_std(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctx_len, const uint8_t *sk);
}
#endif

namespace {

pqcfuzz_status UnsupportedKeygen(uint8_t *, uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}

pqcfuzz_status UnsupportedSign(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_API_UNSUPPORTED;
}

pqcfuzz_status UnsupportedVerify(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_API_UNSUPPORTED;
}

#ifdef PQCFUZZ_HAVE_PQMAGIC
#define PQMAGIC_SIG_BINDINGS(MODE)                                             \
  pqcfuzz_status Sm3Sig##MODE##Keygen(uint8_t *pk, uint8_t *sk) {             \
    return pqcfuzz_normalize_return_code(pqmagic_aigis_sig##MODE##_std_keypair(pk, sk)); \
  }                                                                            \
  pqcfuzz_status Sm3Sig##MODE##Sign(uint8_t *sig, size_t *sig_len,            \
      const uint8_t *msg, size_t msg_len, const uint8_t *sk,                  \
      const uint8_t *ctx, size_t ctx_len) {                                   \
    return pqcfuzz_normalize_return_code(pqmagic_aigis_sig##MODE##_std_signature( \
        sig, sig_len, msg, msg_len, ctx, ctx_len, sk));                       \
  }                                                                            \
  pqcfuzz_status Sm3Sig##MODE##Verify(const uint8_t *sig, size_t sig_len,     \
      const uint8_t *msg, size_t msg_len, const uint8_t *pk,                  \
      const uint8_t *ctx, size_t ctx_len) {                                   \
    return pqcfuzz_normalize_return_code(pqmagic_aigis_sig##MODE##_std_verify( \
        sig, sig_len, msg, msg_len, ctx, ctx_len, pk));                       \
  }                                                                            \
  pqcfuzz_status ShakeSig##MODE##Keygen(uint8_t *pk, uint8_t *sk) {           \
    return pqcfuzz_normalize_return_code(pqmagic_shake_pqmagic_aigis_sig##MODE##_std_keypair(pk, sk)); \
  }                                                                            \
  pqcfuzz_status ShakeSig##MODE##Sign(uint8_t *sig, size_t *sig_len,          \
      const uint8_t *msg, size_t msg_len, const uint8_t *sk,                  \
      const uint8_t *ctx, size_t ctx_len) {                                   \
    return pqcfuzz_normalize_return_code(pqmagic_shake_pqmagic_aigis_sig##MODE##_std_signature( \
        sig, sig_len, msg, msg_len, ctx, ctx_len, sk));                       \
  }                                                                            \
  pqcfuzz_status ShakeSig##MODE##Verify(const uint8_t *sig, size_t sig_len,   \
      const uint8_t *msg, size_t msg_len, const uint8_t *pk,                  \
      const uint8_t *ctx, size_t ctx_len) {                                   \
    return pqcfuzz_normalize_return_code(pqmagic_shake_pqmagic_aigis_sig##MODE##_std_verify( \
        sig, sig_len, msg, msg_len, ctx, ctx_len, pk));                       \
  }
PQMAGIC_SIG_BINDINGS(1)
PQMAGIC_SIG_BINDINGS(2)
PQMAGIC_SIG_BINDINGS(3)
#undef PQMAGIC_SIG_BINDINGS
#else
#define Sm3Sig1Keygen UnsupportedKeygen
#define Sm3Sig1Sign UnsupportedSign
#define Sm3Sig1Verify UnsupportedVerify
#define Sm3Sig2Keygen UnsupportedKeygen
#define Sm3Sig2Sign UnsupportedSign
#define Sm3Sig2Verify UnsupportedVerify
#define Sm3Sig3Keygen UnsupportedKeygen
#define Sm3Sig3Sign UnsupportedSign
#define Sm3Sig3Verify UnsupportedVerify
#define ShakeSig1Keygen UnsupportedKeygen
#define ShakeSig1Sign UnsupportedSign
#define ShakeSig1Verify UnsupportedVerify
#define ShakeSig2Keygen UnsupportedKeygen
#define ShakeSig2Sign UnsupportedSign
#define ShakeSig2Verify UnsupportedVerify
#define ShakeSig3Keygen UnsupportedKeygen
#define ShakeSig3Sign UnsupportedSign
#define ShakeSig3Verify UnsupportedVerify
#endif

#define PQMAGIC_SIG_ADAPTER(MODE, PK, SK, SIG, HASH_PREFIX, HASH_NAME) \
  {                                                                      \
      "pqmagic", "pqmagic_aigis_sig" #MODE "_std_" HASH_NAME,            \
      "AIGIS-SIG-" #MODE, PK, SK, SIG, 1, 0, 1,                          \
      HASH_PREFIX##Sig##MODE##Keygen, HASH_PREFIX##Sig##MODE##Sign,      \
      HASH_PREFIX##Sig##MODE##Verify, nullptr,                           \
  }

const pqcfuzz_sig_adapter kSm3Sig1 = PQMAGIC_SIG_ADAPTER(1, 1056, 2448, 1852, Sm3, "sm3");
const pqcfuzz_sig_adapter kSm3Sig2 = PQMAGIC_SIG_ADAPTER(2, 1312, 3376, 2445, Sm3, "sm3");
const pqcfuzz_sig_adapter kSm3Sig3 = PQMAGIC_SIG_ADAPTER(3, 1568, 3888, 3046, Sm3, "sm3");
const pqcfuzz_sig_adapter kShakeSig1 = PQMAGIC_SIG_ADAPTER(1, 1056, 2448, 1852, Shake, "shake");
const pqcfuzz_sig_adapter kShakeSig2 = PQMAGIC_SIG_ADAPTER(2, 1312, 3376, 2445, Shake, "shake");
const pqcfuzz_sig_adapter kShakeSig3 = PQMAGIC_SIG_ADAPTER(3, 1568, 3888, 3046, Shake, "shake");

#undef PQMAGIC_SIG_ADAPTER

}  // namespace

const pqcfuzz_sig_adapter *pqcfuzz_get_pqmagic_sig_adapter(const char *implementation_id) {
  if (implementation_id == nullptr) {
    return nullptr;
  }
  if (std::strcmp(implementation_id, kSm3Sig1.implementation_id) == 0) {
    return &kSm3Sig1;
  }
  if (std::strcmp(implementation_id, kSm3Sig2.implementation_id) == 0) {
    return &kSm3Sig2;
  }
  if (std::strcmp(implementation_id, kSm3Sig3.implementation_id) == 0) {
    return &kSm3Sig3;
  }
  if (std::strcmp(implementation_id, kShakeSig1.implementation_id) == 0) {
    return &kShakeSig1;
  }
  if (std::strcmp(implementation_id, kShakeSig2.implementation_id) == 0) {
    return &kShakeSig2;
  }
  if (std::strcmp(implementation_id, kShakeSig3.implementation_id) == 0) {
    return &kShakeSig3;
  }
  return nullptr;
}

int pqcfuzz_pqmagic_sig_combined_sign(
    const char *implementation_id,
    uint8_t *sm,
    size_t *smlen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *ctx,
    size_t ctx_len,
    const uint8_t *sk) {
#ifdef PQCFUZZ_HAVE_PQMAGIC
  if (std::strcmp(implementation_id, kSm3Sig1.implementation_id) == 0) {
    return pqmagic_aigis_sig1_std(sm, smlen, m, mlen, ctx, ctx_len, sk);
  }
  if (std::strcmp(implementation_id, kSm3Sig2.implementation_id) == 0) {
    return pqmagic_aigis_sig2_std(sm, smlen, m, mlen, ctx, ctx_len, sk);
  }
  if (std::strcmp(implementation_id, kSm3Sig3.implementation_id) == 0) {
    return pqmagic_aigis_sig3_std(sm, smlen, m, mlen, ctx, ctx_len, sk);
  }
  if (std::strcmp(implementation_id, kShakeSig1.implementation_id) == 0) {
    return pqmagic_shake_pqmagic_aigis_sig1_std(sm, smlen, m, mlen, ctx, ctx_len, sk);
  }
  if (std::strcmp(implementation_id, kShakeSig2.implementation_id) == 0) {
    return pqmagic_shake_pqmagic_aigis_sig2_std(sm, smlen, m, mlen, ctx, ctx_len, sk);
  }
  if (std::strcmp(implementation_id, kShakeSig3.implementation_id) == 0) {
    return pqmagic_shake_pqmagic_aigis_sig3_std(sm, smlen, m, mlen, ctx, ctx_len, sk);
  }
#endif
  return -1;
}

#include "adapters/reference/reference_adapter.h"

#include <cstring>
#include <vector>

#ifdef PQCFUZZ_HAVE_PQCLEAN_REFERENCE
extern "C" {
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                                    const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                                 const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                                    const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                                 const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                                    const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                                 const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
#define PQCFUZZ_DECLARE_SLH(PREFIX)                                                                     \
  int PREFIX##_crypto_sign_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);                 \
  int PREFIX##_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,        \
                                     const uint8_t *sk);                                                \
  int PREFIX##_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,      \
                                  const uint8_t *pk)
PQCFUZZ_DECLARE_SLH(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN);
PQCFUZZ_DECLARE_SLH(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN);
PQCFUZZ_DECLARE_SLH(PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN);
PQCFUZZ_DECLARE_SLH(PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN);
PQCFUZZ_DECLARE_SLH(PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN);
PQCFUZZ_DECLARE_SLH(PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN);
PQCFUZZ_DECLARE_SLH(PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN);
PQCFUZZ_DECLARE_SLH(PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN);
PQCFUZZ_DECLARE_SLH(PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN);
PQCFUZZ_DECLARE_SLH(PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN);
PQCFUZZ_DECLARE_SLH(PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN);
PQCFUZZ_DECLARE_SLH(PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN);
#undef PQCFUZZ_DECLARE_SLH
}
#endif

extern "C" int PQCLEAN_randombytes(uint8_t *out, size_t out_len);

namespace pqcfuzz {
namespace {

constexpr const char *kReferenceVersion = "PQClean/0586a824fc0d49df0b6b6e9179d8d15d06d0974f";

pqcfuzz_status UnsupportedKeygen(uint8_t *, uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}
pqcfuzz_status UnsupportedEncaps(uint8_t *, uint8_t *, const uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}
pqcfuzz_status UnsupportedDecaps(uint8_t *, const uint8_t *, const uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}
pqcfuzz_status UnsupportedKeygenDerand(uint8_t *, uint8_t *, const uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}
pqcfuzz_status UnsupportedEncapsDerand(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}
pqcfuzz_status UnsupportedSigKeygen(uint8_t *, uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}
pqcfuzz_status UnsupportedSign(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_API_UNSUPPORTED;
}
pqcfuzz_status UnsupportedVerify(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_API_UNSUPPORTED;
}
pqcfuzz_status UnsupportedSignSeeded(
    uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t) {
  return PQCFUZZ_API_UNSUPPORTED;
}

#ifdef PQCFUZZ_HAVE_PQCLEAN_REFERENCE
#define PQCFUZZ_REFERENCE_KEM_ADAPTER(NAME, ID, ALG, PK, SK, CT, SS, KEYGEN_DERAND, ENCAPS_DERAND, DECAPS) \
  pqcfuzz_status NAME##KeygenDerand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {                      \
    return pqcfuzz_normalize_return_code(KEYGEN_DERAND(pk, sk, coins));                                    \
  }                                                                                                        \
  pqcfuzz_status NAME##EncapsDerand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {   \
    return pqcfuzz_normalize_return_code(ENCAPS_DERAND(ct, ss, pk, coins));                                \
  }                                                                                                        \
  pqcfuzz_status NAME##Keygen(uint8_t *pk, uint8_t *sk) {                                                   \
    uint8_t coins[64] = {0};                                                                               \
    PQCLEAN_randombytes(coins, sizeof(coins));                                                                     \
    return pqcfuzz_normalize_return_code(KEYGEN_DERAND(pk, sk, coins));                                    \
  }                                                                                                        \
  pqcfuzz_status NAME##Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {                                \
    uint8_t coins[32] = {0};                                                                               \
    PQCLEAN_randombytes(coins, sizeof(coins));                                                                     \
    return pqcfuzz_normalize_return_code(ENCAPS_DERAND(ct, ss, pk, coins));                                \
  }                                                                                                        \
  pqcfuzz_status NAME##Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {                         \
    return pqcfuzz_normalize_return_code(DECAPS(ss, ct, sk));                                              \
  }                                                                                                        \
  const pqcfuzz_kem_adapter k##NAME = {                                                                    \
      "pqclean_reference", ID, ALG, PK, SK, CT, SS, NAME##Keygen, NAME##Encaps, NAME##Decaps,              \
      NAME##KeygenDerand, NAME##EncapsDerand, kReferenceVersion}

  PQCFUZZ_REFERENCE_KEM_ADAPTER(RefMlKem512, "pqclean_ref_mlkem512", "ML-KEM-512", 800, 1632, 768, 32,
                                PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand,
                                PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand,
                                PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec);
  PQCFUZZ_REFERENCE_KEM_ADAPTER(RefMlKem768, "pqclean_ref_mlkem768", "ML-KEM-768", 1184, 2400, 1088, 32,
                                PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand,
                                PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand,
                                PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec);
  PQCFUZZ_REFERENCE_KEM_ADAPTER(RefMlKem1024, "pqclean_ref_mlkem1024", "ML-KEM-1024", 1568, 3168, 1568, 32,
                                PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand,
                                PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand,
                                PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec);
#undef PQCFUZZ_REFERENCE_KEM_ADAPTER

#define PQCFUZZ_REFERENCE_SIG_ADAPTER(NAME, ID, ALG, PK, SK, SIG, KEYPAIR, SIGN_CTX, VERIFY_CTX)     \
  pqcfuzz_status NAME##Keygen(uint8_t *pk, uint8_t *sk) {                                           \
    return pqcfuzz_normalize_return_code(KEYPAIR(pk, sk));                                          \
  }                                                                                                 \
  pqcfuzz_status NAME##Sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,      \
                            const uint8_t *sk, const uint8_t *ctx, size_t ctx_len) {                \
    (void)ctx;                                                                                      \
    return pqcfuzz_normalize_return_code(SIGN_CTX(sig, sig_len, msg, msg_len, ctx, ctx_len, sk));   \
  }                                                                                                 \
  pqcfuzz_status NAME##Verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, \
                              const uint8_t *pk, const uint8_t *ctx, size_t ctx_len) {              \
    (void)ctx;                                                                                      \
    return pqcfuzz_normalize_return_code(VERIFY_CTX(sig, sig_len, msg, msg_len, ctx, ctx_len, pk)); \
  }                                                                                                 \
  const pqcfuzz_sig_adapter k##NAME = {                                                             \
      "pqclean_reference", ID, ALG, PK, SK, SIG, 1, 0, 0, NAME##Keygen, NAME##Sign, NAME##Verify,   \
      UnsupportedSignSeeded, 1, 1, 1, kReferenceVersion}

  PQCFUZZ_REFERENCE_SIG_ADAPTER(RefMlDsa44, "pqclean_ref_mldsa44", "ML-DSA-44", 1312, 2560, 2420,
                                PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair,
                                PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx,
                                PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx);
  PQCFUZZ_REFERENCE_SIG_ADAPTER(RefMlDsa65, "pqclean_ref_mldsa65", "ML-DSA-65", 1952, 4032, 3309,
                                PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair,
                                PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx,
                                PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx);
  PQCFUZZ_REFERENCE_SIG_ADAPTER(RefMlDsa87, "pqclean_ref_mldsa87", "ML-DSA-87", 2592, 4896, 4627,
                                PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair,
                                PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx,
                                PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx);
#undef PQCFUZZ_REFERENCE_SIG_ADAPTER

#define PQCFUZZ_REFERENCE_SLH_ADAPTER(NAME, PREFIX, ID, ALG, SEED_BYTES, PK, SK, SIG)                     \
  pqcfuzz_status NAME##KeygenSeeded(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len) {    \
    if (seed_len != SEED_BYTES) return PQCFUZZ_INVALID_INPUT;                                            \
    return pqcfuzz_normalize_return_code(PREFIX##_crypto_sign_seed_keypair(pk, sk, seed));               \
  }                                                                                                      \
  pqcfuzz_status NAME##Keygen(uint8_t *pk, uint8_t *sk) {                                                \
    std::vector<uint8_t> seed(SEED_BYTES, 0);                                                            \
    PQCLEAN_randombytes(seed.data(), seed.size());                                                       \
    return pqcfuzz_normalize_return_code(PREFIX##_crypto_sign_seed_keypair(pk, sk, seed.data()));        \
  }                                                                                                      \
  pqcfuzz_status NAME##Sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,           \
                            const uint8_t *sk, const uint8_t *, size_t) {                                \
    return pqcfuzz_normalize_return_code(PREFIX##_crypto_sign_signature(sig, sig_len, msg, msg_len, sk)); \
  }                                                                                                      \
  pqcfuzz_status NAME##Verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len,    \
                              const uint8_t *pk, const uint8_t *, size_t) {                              \
    return pqcfuzz_normalize_return_code(PREFIX##_crypto_sign_verify(sig, sig_len, msg, msg_len, pk));   \
  }                                                                                                      \
  const pqcfuzz_sig_adapter k##NAME = {                                                                  \
      "pqclean_reference", ID, ALG, PK, SK, SIG, 0, 0, 0, NAME##Keygen, NAME##Sign, NAME##Verify,       \
      UnsupportedSignSeeded, 1, 0, 0, kReferenceVersion, NAME##KeygenSeeded}

PQCFUZZ_REFERENCE_SLH_ADAPTER(RefSlhSha2_128s, PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN, "pqclean_ref_slhdsa_sha2_128s",
                              "SLH-DSA-SHA2-128s", 48, 32, 64, 7856);
PQCFUZZ_REFERENCE_SLH_ADAPTER(RefSlhSha2_128f, PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN, "pqclean_ref_slhdsa_sha2_128f",
                              "SLH-DSA-SHA2-128f", 48, 32, 64, 17088);
PQCFUZZ_REFERENCE_SLH_ADAPTER(RefSlhSha2_192s, PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN, "pqclean_ref_slhdsa_sha2_192s",
                              "SLH-DSA-SHA2-192s", 72, 48, 96, 16224);
PQCFUZZ_REFERENCE_SLH_ADAPTER(RefSlhSha2_192f, PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN, "pqclean_ref_slhdsa_sha2_192f",
                              "SLH-DSA-SHA2-192f", 72, 48, 96, 35664);
PQCFUZZ_REFERENCE_SLH_ADAPTER(RefSlhSha2_256s, PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN, "pqclean_ref_slhdsa_sha2_256s",
                              "SLH-DSA-SHA2-256s", 96, 64, 128, 29792);
PQCFUZZ_REFERENCE_SLH_ADAPTER(RefSlhSha2_256f, PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN, "pqclean_ref_slhdsa_sha2_256f",
                              "SLH-DSA-SHA2-256f", 96, 64, 128, 49856);
PQCFUZZ_REFERENCE_SLH_ADAPTER(RefSlhShake128s, PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN, "pqclean_ref_slhdsa_shake_128s",
                              "SLH-DSA-SHAKE-128s", 48, 32, 64, 7856);
PQCFUZZ_REFERENCE_SLH_ADAPTER(RefSlhShake128f, PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN, "pqclean_ref_slhdsa_shake_128f",
                              "SLH-DSA-SHAKE-128f", 48, 32, 64, 17088);
PQCFUZZ_REFERENCE_SLH_ADAPTER(RefSlhShake192s, PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN, "pqclean_ref_slhdsa_shake_192s",
                              "SLH-DSA-SHAKE-192s", 72, 48, 96, 16224);
PQCFUZZ_REFERENCE_SLH_ADAPTER(RefSlhShake192f, PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN, "pqclean_ref_slhdsa_shake_192f",
                              "SLH-DSA-SHAKE-192f", 72, 48, 96, 35664);
PQCFUZZ_REFERENCE_SLH_ADAPTER(RefSlhShake256s, PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN, "pqclean_ref_slhdsa_shake_256s",
                              "SLH-DSA-SHAKE-256s", 96, 64, 128, 29792);
PQCFUZZ_REFERENCE_SLH_ADAPTER(RefSlhShake256f, PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN, "pqclean_ref_slhdsa_shake_256f",
                              "SLH-DSA-SHAKE-256f", 96, 64, 128, 49856);
#undef PQCFUZZ_REFERENCE_SLH_ADAPTER
#else
#define PQCFUZZ_UNSUPPORTED_REFERENCE_KEM(NAME, ID, ALG, PK, SK, CT, SS)                         \
  const pqcfuzz_kem_adapter k##NAME = {                                                          \
      "pqclean_reference", ID, ALG, PK, SK, CT, SS, UnsupportedKeygen, UnsupportedEncaps,         \
      UnsupportedDecaps, UnsupportedKeygenDerand, UnsupportedEncapsDerand, kReferenceVersion}
  PQCFUZZ_UNSUPPORTED_REFERENCE_KEM(RefMlKem512, "pqclean_ref_mlkem512", "ML-KEM-512", 800, 1632, 768, 32);
  PQCFUZZ_UNSUPPORTED_REFERENCE_KEM(RefMlKem768, "pqclean_ref_mlkem768", "ML-KEM-768", 1184, 2400, 1088, 32);
  PQCFUZZ_UNSUPPORTED_REFERENCE_KEM(RefMlKem1024, "pqclean_ref_mlkem1024", "ML-KEM-1024", 1568, 3168, 1568, 32);

#define PQCFUZZ_UNSUPPORTED_REFERENCE_SIG(NAME, ID, ALG, PK, SK, SIG)                          \
  const pqcfuzz_sig_adapter k##NAME = {                                                        \
      "pqclean_reference", ID, ALG, PK, SK, SIG, 1, 0, 0, UnsupportedSigKeygen, UnsupportedSign, \
      UnsupportedVerify, UnsupportedSignSeeded, 1, 1, 1, kReferenceVersion}
  PQCFUZZ_UNSUPPORTED_REFERENCE_SIG(RefMlDsa44, "pqclean_ref_mldsa44", "ML-DSA-44", 1312, 2560, 2420);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SIG(RefMlDsa65, "pqclean_ref_mldsa65", "ML-DSA-65", 1952, 4032, 3309);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SIG(RefMlDsa87, "pqclean_ref_mldsa87", "ML-DSA-87", 2592, 4896, 4627);
#undef PQCFUZZ_UNSUPPORTED_REFERENCE_SIG

#define PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(NAME, ID, ALG, PK, SK, SIG)                                  \
  const pqcfuzz_sig_adapter k##NAME = {                                                               \
      "pqclean_reference", ID, ALG, PK, SK, SIG, 0, 0, 0, UnsupportedSigKeygen, UnsupportedSign,      \
      UnsupportedVerify, UnsupportedSignSeeded, 1, 0, 0, kReferenceVersion, nullptr}
  PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(RefSlhSha2_128s, "pqclean_ref_slhdsa_sha2_128s", "SLH-DSA-SHA2-128s", 32, 64, 7856);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(RefSlhSha2_128f, "pqclean_ref_slhdsa_sha2_128f", "SLH-DSA-SHA2-128f", 32, 64, 17088);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(RefSlhSha2_192s, "pqclean_ref_slhdsa_sha2_192s", "SLH-DSA-SHA2-192s", 48, 96, 16224);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(RefSlhSha2_192f, "pqclean_ref_slhdsa_sha2_192f", "SLH-DSA-SHA2-192f", 48, 96, 35664);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(RefSlhSha2_256s, "pqclean_ref_slhdsa_sha2_256s", "SLH-DSA-SHA2-256s", 64, 128, 29792);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(RefSlhSha2_256f, "pqclean_ref_slhdsa_sha2_256f", "SLH-DSA-SHA2-256f", 64, 128, 49856);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(RefSlhShake128s, "pqclean_ref_slhdsa_shake_128s", "SLH-DSA-SHAKE-128s", 32, 64, 7856);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(RefSlhShake128f, "pqclean_ref_slhdsa_shake_128f", "SLH-DSA-SHAKE-128f", 32, 64, 17088);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(RefSlhShake192s, "pqclean_ref_slhdsa_shake_192s", "SLH-DSA-SHAKE-192s", 48, 96, 16224);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(RefSlhShake192f, "pqclean_ref_slhdsa_shake_192f", "SLH-DSA-SHAKE-192f", 48, 96, 35664);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(RefSlhShake256s, "pqclean_ref_slhdsa_shake_256s", "SLH-DSA-SHAKE-256s", 64, 128, 29792);
  PQCFUZZ_UNSUPPORTED_REFERENCE_SLH(RefSlhShake256f, "pqclean_ref_slhdsa_shake_256f", "SLH-DSA-SHAKE-256f", 64, 128, 49856);
#undef PQCFUZZ_UNSUPPORTED_REFERENCE_SLH
#endif

const pqcfuzz_kem_adapter *const kReferenceKemAdapters[] = {&kRefMlKem512, &kRefMlKem768, &kRefMlKem1024};
const pqcfuzz_sig_adapter *const kReferenceSigAdapters[] = {
    &kRefMlDsa44,
    &kRefMlDsa65,
    &kRefMlDsa87,
    &kRefSlhSha2_128s,
    &kRefSlhSha2_128f,
    &kRefSlhSha2_192s,
    &kRefSlhSha2_192f,
    &kRefSlhSha2_256s,
    &kRefSlhSha2_256f,
    &kRefSlhShake128s,
    &kRefSlhShake128f,
    &kRefSlhShake192s,
    &kRefSlhShake192f,
    &kRefSlhShake256s,
    &kRefSlhShake256f,
};

}  // namespace

const pqcfuzz_kem_adapter *pqcfuzz_get_pqclean_reference_kem_adapter(const char *implementation_id) {
  if (implementation_id == nullptr) {
    return nullptr;
  }
  for (const pqcfuzz_kem_adapter *adapter : kReferenceKemAdapters) {
    if (std::strcmp(adapter->implementation_id, implementation_id) == 0) {
      return adapter;
    }
  }
  return nullptr;
}

const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_reference_sig_adapter(const char *implementation_id) {
  if (implementation_id == nullptr) {
    return nullptr;
  }
  for (const pqcfuzz_sig_adapter *adapter : kReferenceSigAdapters) {
    if (std::strcmp(adapter->implementation_id, implementation_id) == 0) {
      return adapter;
    }
  }
  return nullptr;
}

const char *pqcfuzz_pqclean_reference_version() {
  return kReferenceVersion;
}

}  // namespace pqcfuzz

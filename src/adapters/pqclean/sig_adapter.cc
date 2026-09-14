#include "adapters/pqclean/sig_adapter.h"

#include <cstring>

#ifdef PQCFUZZ_HAVE_PQCLEAN
extern "C" {
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);
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

pqcfuzz_status UnsupportedSignSeeded(
    uint8_t *,
    size_t *,
    const uint8_t *,
    size_t,
    const uint8_t *,
    const uint8_t *,
    size_t,
    const uint8_t *,
    size_t) {
  return PQCFUZZ_API_UNSUPPORTED;
}

#ifdef PQCFUZZ_HAVE_PQCLEAN
pqcfuzz_status MlDsa44Keygen(uint8_t *pk, uint8_t *sk) {
  return pqcfuzz_normalize_return_code(PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk));
}
pqcfuzz_status MlDsa44Sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk, const uint8_t *, size_t ctx_len) {
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  return pqcfuzz_normalize_return_code(PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, sig_len, msg, msg_len, sk));
}
pqcfuzz_status MlDsa44Verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk, const uint8_t *, size_t ctx_len) {
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  return pqcfuzz_normalize_return_code(PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, sig_len, msg, msg_len, pk));
}
pqcfuzz_status MlDsa65Keygen(uint8_t *pk, uint8_t *sk) {
  return pqcfuzz_normalize_return_code(PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk));
}
pqcfuzz_status MlDsa65Sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk, const uint8_t *, size_t ctx_len) {
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  return pqcfuzz_normalize_return_code(PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, sig_len, msg, msg_len, sk));
}
pqcfuzz_status MlDsa65Verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk, const uint8_t *, size_t ctx_len) {
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  return pqcfuzz_normalize_return_code(PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, sig_len, msg, msg_len, pk));
}
pqcfuzz_status MlDsa87Keygen(uint8_t *pk, uint8_t *sk) {
  return pqcfuzz_normalize_return_code(PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk));
}
pqcfuzz_status MlDsa87Sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk, const uint8_t *, size_t ctx_len) {
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  return pqcfuzz_normalize_return_code(PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, sig_len, msg, msg_len, sk));
}
pqcfuzz_status MlDsa87Verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk, const uint8_t *, size_t ctx_len) {
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  return pqcfuzz_normalize_return_code(PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, sig_len, msg, msg_len, pk));
}
#else
#define MlDsa44Keygen UnsupportedKeygen
#define MlDsa44Sign UnsupportedSign
#define MlDsa44Verify UnsupportedVerify
#define MlDsa65Keygen UnsupportedKeygen
#define MlDsa65Sign UnsupportedSign
#define MlDsa65Verify UnsupportedVerify
#define MlDsa87Keygen UnsupportedKeygen
#define MlDsa87Sign UnsupportedSign
#define MlDsa87Verify UnsupportedVerify
#endif

const pqcfuzz_sig_adapter kMlDsa44 = {
    "pqclean", "pqclean_mldsa44_clean", "ML-DSA-44", 1312, 2560, 2420, 0, 0, 0,
    MlDsa44Keygen, MlDsa44Sign, MlDsa44Verify, UnsupportedSignSeeded, 1, 0, 0};
const pqcfuzz_sig_adapter kMlDsa65 = {
    "pqclean", "pqclean_mldsa65_clean", "ML-DSA-65", 1952, 4032, 3309, 0, 0, 0,
    MlDsa65Keygen, MlDsa65Sign, MlDsa65Verify, UnsupportedSignSeeded, 1, 0, 0};
const pqcfuzz_sig_adapter kMlDsa87 = {
    "pqclean", "pqclean_mldsa87_clean", "ML-DSA-87", 2592, 4896, 4627, 0, 0, 0,
    MlDsa87Keygen, MlDsa87Sign, MlDsa87Verify, UnsupportedSignSeeded, 1, 0, 0};

#define PQCFUZZ_SLH_PQCLEAN_ADAPTER(symbol, impl, algorithm, pk, sk, sig) \
  const pqcfuzz_sig_adapter symbol = { \
      "pqclean", impl, algorithm, pk, sk, sig, 0, 0, 0, UnsupportedKeygen, UnsupportedSign, UnsupportedVerify, UnsupportedSignSeeded, 0, 0, 0}

PQCFUZZ_SLH_PQCLEAN_ADAPTER(kSlhDsaSha2_128s, "pqclean_slhdsa_sha2_128s_clean", "SLH-DSA-SHA2-128s", 32, 64, 7856);
PQCFUZZ_SLH_PQCLEAN_ADAPTER(kSlhDsaShake_128s, "pqclean_slhdsa_shake_128s_clean", "SLH-DSA-SHAKE-128s", 32, 64, 7856);
PQCFUZZ_SLH_PQCLEAN_ADAPTER(kSlhDsaSha2_128f, "pqclean_slhdsa_sha2_128f_clean", "SLH-DSA-SHA2-128f", 32, 64, 17088);
PQCFUZZ_SLH_PQCLEAN_ADAPTER(kSlhDsaShake_128f, "pqclean_slhdsa_shake_128f_clean", "SLH-DSA-SHAKE-128f", 32, 64, 17088);
PQCFUZZ_SLH_PQCLEAN_ADAPTER(kSlhDsaSha2_192s, "pqclean_slhdsa_sha2_192s_clean", "SLH-DSA-SHA2-192s", 48, 96, 16224);
PQCFUZZ_SLH_PQCLEAN_ADAPTER(kSlhDsaShake_192s, "pqclean_slhdsa_shake_192s_clean", "SLH-DSA-SHAKE-192s", 48, 96, 16224);
PQCFUZZ_SLH_PQCLEAN_ADAPTER(kSlhDsaSha2_192f, "pqclean_slhdsa_sha2_192f_clean", "SLH-DSA-SHA2-192f", 48, 96, 35664);
PQCFUZZ_SLH_PQCLEAN_ADAPTER(kSlhDsaShake_192f, "pqclean_slhdsa_shake_192f_clean", "SLH-DSA-SHAKE-192f", 48, 96, 35664);
PQCFUZZ_SLH_PQCLEAN_ADAPTER(kSlhDsaSha2_256s, "pqclean_slhdsa_sha2_256s_clean", "SLH-DSA-SHA2-256s", 64, 128, 29792);
PQCFUZZ_SLH_PQCLEAN_ADAPTER(kSlhDsaShake_256s, "pqclean_slhdsa_shake_256s_clean", "SLH-DSA-SHAKE-256s", 64, 128, 29792);
PQCFUZZ_SLH_PQCLEAN_ADAPTER(kSlhDsaSha2_256f, "pqclean_slhdsa_sha2_256f_clean", "SLH-DSA-SHA2-256f", 64, 128, 49856);
PQCFUZZ_SLH_PQCLEAN_ADAPTER(kSlhDsaShake_256f, "pqclean_slhdsa_shake_256f_clean", "SLH-DSA-SHAKE-256f", 64, 128, 49856);

}  // namespace

const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_mldsa44_adapter(void) {
  return &kMlDsa44;
}

const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_mldsa65_adapter(void) {
  return &kMlDsa65;
}

const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_mldsa87_adapter(void) {
  return &kMlDsa87;
}

const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_sha2_128s_adapter(void) { return &kSlhDsaSha2_128s; }
const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_shake_128s_adapter(void) { return &kSlhDsaShake_128s; }
const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_sha2_128f_adapter(void) { return &kSlhDsaSha2_128f; }
const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_shake_128f_adapter(void) { return &kSlhDsaShake_128f; }
const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_sha2_192s_adapter(void) { return &kSlhDsaSha2_192s; }
const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_shake_192s_adapter(void) { return &kSlhDsaShake_192s; }
const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_sha2_192f_adapter(void) { return &kSlhDsaSha2_192f; }
const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_shake_192f_adapter(void) { return &kSlhDsaShake_192f; }
const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_sha2_256s_adapter(void) { return &kSlhDsaSha2_256s; }
const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_shake_256s_adapter(void) { return &kSlhDsaShake_256s; }
const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_sha2_256f_adapter(void) { return &kSlhDsaSha2_256f; }
const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_slhdsa_shake_256f_adapter(void) { return &kSlhDsaShake_256f; }

const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_sig_adapter(const char *implementation_id) {
  if (implementation_id == nullptr) {
    return nullptr;
  }
  if (std::strcmp(implementation_id, kMlDsa44.implementation_id) == 0) {
    return &kMlDsa44;
  }
  if (std::strcmp(implementation_id, kMlDsa65.implementation_id) == 0) {
    return &kMlDsa65;
  }
  if (std::strcmp(implementation_id, kMlDsa87.implementation_id) == 0) {
    return &kMlDsa87;
  }
  const pqcfuzz_sig_adapter *slh_adapters[] = {
      &kSlhDsaSha2_128s, &kSlhDsaShake_128s, &kSlhDsaSha2_128f, &kSlhDsaShake_128f,
      &kSlhDsaSha2_192s, &kSlhDsaShake_192s, &kSlhDsaSha2_192f, &kSlhDsaShake_192f,
      &kSlhDsaSha2_256s, &kSlhDsaShake_256s, &kSlhDsaSha2_256f, &kSlhDsaShake_256f,
  };
  for (const auto *adapter : slh_adapters) {
    if (std::strcmp(implementation_id, adapter->implementation_id) == 0) {
      return adapter;
    }
  }
  return nullptr;
}

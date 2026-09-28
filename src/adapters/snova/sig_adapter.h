#ifndef PQCFUZZ_ADAPTERS_SNOVA_SIG_ADAPTER_H
#define PQCFUZZ_ADAPTERS_SNOVA_SIG_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#include "adapters/adapter_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

// Optional capability/extension table for SNOVA.  It is deliberately separate
// from pqcfuzz_sig_adapter so the append-only ABI of the shared signature
// interface is untouched.  Implementations return nullptr when the adapter was
// not compiled with PQCFUZZ_HAVE_SNOVA, so a misconfigured job fails at
// routing instead of silently running the wrong backend.
typedef struct pqcfuzz_snova_api {
  const char *implementation_id;
  const char *algorithm;
  const char *backend;    // "AES" or "SHAKE"
  const char *sk_format;  // "SSK" (48-byte seed) or "ESK" (expanded)
  size_t pk_len;
  size_t sk_len;
  size_t sig_max_len;
  size_t signature_data_bytes;  // sig_max_len - salt
  size_t hash_bytes;
  size_t expanded_pk_len;
  int fixed_abq;
  int supports_digest_api;
  int supports_keygen_from_sk;
  // Digest-level signing/verification with an explicit 16-byte salt.
  pqcfuzz_status (*sign_digest)(uint8_t *sig, size_t *sig_len, const uint8_t *digest, size_t digest_len,
                                const uint8_t *sk, const uint8_t *salt);
  pqcfuzz_status (*verify_digest)(const uint8_t *sig, size_t sig_len, const uint8_t *digest, size_t digest_len,
                                  const uint8_t *pk);
  // Recompute a public key from a stored SSK/ESK.
  pqcfuzz_status (*keygen_from_sk)(uint8_t *pk, const uint8_t *sk, size_t sk_len);
  // Pack the expanded public map (seed || P22,P11,P12,P21,A,B,Q1,Q2 nibbles).
  // The caller provides a buffer of expanded_pk_len bytes.
  void (*expand_public)(uint8_t *expanded_pk, const uint8_t *pk);
} pqcfuzz_snova_api;

const pqcfuzz_sig_adapter *pqcfuzz_get_snova_sig_adapter(const char *implementation_id);
const pqcfuzz_snova_api *pqcfuzz_get_snova_api(const char *implementation_id);

#ifdef __cplusplus
}
#endif

#endif

#ifndef PQCFUZZ_ADAPTERS_ADAPTER_INTERFACE_H
#define PQCFUZZ_ADAPTERS_ADAPTER_INTERFACE_H

#include <stddef.h>
#include <stdint.h>

#include "adapters/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef pqcfuzz_status (*pqcfuzz_kem_keygen_fn)(uint8_t *pk, uint8_t *sk);
typedef pqcfuzz_status (*pqcfuzz_kem_encaps_fn)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
typedef pqcfuzz_status (*pqcfuzz_kem_decaps_fn)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
typedef pqcfuzz_status (*pqcfuzz_kem_keygen_derand_fn)(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
typedef pqcfuzz_status (*pqcfuzz_kem_encaps_derand_fn)(
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk,
    const uint8_t *coins);

typedef pqcfuzz_status (*pqcfuzz_sig_keygen_fn)(uint8_t *pk, uint8_t *sk);
typedef pqcfuzz_status (*pqcfuzz_sig_sign_fn)(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len);
typedef pqcfuzz_status (*pqcfuzz_sig_verify_fn)(
    const uint8_t *sig,
    size_t sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *pk,
    const uint8_t *ctx,
    size_t ctx_len);
typedef pqcfuzz_status (*pqcfuzz_sig_sign_seeded_fn)(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len,
    const uint8_t *seed,
    size_t seed_len);
typedef pqcfuzz_status (*pqcfuzz_sig_keygen_seeded_fn)(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *seed,
    size_t seed_len);

// Optional NIST signed-message (attached) API used by schemes that expose a
// combined BE16-length || salt || message || header || value frame (Falcon
// section 3.11.6).  Appended after the fields above so every pre-existing
// adapter initializer keeps its meaning and defaults these to nullptr.
typedef pqcfuzz_status (*pqcfuzz_sig_sign_attached_fn)(
    uint8_t *sm,
    size_t *sm_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk);
typedef pqcfuzz_status (*pqcfuzz_sig_open_attached_fn)(
    uint8_t *msg,
    size_t *msg_len,
    const uint8_t *sm,
    size_t sm_len,
    const uint8_t *pk);

typedef struct pqcfuzz_kem_adapter {
  const char *project_id;
  const char *implementation_id;
  const char *algorithm;
  size_t pk_len;
  size_t sk_len;
  size_t ct_len;
  size_t ss_len;
  pqcfuzz_kem_keygen_fn keygen;
  pqcfuzz_kem_encaps_fn encaps;
  pqcfuzz_kem_decaps_fn decaps;
  // Deterministic hooks used by KAT and randomness oracles.  Optional:
  // callers must check for nullptr.
  pqcfuzz_kem_keygen_derand_fn keygen_derand;
  pqcfuzz_kem_encaps_derand_fn encaps_derand;
  // Reference model provenance (e.g. a pinned source commit).
  const char *reference_version;
} pqcfuzz_kem_adapter;

typedef struct pqcfuzz_sig_adapter {
  const char *project_id;
  const char *implementation_id;
  const char *algorithm;
  size_t pk_len;
  size_t sk_len;
  size_t sig_max_len;
  int supports_context;
  int supports_seeded_sign;
  int supports_deterministic_sign;
  pqcfuzz_sig_keygen_fn keygen;
  pqcfuzz_sig_sign_fn sign;
  pqcfuzz_sig_verify_fn verify;
  pqcfuzz_sig_sign_seeded_fn sign_seeded;
  // Boundary-testing capabilities.  Appended fields default to zero for
  // adapters that predate them.
  // verify_checks_length: the verify entry point receives a signature length
  // and is expected to enforce exact-length rejection itself.
  int verify_checks_length;
  // sign/verify_accepts_extended_context: the entry point receives ctx_len and
  // is expected to enforce the FIPS context limit itself, so the executor
  // must not pre-reject ctx_len > 255.
  int sign_accepts_extended_context;
  int verify_accepts_extended_context;
  // Reference model provenance (e.g. a pinned source commit).
  const char *reference_version;
  // Seed-based key generation used by KAT vectors.  Optional.
  pqcfuzz_sig_keygen_seeded_fn keygen_seeded;
  // Optional attached (signed-message) API; nullptr when unsupported.
  pqcfuzz_sig_sign_attached_fn sign_attached;
  pqcfuzz_sig_open_attached_fn open_attached;
} pqcfuzz_sig_adapter;

#ifdef __cplusplus
}
#endif

#endif

#ifndef PQCDF_ADAPTER_INTERFACE_H
#define PQCDF_ADAPTER_INTERFACE_H

#include <stddef.h>
#include <stdint.h>

/* Framework-level return convention: 0 means success, non-zero means failure. */

typedef int (*pqcdf_init_fn)(void);
typedef void (*pqcdf_cleanup_fn)(void);

typedef int (*pqcdf_kem_keygen_fn)(uint8_t *pk, uint8_t *sk);
typedef int (*pqcdf_kem_encaps_fn)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
typedef int (*pqcdf_kem_decaps_fn)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
typedef int (*pqcdf_kem_keygen_derand_fn)(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len);
typedef int (*pqcdf_kem_encaps_derand_fn)(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *seed, size_t seed_len);
typedef int (*pqcdf_kpke_keygen_derand_fn)(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len);
typedef int (*pqcdf_kpke_encrypt_fn)(uint8_t *ct, const uint8_t *msg, const uint8_t *pk, const uint8_t *coins, size_t coins_len);
typedef int (*pqcdf_kpke_decrypt_fn)(uint8_t *msg, const uint8_t *ct, const uint8_t *sk);

typedef int (*pqcdf_sig_keygen_fn)(uint8_t *pk, uint8_t *sk);
typedef int (*pqcdf_sig_sign_fn)(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
typedef int (*pqcdf_sig_verify_fn)(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);
typedef int (*pqcdf_sig_sign_derand_fn)(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *seed,
    size_t seed_len);

typedef struct pqcdf_kem_adapter {
  const char *project_id;
  const char *implementation_id;
  size_t pk_len;
  size_t sk_len;
  size_t ct_len;
  size_t ss_len;
  int supports_keygen_derand;
  int supports_encaps_derand;
  pqcdf_init_fn init;
  pqcdf_cleanup_fn cleanup;
  pqcdf_kem_keygen_fn keygen;
  pqcdf_kem_encaps_fn encaps;
  pqcdf_kem_decaps_fn decaps;
  pqcdf_kem_keygen_derand_fn keygen_derand;
  pqcdf_kem_encaps_derand_fn encaps_derand;
} pqcdf_kem_adapter;

typedef struct pqcdf_sig_adapter {
  const char *project_id;
  const char *implementation_id;
  size_t pk_len;
  size_t sk_len;
  size_t sig_max_len;
  int supports_sign_derand;
  pqcdf_init_fn init;
  pqcdf_cleanup_fn cleanup;
  pqcdf_sig_keygen_fn keygen;
  pqcdf_sig_sign_fn sign;
  pqcdf_sig_verify_fn verify;
  pqcdf_sig_sign_derand_fn sign_derand;
} pqcdf_sig_adapter;

typedef struct pqcdf_kpke_adapter {
  const char *project_id;
  const char *implementation_id;
  size_t pk_len;
  size_t sk_len;
  size_t ct_len;
  size_t msg_len;
  int supports_keygen_derand;
  pqcdf_init_fn init;
  pqcdf_cleanup_fn cleanup;
  pqcdf_kpke_keygen_derand_fn keygen_derand;
  pqcdf_kpke_encrypt_fn encrypt;
  pqcdf_kpke_decrypt_fn decrypt;
} pqcdf_kpke_adapter;

#endif

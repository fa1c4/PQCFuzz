#ifndef PQCFUZZ_ADAPTERS_SIKE_REFERENCE_ADAPTER_H
#define PQCFUZZ_ADAPTERS_SIKE_REFERENCE_ADAPTER_H

#include <cstddef>
#include <cstdint>

#include "adapters/status.h"

// Test-build-only hooks over the pinned PQCrypto-SIDH isogeny functions.  They
// let the oracle executor recompute the SIKE re-encryption gate without
// copying the target's kem.c logic.  The hooks are compiled only with
// PQCFUZZ_HAVE_SIKE_REFERENCE and are never linked into a target-only build;
// the public KEM entry points stay the only externally visible API.
namespace pqcfuzz {
namespace sike_reference {

struct SikeReferenceHooks {
  // Decrypt-side j-invariant: EphemeralSecretAgreement_B(sk3, c0).
  pqcfuzz_status (*pke_j_invariant)(
      uint8_t *j_out,
      size_t j_len,
      const uint8_t *sk3,
      size_t sk3_len,
      const uint8_t *c0,
      size_t c0_len);
  // 2-isogeny image: EphemeralKeyGeneration_A(scalar) -> public key.
  pqcfuzz_status (*isogen2)(uint8_t *pk_out, size_t pk_len, const uint8_t *scalar, size_t scalar_len);
  // 3-isogeny image: EphemeralKeyGeneration_B(scalar) -> public key.
  pqcfuzz_status (*isogen3)(uint8_t *pk_out, size_t pk_len, const uint8_t *scalar, size_t scalar_len);
};

// Returns nullptr when the reference hooks are not linked into this binary.
const SikeReferenceHooks *GetSikeReferenceHooks();

}  // namespace sike_reference
}  // namespace pqcfuzz

#endif

#include "adapters/sike/reference_adapter.h"

#ifdef PQCFUZZ_HAVE_SIKE_REFERENCE

#include <cstring>

#ifndef PQCFUZZ_SIKE_API_HEADER
#define PQCFUZZ_SIKE_API_HEADER "P434_api.h"
#endif
extern "C" {
#include PQCFUZZ_SIKE_API_HEADER
}

#ifndef PQCFUZZ_SIDH_DERIVE_B
#define PQCFUZZ_SIDH_DERIVE_B EphemeralSecretAgreement_B
#endif
#ifndef PQCFUZZ_SIDH_KEYGEN_A
#define PQCFUZZ_SIDH_KEYGEN_A EphemeralKeyGeneration_A
#endif
#ifndef PQCFUZZ_SIDH_KEYGEN_B
#define PQCFUZZ_SIDH_KEYGEN_B EphemeralKeyGeneration_B
#endif

namespace pqcfuzz {
namespace sike_reference {
namespace {

pqcfuzz_status PkeJInvariant(
    uint8_t *j_out,
    size_t j_len,
    const uint8_t *sk3,
    size_t sk3_len,
    const uint8_t *c0,
    size_t c0_len) {
  if (j_out == nullptr || sk3 == nullptr || c0 == nullptr || j_len != SIDH_BYTES ||
      sk3_len != SIDH_SECRETKEYBYTES_B || c0_len != SIDH_PUBLICKEYBYTES) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return PQCFUZZ_SIDH_DERIVE_B(sk3, c0, j_out) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status Isogen2(uint8_t *pk_out, size_t pk_len, const uint8_t *scalar, size_t scalar_len) {
  if (pk_out == nullptr || scalar == nullptr || pk_len != SIDH_PUBLICKEYBYTES ||
      scalar_len != SIDH_SECRETKEYBYTES_A) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return PQCFUZZ_SIDH_KEYGEN_A(scalar, pk_out) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status Isogen3(uint8_t *pk_out, size_t pk_len, const uint8_t *scalar, size_t scalar_len) {
  if (pk_out == nullptr || scalar == nullptr || pk_len != SIDH_PUBLICKEYBYTES ||
      scalar_len != SIDH_SECRETKEYBYTES_B) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return PQCFUZZ_SIDH_KEYGEN_B(scalar, pk_out) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

const SikeReferenceHooks kHooks = {
    PkeJInvariant,
    Isogen2,
    Isogen3,
};

}  // namespace

const SikeReferenceHooks *GetSikeReferenceHooks() {
  return &kHooks;
}

}  // namespace sike_reference
}  // namespace pqcfuzz

#else

namespace pqcfuzz {
namespace sike_reference {

const SikeReferenceHooks *GetSikeReferenceHooks() {
  return nullptr;
}

}  // namespace sike_reference
}  // namespace pqcfuzz

#endif  // PQCFUZZ_HAVE_SIKE_REFERENCE

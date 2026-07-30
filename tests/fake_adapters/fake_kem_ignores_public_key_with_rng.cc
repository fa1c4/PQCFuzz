#include "adapters/adapter_interface.h"
#include "adapters/rng_control.h"

#include <cstring>

namespace {

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x22, 4);
  std::memset(sk, 0x33, 4);
  return PQCFUZZ_OK;
}

pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *) {
  uint8_t random = 0;
  if (!pqcfuzz_rng_fill_bytes(&random, 1)) return PQCFUZZ_INVALID_INPUT;
  for (size_t i = 0; i < 4; ++i) {
    ct[i] = static_cast<uint8_t>(random + i);
    ss[i] = static_cast<uint8_t>(0x80 + random + i);
  }
  return PQCFUZZ_OK;
}

pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *, const uint8_t *) {
  std::memset(ss, 0x44, 4);
  return PQCFUZZ_OK;
}

const pqcfuzz_kem_adapter kAdapter = {
    "fake", "fake_kem_ignores_public_key_with_rng", "ML-KEM-768", 4, 4, 4, 4, Keygen, Encaps, Decaps};

}  // namespace

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_kem_ignores_public_key_with_rng_adapter() {
  return &kAdapter;
}

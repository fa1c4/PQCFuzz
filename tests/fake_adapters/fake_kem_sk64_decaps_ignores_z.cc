#include "adapters/adapter_interface.h"

#include <cstring>

namespace {

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x10, 64);
  std::memset(sk, 0x20, 64);
  return PQCFUZZ_OK;
}

pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *) {
  std::memset(ct, 0x30, 64);
  std::memset(ss, 0x42, 4);
  return PQCFUZZ_OK;
}

pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *, const uint8_t *) {
  std::memset(ss, 0x42, 4);
  return PQCFUZZ_OK;
}

}  // namespace

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_kem_sk64_decaps_ignores_z_adapter() {
  static const pqcfuzz_kem_adapter adapter = {
      "fake", "fake_kem_sk64_decaps_ignores_z", "ML-KEM-768", 64, 64, 64, 4, Keygen, Encaps, Decaps};
  return &adapter;
}

#include "adapters/adapter_interface.h"

#include <cstring>

namespace {

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  for (size_t i = 0; i < 4; ++i) {
    pk[i] = static_cast<uint8_t>(0x10 + i);
    sk[i] = static_cast<uint8_t>(0x20 + i);
  }
  return PQCFUZZ_OK;
}

pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *) {
  for (size_t i = 0; i < 4; ++i) {
    ct[i] = static_cast<uint8_t>(0x30 + i);
    ss[i] = 0x42;
  }
  return PQCFUZZ_OK;
}

pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *, const uint8_t *) {
  std::memset(ss, 0x42, 4);
  return PQCFUZZ_OK;
}

}  // namespace

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_kem_equal_adapter() {
  static const pqcfuzz_kem_adapter adapter = {
      "fake", "fake_kem_equal", "ML-KEM-768", 4, 4, 4, 4, Keygen, Encaps, Decaps};
  return &adapter;
}

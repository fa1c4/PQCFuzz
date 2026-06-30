#include "adapters/adapter_interface.h"

namespace {

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  for (size_t i = 0; i < 4; ++i) {
    pk[i] = static_cast<uint8_t>(0x40 + i);
    sk[i] = static_cast<uint8_t>(0x50 + i);
  }
  return PQCFUZZ_OK;
}

pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  for (size_t i = 0; i < 4; ++i) {
    sig[i] = static_cast<uint8_t>(0x60 + i);
  }
  *sig_len = 4;
  return PQCFUZZ_OK;
}

pqcfuzz_status Verify(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_OK;
}

}  // namespace

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_sig_verify_accepts_mutation_adapter() {
  static const pqcfuzz_sig_adapter adapter = {
      "fake", "fake_sig_verify_accepts_mutation", "ML-DSA-44", 4, 4, 4, 0, 0, 0, Keygen, Sign, Verify, nullptr};
  return &adapter;
}

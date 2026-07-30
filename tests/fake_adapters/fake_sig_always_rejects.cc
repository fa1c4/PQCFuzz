#include "adapters/adapter_interface.h"

#include <cstring>

namespace {

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x40, 4);
  std::memset(sk, 0x50, 4);
  return PQCFUZZ_OK;
}

pqcfuzz_status Sign(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *,
    size_t,
    const uint8_t *,
    const uint8_t *,
    size_t) {
  std::memset(sig, 0x60, 4);
  *sig_len = 4;
  return PQCFUZZ_OK;
}

pqcfuzz_status Verify(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_REJECT;
}

const pqcfuzz_sig_adapter kAdapter = {
    "fake", "fake_sig_always_rejects", "ML-DSA-44", 4, 4, 4, 1, 0, 0, Keygen, Sign, Verify, nullptr};

}  // namespace

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_sig_always_rejects_adapter() {
  return &kAdapter;
}

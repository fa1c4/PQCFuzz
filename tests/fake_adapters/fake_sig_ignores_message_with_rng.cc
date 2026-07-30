#include "adapters/adapter_interface.h"
#include "adapters/rng_control.h"

#include <cstring>

namespace {

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x41, 4);
  std::memset(sk, 0x51, 4);
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
  uint8_t random = 0;
  if (!pqcfuzz_rng_fill_bytes(&random, 1)) return PQCFUZZ_INVALID_INPUT;
  for (size_t i = 0; i < 4; ++i) sig[i] = static_cast<uint8_t>(random + i);
  *sig_len = 4;
  return PQCFUZZ_OK;
}

pqcfuzz_status Verify(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_API_UNSUPPORTED;
}

const pqcfuzz_sig_adapter kAdapter = {
    "fake", "fake_sig_ignores_message_with_rng", "ML-DSA-44", 4, 4, 4, 1, 0, 0, Keygen, Sign, Verify, nullptr};

}  // namespace

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_sig_ignores_message_with_rng_adapter() {
  return &kAdapter;
}

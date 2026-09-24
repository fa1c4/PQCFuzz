// Test-only NTRU KEM adapter with a broken implicit-rejection path: it always
// returns the same valid shared secret, ignoring the failure flag.  It is used
// to prove that ntru_ct_padding, ntru_implicit_rejection_exact and
// ntru_prf_key_separation actually fire when the fallback is broken.
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "adapters/adapter_interface.h"

namespace {

pqcfuzz_kem_adapter g_adapter = {
    "ntru",
    "ntru_fake_swallow_fail",
    "NTRU-HPS-2048-509",
    0,
    0,
    0,
    32,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    "fake-ntru",
};

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  if (pk == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  for (size_t i = 0; i < g_adapter.pk_len; ++i) {
    pk[i] = static_cast<uint8_t>(i * 7 + 1);
  }
  for (size_t i = 0; i < g_adapter.sk_len; ++i) {
    sk[i] = static_cast<uint8_t>(i * 11 + 3);
  }
  return PQCFUZZ_OK;
}

pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *) {
  if (ct == nullptr || ss == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  std::memset(ct, 0x5A, g_adapter.ct_len);
  for (size_t i = 0; i < g_adapter.ss_len; ++i) {
    ss[i] = static_cast<uint8_t>(0x40 + i);
  }
  return PQCFUZZ_OK;
}

pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *, const uint8_t *) {
  if (ss == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  // Always returns the valid secret, even for a failed ciphertext.
  for (size_t i = 0; i < g_adapter.ss_len; ++i) {
    ss[i] = static_cast<uint8_t>(0x40 + i);
  }
  return PQCFUZZ_OK;
}

}  // namespace

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_ntru_adapter() {
  return &g_adapter;
}

extern "C" void pqcfuzz_fake_ntru_configure(
    const char *algorithm,
    size_t pk_len,
    size_t sk_len,
    size_t ct_len,
    size_t ss_len) {
  g_adapter.algorithm = algorithm;
  g_adapter.pk_len = pk_len;
  g_adapter.sk_len = sk_len;
  g_adapter.ct_len = ct_len;
  g_adapter.ss_len = ss_len;
  g_adapter.keygen = Keygen;
  g_adapter.encaps = Encaps;
  g_adapter.decaps = Decaps;
}

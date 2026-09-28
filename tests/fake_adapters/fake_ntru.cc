// Test-only NTRU KEM adapters with deliberately broken implicit-rejection
// paths.  Each mode corrupts the fallback secret in a specific way so the
// ntru_ct_padding, ntru_implicit_rejection_exact and ntru_prf_key_separation
// oracles can be shown to fire for that exact mutation.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "adapters/adapter_interface.h"
#include "mutators/sha3.h"

namespace {

enum class FakeMode {
  kSwallowFail = 0,
  kSha3WithPrfOffByOne = 1,
  kShake256Fallback = 2,
  kZeroOnFail = 3,
};

FakeMode g_mode = FakeMode::kSwallowFail;

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

pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  if (ss == nullptr || ct == nullptr || sk == nullptr || g_adapter.sk_len < 32) {
    return PQCFUZZ_INVALID_INPUT;
  }
  const uint8_t *prf = sk + g_adapter.sk_len - 32;
  switch (g_mode) {
    case FakeMode::kSwallowFail:
      // Always returns the valid secret, even for a failed ciphertext.
      for (size_t i = 0; i < g_adapter.ss_len; ++i) {
        ss[i] = static_cast<uint8_t>(0x40 + i);
      }
      return PQCFUZZ_OK;
    case FakeMode::kSha3WithPrfOffByOne: {
      std::vector<uint8_t> material(prf + 1, prf + 32);
      material.push_back(0x00);
      material.insert(material.end(), ct, ct + g_adapter.ct_len);
      const std::vector<uint8_t> digest = pqcfuzz::Sha3_256(material);
      std::memcpy(ss, digest.data(), g_adapter.ss_len);
      return PQCFUZZ_OK;
    }
    case FakeMode::kShake256Fallback: {
      std::vector<uint8_t> material(prf, prf + 32);
      material.insert(material.end(), ct, ct + g_adapter.ct_len);
      const std::vector<uint8_t> digest = pqcfuzz::Shake256(material, g_adapter.ss_len);
      std::memcpy(ss, digest.data(), g_adapter.ss_len);
      return PQCFUZZ_OK;
    }
    case FakeMode::kZeroOnFail:
      std::memset(ss, 0, g_adapter.ss_len);
      return PQCFUZZ_OK;
  }
  return PQCFUZZ_INVALID_INPUT;
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

extern "C" void pqcfuzz_fake_ntru_set_mode(const char *mode) {
  const std::string requested = mode == nullptr ? "swallow_fail" : mode;
  if (requested == "prf_off_by_one") {
    g_mode = FakeMode::kSha3WithPrfOffByOne;
  } else if (requested == "shake256_fallback") {
    g_mode = FakeMode::kShake256Fallback;
  } else if (requested == "zero_on_fail") {
    g_mode = FakeMode::kZeroOnFail;
  } else {
    g_mode = FakeMode::kSwallowFail;
  }
}

// Test-only CROSS signature adapters with selected broken verification
// policies.  They are used to prove that the CROSS mutation oracles fire for
// the documented failure predicates and that a length-respecting mutant is
// still caught by the content oracles.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "adapters/adapter_interface.h"

namespace {

enum class FakeMode {
  kAlwaysAccept = 0,
  kAcceptExactLength = 1,
};

FakeMode g_mode = FakeMode::kAlwaysAccept;

pqcfuzz_sig_adapter g_adapter = {
    "cross",
    "cross_fake",
    "CROSS-RSDP-1-FAST",
    0,
    0,
    0,
    0,
    0,
    0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    1,
    0,
    0,
    "fake-cross",
    nullptr,
    nullptr,
    nullptr,
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

pqcfuzz_status KeygenSeeded(uint8_t *pk, uint8_t *sk, const uint8_t *, size_t) {
  return Keygen(pk, sk);
}

pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  if (sig == nullptr || sig_len == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  for (size_t i = 0; i < g_adapter.sig_max_len; ++i) {
    sig[i] = static_cast<uint8_t>((i * 13 + 5) & 0xFF);
  }
  *sig_len = g_adapter.sig_max_len;
  return PQCFUZZ_OK;
}

pqcfuzz_status SignSeeded(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len,
    const uint8_t *,
    size_t) {
  return Sign(sig, sig_len, msg, msg_len, sk, ctx, ctx_len);
}

pqcfuzz_status Verify(const uint8_t *sig, size_t sig_len, const uint8_t *, size_t, const uint8_t *, const uint8_t *,
                      size_t) {
  if (sig == nullptr) {
    return PQCFUZZ_REJECT;
  }
  switch (g_mode) {
    case FakeMode::kAlwaysAccept:
      return PQCFUZZ_OK;
    case FakeMode::kAcceptExactLength:
      // Accepts any content at the profile length; this must keep the exact
      // length oracle green while the content oracles still fire.
      return sig_len == g_adapter.sig_max_len ? PQCFUZZ_OK : PQCFUZZ_REJECT;
  }
  return PQCFUZZ_REJECT;
}

}  // namespace

extern "C" void pqcfuzz_fake_cross_configure(
    const char *algorithm,
    size_t pk_len,
    size_t sk_len,
    size_t sig_max_len,
    const char *mode) {
  g_adapter.algorithm = algorithm;
  g_adapter.pk_len = pk_len;
  g_adapter.sk_len = sk_len;
  g_adapter.sig_max_len = sig_max_len;
  g_adapter.keygen = Keygen;
  g_adapter.sign = Sign;
  g_adapter.verify = Verify;
  g_adapter.sign_seeded = SignSeeded;
  g_adapter.keygen_seeded = KeygenSeeded;
  const std::string requested = mode == nullptr ? "always_accept" : mode;
  g_mode = requested == "accept_exact_length" ? FakeMode::kAcceptExactLength : FakeMode::kAlwaysAccept;
}

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_cross_adapter() {
  return &g_adapter;
}

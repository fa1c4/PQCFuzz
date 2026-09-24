// Test-only Falcon adapter that accepts every verification.  It is used to
// prove that the negative/canonicality oracles actually fire when the
// verifier's decision is broken ("returns always-true" mutant).
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "adapters/adapter_interface.h"

namespace {

constexpr size_t kPkLen = 897;
constexpr size_t kSkLen = 1281;
constexpr size_t kSigMaxLen = 752;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  if (pk == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  std::memset(pk, 0x00, kPkLen);
  std::memset(sk, 0x00, kSkLen);
  pk[0] = 0x09;
  sk[0] = 0x59;
  for (size_t i = 1; i < kPkLen; ++i) {
    pk[i] = static_cast<uint8_t>(i * 7 + 3);
  }
  for (size_t i = 1; i < kSkLen; ++i) {
    sk[i] = static_cast<uint8_t>(i * 11 + 5);
  }
  return PQCFUZZ_OK;
}

pqcfuzz_status KeygenSeeded(uint8_t *pk, uint8_t *sk, const uint8_t *, size_t) {
  return Keygen(pk, sk);
}

pqcfuzz_status Sign(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *,
    size_t,
    const uint8_t *,
    const uint8_t *ctx,
    size_t ctx_len) {
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  if (sig == nullptr || sig_len == nullptr || *sig_len < 128) {
    return PQCFUZZ_INVALID_INPUT;
  }
  std::memset(sig, 0x00, *sig_len);
  sig[0] = 0x39;
  for (size_t i = 1; i < 41; ++i) {
    sig[i] = static_cast<uint8_t>(0x10 + i);
  }
  // A compressed payload of zero coefficients: each coefficient is
  // sign=0, low7=0, unary terminator=1 (nine bits), so 0x81 repeats.
  for (size_t i = 41; i < 617; ++i) {
    sig[i] = 0x81;
  }
  *sig_len = 617;
  return PQCFUZZ_OK;
}

pqcfuzz_status SignSeeded(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len,
    const uint8_t *,
    size_t) {
  return Sign(sig, sig_len, message, message_len, sk, ctx, ctx_len);
}

pqcfuzz_status AcceptVerify(
    const uint8_t *,
    size_t,
    const uint8_t *,
    size_t,
    const uint8_t *,
    const uint8_t *ctx,
    size_t ctx_len) {
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  return PQCFUZZ_OK;
}

}  // namespace

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_falcon_accepts_all_adapter() {
  static const pqcfuzz_sig_adapter adapter = {
      "falcon",
      "falcon_fake_accepts_all",
      "FALCON-512-COMPRESSED",
      kPkLen,
      kSkLen,
      kSigMaxLen,
      0,
      1,
      0,
      Keygen,
      Sign,
      AcceptVerify,
      SignSeeded,
      1,
      0,
      0,
      "fake-falcon",
      KeygenSeeded,
      nullptr,
      nullptr,
  };
  return &adapter;
}

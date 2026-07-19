#include "adapters/adapter_interface.h"
#include "adapters/rng_control.h"

#include <cstddef>
#include <cstdint>

namespace {

constexpr size_t kLength = 8;

void FillRandom(uint8_t *out, size_t length, uint8_t fallback) {
  if (!pqcfuzz_rng_fill_bytes(out, length)) {
    for (size_t i = 0; i < length; ++i) {
      out[i] = static_cast<uint8_t>(fallback + i * 17u);
    }
  }
}

uint8_t Fold(const uint8_t *data, size_t length, uint8_t initial) {
  uint8_t out = initial;
  for (size_t i = 0; i < length; ++i) {
    out = static_cast<uint8_t>((out << 1u) | (out >> 7u));
    out ^= data[i];
  }
  return out;
}

pqcfuzz_status KemKeygen(uint8_t *pk, uint8_t *sk) {
  FillRandom(pk, kLength, 0x31);
  for (size_t i = 0; i < kLength; ++i) {
    sk[i] = static_cast<uint8_t>(pk[i] ^ 0xa5u);
  }
  return PQCFUZZ_OK;
}

pqcfuzz_status KemEncaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
  uint8_t randomness[kLength];
  FillRandom(randomness, kLength, 0x53);
  for (size_t i = 0; i < kLength; ++i) {
    ct[i] = static_cast<uint8_t>(randomness[i] ^ pk[i]);
    ss[i] = static_cast<uint8_t>(ct[i] ^ pk[(i + 1) % kLength]);
  }
  return PQCFUZZ_OK;
}

pqcfuzz_status KemDecaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  for (size_t i = 0; i < kLength; ++i) {
    const uint8_t pk_next = static_cast<uint8_t>(sk[(i + 1) % kLength] ^ 0xa5u);
    ss[i] = static_cast<uint8_t>(ct[i] ^ pk_next);
  }
  return PQCFUZZ_OK;
}

pqcfuzz_status SigKeygen(uint8_t *pk, uint8_t *sk) {
  FillRandom(sk, kLength, 0x71);
  for (size_t i = 0; i < kLength; ++i) {
    pk[i] = static_cast<uint8_t>(sk[i] ^ 0xa5u);
  }
  return PQCFUZZ_OK;
}

uint8_t SignatureByte(
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len,
    uint8_t randomness) {
  uint8_t value = Fold(msg, msg_len, sk[0]);
  value = Fold(ctx, ctx_len, value);
  return static_cast<uint8_t>(value ^ randomness);
}

pqcfuzz_status SigSign(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len) {
  uint8_t randomness = 0;
  FillRandom(&randomness, 1, 0x91);
  const uint8_t value = SignatureByte(msg, msg_len, sk, ctx, ctx_len, randomness);
  for (size_t i = 0; i < kLength; ++i) {
    sig[i] = static_cast<uint8_t>(value + i * 13u);
  }
  *sig_len = kLength;
  return PQCFUZZ_OK;
}

pqcfuzz_status SigVerify(
    const uint8_t *sig,
    size_t sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *pk,
    const uint8_t *ctx,
    size_t ctx_len) {
  if (sig_len != kLength) {
    return PQCFUZZ_REJECT;
  }
  const uint8_t sk_first = static_cast<uint8_t>(pk[0] ^ 0xa5u);
  uint8_t value = Fold(msg, msg_len, sk_first);
  value = Fold(ctx, ctx_len, value);
  value ^= 0x91;
  for (size_t i = 0; i < kLength; ++i) {
    if (sig[i] != static_cast<uint8_t>(value + i * 13u)) {
      return PQCFUZZ_REJECT;
    }
  }
  return PQCFUZZ_OK;
}

}  // namespace

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_kem_oracle_contract_adapter() {
  static const pqcfuzz_kem_adapter adapter = {
      "fake", "fake_kem_oracle_contract", "ML-KEM-768", kLength, kLength, kLength, kLength,
      KemKeygen, KemEncaps, KemDecaps};
  return &adapter;
}

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_sig_oracle_contract_adapter() {
  static const pqcfuzz_sig_adapter adapter = {
      "fake", "fake_sig_oracle_contract", "ML-DSA-44", kLength, kLength, kLength,
      1, 0, 0, SigKeygen, SigSign, SigVerify, nullptr};
  return &adapter;
}

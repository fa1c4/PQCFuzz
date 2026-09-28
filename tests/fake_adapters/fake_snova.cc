// Deliberately broken SNOVA adapter used to prove that the negative oracles
// detect a wrong implementation.  It is linked INSTEAD of the real adapter
// (the getter symbols overlap), so a test never confuses the two.
//
// Profile assumed by tests: SNOVA-R2-24-5-16-4-AES with the expanded (ESK)
// private-key format.  verify() always accepts; keygen_from_sk() ignores the
// key length.

#include "adapters/snova/sig_adapter.h"

#include <cstring>
#include <vector>

namespace {

constexpr size_t kPkLen = 1016;
constexpr size_t kSkLen = 36848;
constexpr size_t kSigLen = 248;
constexpr size_t kHashBytes = 40;
constexpr size_t kExpandedLen = 36856;
constexpr size_t kPublicSeedBytes = 16;

void FillDeterministic(uint8_t *out, size_t out_len, const uint8_t *material, size_t material_len, uint8_t tag) {
  for (size_t i = 0; i < out_len; ++i) {
    uint8_t value = tag;
    for (size_t j = 0; j < material_len; ++j) {
      value = static_cast<uint8_t>(value * 31u + material[j] + static_cast<uint8_t>(i + j));
    }
    out[i] = value;
  }
}

pqcfuzz_status FakeKeygen(uint8_t *pk, uint8_t *sk) {
  const uint8_t seed[48] = {1};
  FillDeterministic(pk, kPkLen, seed, sizeof(seed), 0x11);
  FillDeterministic(sk, kSkLen, seed, sizeof(seed), 0x22);
  return PQCFUZZ_OK;
}

pqcfuzz_status FakeSign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk,
                        const uint8_t *ctx, size_t ctx_len) {
  (void)sk;
  (void)ctx;
  (void)ctx_len;
  if (*sig_len < kSigLen) {
    return PQCFUZZ_INVALID_INPUT;
  }
  FillDeterministic(sig, kSigLen, msg, msg_len, 0x33);
  *sig_len = kSigLen;
  return PQCFUZZ_OK;
}

pqcfuzz_status FakeVerify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk,
                          const uint8_t *ctx, size_t ctx_len) {
  (void)sig;
  (void)sig_len;
  (void)msg;
  (void)msg_len;
  (void)pk;
  (void)ctx;
  (void)ctx_len;
  return PQCFUZZ_OK;  // the bug: every signature is accepted
}

pqcfuzz_status FakeKeygenSeeded(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len) {
  FillDeterministic(pk, kPkLen, seed, seed_len, 0x11);
  FillDeterministic(sk, kSkLen, seed, seed_len, 0x22);
  return PQCFUZZ_OK;
}

pqcfuzz_status FakeSignSeeded(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk,
                              const uint8_t *ctx, size_t ctx_len, const uint8_t *seed, size_t seed_len) {
  (void)sk;
  (void)ctx;
  (void)ctx_len;
  (void)seed;
  (void)seed_len;
  if (*sig_len < kSigLen) {
    return PQCFUZZ_INVALID_INPUT;
  }
  FillDeterministic(sig, kSigLen, msg, msg_len, 0x33);
  *sig_len = kSigLen;
  return PQCFUZZ_OK;
}

pqcfuzz_status FakeSignDigest(uint8_t *sig, size_t *sig_len, const uint8_t *digest, size_t digest_len,
                              const uint8_t *sk, const uint8_t *salt) {
  (void)sk;
  (void)salt;
  if (*sig_len < kSigLen) {
    return PQCFUZZ_INVALID_INPUT;
  }
  FillDeterministic(sig, kSigLen, digest, digest_len, 0x33);
  *sig_len = kSigLen;
  return PQCFUZZ_OK;
}

pqcfuzz_status FakeVerifyDigest(const uint8_t *sig, size_t sig_len, const uint8_t *digest, size_t digest_len,
                                const uint8_t *pk) {
  (void)sig;
  (void)sig_len;
  (void)digest;
  (void)digest_len;
  (void)pk;
  return PQCFUZZ_OK;
}

pqcfuzz_status FakeKeygenFromSk(uint8_t *pk, const uint8_t *sk, size_t sk_len) {
  (void)sk_len;
  FillDeterministic(pk, kPkLen, sk, sk_len < 32 ? sk_len : 32, 0x11);
  return PQCFUZZ_OK;
}

void FakeExpandPublic(uint8_t *expanded_pk, const uint8_t *pk) {
  FillDeterministic(expanded_pk, kExpandedLen, pk, kPublicSeedBytes, 0x44);
}

const pqcfuzz_snova_api kFakeApi = {
    "fake_snova_esk",
    "SNOVA-R2-24-5-16-4-AES",
    "AES",
    "ESK",
    kPkLen,
    kSkLen,
    kSigLen,
    kSigLen - 16,
    kHashBytes,
    kExpandedLen,
    0,
    1,
    1,
    FakeSignDigest,
    FakeVerifyDigest,
    FakeKeygenFromSk,
    FakeExpandPublic,
};

const pqcfuzz_sig_adapter kFakeAdapter = {
    "snova",
    "fake_snova_esk",
    "SNOVA-R2-24-5-16-4-AES",
    kPkLen,
    kSkLen,
    kSigLen,
    0,
    1,
    0,
    FakeKeygen,
    FakeSign,
    FakeVerify,
    FakeSignSeeded,
    1,
    0,
    0,
    "fake",
    FakeKeygenSeeded,
};

}  // namespace

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_snova_sig_adapter(const char *implementation_id) {
  if (implementation_id != nullptr && std::strcmp(implementation_id, "fake_snova_esk") == 0) {
    return &kFakeAdapter;
  }
  return nullptr;
}

extern "C" const pqcfuzz_snova_api *pqcfuzz_get_snova_api(const char *implementation_id) {
  if (implementation_id != nullptr && std::strcmp(implementation_id, "fake_snova_esk") == 0) {
    return &kFakeApi;
  }
  return nullptr;
}

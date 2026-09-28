// PQClean Falcon clean adapter.
//
// PQClean wraps the same Falcon core as the author reference, so this lane is
// a same-source second build, never reported as an independent
// reimplementation.  PQClean namespaces every symbol with its own prefix, so
// both builds link into one binary without renaming.
#include "adapters/falcon/sig_adapter.h"

#ifdef PQCFUZZ_HAVE_FALCON_PQCLEAN

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "adapters/rng_control.h"
#include "adapters/status.h"

#ifndef PQCFUZZ_FALCON_PQCLEAN_API_HEADER
#define PQCFUZZ_FALCON_PQCLEAN_API_HEADER "api.h"
#endif
extern "C" {
#include PQCFUZZ_FALCON_PQCLEAN_API_HEADER
}

#ifndef PQCFUZZ_FALCON_PQCLEAN_KEYPAIR
#define PQCFUZZ_FALCON_PQCLEAN_KEYPAIR crypto_sign_keypair
#endif
#ifndef PQCFUZZ_FALCON_PQCLEAN_SIGN
#define PQCFUZZ_FALCON_PQCLEAN_SIGN crypto_sign_signature
#endif
#ifndef PQCFUZZ_FALCON_PQCLEAN_VERIFY
#define PQCFUZZ_FALCON_PQCLEAN_VERIFY crypto_sign_verify
#endif
#ifndef PQCFUZZ_FALCON_PQCLEAN_PUBLICKEYBYTES
#define PQCFUZZ_FALCON_PQCLEAN_PUBLICKEYBYTES CRYPTO_PUBLICKEYBYTES
#endif
#ifndef PQCFUZZ_FALCON_PQCLEAN_SECRETKEYBYTES
#define PQCFUZZ_FALCON_PQCLEAN_SECRETKEYBYTES CRYPTO_SECRETKEYBYTES
#endif
#ifndef PQCFUZZ_FALCON_PQCLEAN_BYTES
#define PQCFUZZ_FALCON_PQCLEAN_BYTES CRYPTO_BYTES
#endif
#ifndef PQCFUZZ_FALCON_PQCLEAN_ALGORITHM
#define PQCFUZZ_FALCON_PQCLEAN_ALGORITHM "FALCON-512-COMPRESSED"
#endif
#ifndef PQCFUZZ_FALCON_PQCLEAN_IMPLEMENTATION_ID
#define PQCFUZZ_FALCON_PQCLEAN_IMPLEMENTATION_ID "falcon_pqclean_512"
#endif

namespace {

constexpr size_t kPkLen = PQCFUZZ_FALCON_PQCLEAN_PUBLICKEYBYTES;
constexpr size_t kSkLen = PQCFUZZ_FALCON_PQCLEAN_SECRETKEYBYTES;
constexpr size_t kSigMaxLen = PQCFUZZ_FALCON_PQCLEAN_BYTES;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  if (pk == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  return PQCFUZZ_FALCON_PQCLEAN_KEYPAIR(pk, sk) == 0 ? PQCFUZZ_OK : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status Sign(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len) {
  if (sig == nullptr || sig_len == nullptr || sk == nullptr || (msg == nullptr && msg_len != 0)) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (ctx != nullptr && ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  return PQCFUZZ_FALCON_PQCLEAN_SIGN(sig, sig_len, msg, msg_len, sk) == 0 ? PQCFUZZ_OK
                                                                          : PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status Verify(
    const uint8_t *sig,
    size_t sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *pk,
    const uint8_t *ctx,
    size_t ctx_len) {
  if (sig == nullptr || pk == nullptr || (msg == nullptr && msg_len != 0)) {
    return PQCFUZZ_REJECT;
  }
  if (ctx != nullptr && ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  return PQCFUZZ_FALCON_PQCLEAN_VERIFY(sig, sig_len, msg, msg_len, pk) == 0 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
}

const pqcfuzz_sig_adapter kAdapter = {
    "falcon",
    PQCFUZZ_FALCON_PQCLEAN_IMPLEMENTATION_ID,
    PQCFUZZ_FALCON_PQCLEAN_ALGORITHM,
    kPkLen,
    kSkLen,
    kSigMaxLen,
    0,  // supports_context
    0,  // supports_seeded_sign (PQClean exposes no seeded API)
    0,  // supports_deterministic_sign
    &Keygen,
    &Sign,
    &Verify,
    nullptr,  // sign_seeded
    1,        // verify_checks_length
    0,
    0,
    "PQClean fc4f8e0 falcon clean (same Falcon core as the author reference)",
    nullptr,  // keygen_seeded
    nullptr,
    nullptr,
};

}  // namespace

// PQClean's randombytes.h macro maps every call to PQCLEAN_randombytes; the
// harness RNG control makes the build deterministic under a scoped tape and
// otherwise falls back to a fixed stream (never the system RNG in tests).
extern "C" int PQCLEAN_randombytes(uint8_t *out, size_t out_len) {
  if (out == nullptr) {
    return -1;
  }
  if (pqcfuzz::pqcfuzz_rng_is_active()) {
    if (!pqcfuzz_rng_fill_bytes(out, out_len)) {
      std::memset(out, 0, out_len);
      return -1;
    }
    return 0;
  }
  static uint64_t counter = 0x9e3779b97f4a7c15ull;
  for (size_t i = 0; i < out_len; ++i) {
    counter ^= counter << 13;
    counter ^= counter >> 7;
    counter ^= counter << 17;
    out[i] = static_cast<uint8_t>(counter + i);
  }
  return 0;
}

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_falcon_pqclean_sig_adapter() {
  return &kAdapter;
}

#else

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_falcon_pqclean_sig_adapter() {
  return nullptr;
}

#endif  // PQCFUZZ_HAVE_FALCON_PQCLEAN

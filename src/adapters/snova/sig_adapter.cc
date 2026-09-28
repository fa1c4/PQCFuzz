// SNOVA round-2 signature adapter.
//
// This translation unit is compiled once per (algorithm, backend) with:
//   -D v_SNOVA=<v> -D o_SNOVA=<o> -D l_SNOVA=<l>
//   -D PK_EXPAND_SHAKE=0|1 -D OPTIMISATION=0 -D FIXED_ABQ=2
//   -D PQCFUZZ_SNOVA_ALGORITHM="SNOVA-R2-..." 
//   -D PQCFUZZ_SNOVA_IMPLEMENTATION_BASE="snova_reference"
// Both the seed (SSK, 48 bytes) and expanded (ESK) private-key storage formats
// are registered from the same object as "<base>_ssk" / "<base>_esk" so an
// SSK-vs-ESK pair can be linked into one binary.  Builds without
// PQCFUZZ_HAVE_SNOVA return nullptr so routing fails visibly.

#include "adapters/snova/sig_adapter.h"

#include <cstring>
#include <random>
#include <vector>

#include "adapters/rng_control.h"

#ifdef PQCFUZZ_HAVE_SNOVA
#include "api.h"
#include "snova.h"
#include "deriv_params.h"
#endif

#ifndef PQCFUZZ_SNOVA_ALGORITHM
#define PQCFUZZ_SNOVA_ALGORITHM "SNOVA-R2-24-5-16-4-AES"
#endif

#ifndef PQCFUZZ_SNOVA_IMPLEMENTATION_BASE
#define PQCFUZZ_SNOVA_IMPLEMENTATION_BASE "snova_reference"
#endif

#ifdef PK_EXPAND_SHAKE
#if PK_EXPAND_SHAKE
#define PQCFUZZ_SNOVA_BACKEND "SHAKE"
#else
#define PQCFUZZ_SNOVA_BACKEND "AES"
#endif
#else
#define PQCFUZZ_SNOVA_BACKEND "SHAKE"
#endif

#ifdef PQCFUZZ_HAVE_SNOVA

namespace {

constexpr size_t kPublicSeedBytes = seed_length_public;
constexpr size_t kPrivateSeedBytes = seed_length_private;
constexpr size_t kSeedBytes = seed_length;
constexpr size_t kSignatureBytes = bytes_signature;
constexpr size_t kSaltBytes = bytes_salt;
constexpr size_t kEskBytes = bytes_sk;

enum class SkFormat { kSsk, kEsk };

size_t SkLenFor(SkFormat format) { return format == SkFormat::kSsk ? kSeedBytes : kEskBytes; }
const char *SkFormatName(SkFormat format) { return format == SkFormat::kSsk ? "SSK" : "ESK"; }

pqcfuzz_status FillRandom(uint8_t *out, size_t out_len) {
  if (pqcfuzz::pqcfuzz_rng_is_active()) {
    if (!pqcfuzz_rng_fill_bytes(out, out_len)) {
      std::memset(out, 0, out_len);
      return PQCFUZZ_INVALID_INPUT;
    }
    return PQCFUZZ_OK;
  }
  std::random_device device;
  for (size_t i = 0; i < out_len; ++i) {
    out[i] = static_cast<uint8_t>(device());
  }
  return PQCFUZZ_OK;
}

void MessageDigest(const uint8_t *message, size_t message_len, uint8_t out[64]) {
  shake256(message, static_cast<int>(message_len), out, 64);
}

void GenerateFromSeeds(SkFormat format, uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
  snova_init();
  if (format == SkFormat::kSsk) {
    generate_keys_ssk(pk, sk, seed, seed + kPublicSeedBytes);
  } else {
    generate_keys_esk(pk, sk, seed, seed + kPublicSeedBytes);
  }
}

pqcfuzz_status KeygenInternal(SkFormat format, uint8_t *pk, uint8_t *sk) {
  uint8_t seed[kSeedBytes];
  const pqcfuzz_status status = FillRandom(seed, sizeof(seed));
  if (status != PQCFUZZ_OK) {
    // Do not publish a key that was generated from an RNG failure.
    std::memset(pk, 0xA5, bytes_pk);
    std::memset(sk, 0xA5, SkLenFor(format));
    return status;
  }
  GenerateFromSeeds(format, pk, sk, seed);
  std::memset(seed, 0, sizeof(seed));
  return PQCFUZZ_OK;
}

pqcfuzz_status SignDigestInternal(SkFormat format, uint8_t *sig, size_t *sig_len, const uint8_t *digest,
                                  size_t digest_len, const uint8_t *sk, const uint8_t *salt) {
  if (sig == nullptr || sig_len == nullptr || digest == nullptr || sk == nullptr || salt == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (*sig_len < kSignatureBytes + kSaltBytes) {
    return PQCFUZZ_INVALID_INPUT;
  }
  snova_init();
  uint8_t mutable_salt[kSaltBytes];
  std::memcpy(mutable_salt, salt, kSaltBytes);
  if (format == SkFormat::kSsk) {
    sign_digest_ssk(sig, digest, digest_len, mutable_salt, sk);
  } else {
    sign_digest_esk(sig, digest, digest_len, mutable_salt, sk);
  }
  std::memset(mutable_salt, 0, sizeof(mutable_salt));
  *sig_len = kSignatureBytes + kSaltBytes;
  return PQCFUZZ_OK;
}

pqcfuzz_status SignInternal(SkFormat format, uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,
                            const uint8_t *sk, const uint8_t *ctx, size_t ctx_len) {
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  if (sig == nullptr || sig_len == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (msg == nullptr && msg_len != 0) {
    return PQCFUZZ_INVALID_INPUT;
  }
  uint8_t digest[64];
  MessageDigest(msg, msg_len, digest);
  uint8_t salt[kSaltBytes];
  const pqcfuzz_status status = FillRandom(salt, sizeof(salt));
  if (status != PQCFUZZ_OK) {
    return status;
  }
  const pqcfuzz_status result = SignDigestInternal(format, sig, sig_len, digest, sizeof(digest), sk, salt);
  std::memset(digest, 0, sizeof(digest));
  std::memset(salt, 0, sizeof(salt));
  return result;
}

pqcfuzz_status VerifySignature(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len,
                               const uint8_t *pk, const uint8_t *ctx, size_t ctx_len) {
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  if (sig == nullptr || pk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  // The reference API has no signature-length parameter; the pinned profile
  // fixes the signature at exactly CRYPTO_BYTES, so the adapter enforces it.
  if (sig_len != kSignatureBytes + kSaltBytes) {
    return PQCFUZZ_REJECT;
  }
  uint8_t digest[64];
  MessageDigest(msg, msg_len, digest);
  snova_init();
  const int result = verify_signture(digest, sizeof(digest), sig, pk);
  std::memset(digest, 0, sizeof(digest));
  return result == 0 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
}

pqcfuzz_status KeygenSeeded(SkFormat format, uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len) {
  if (pk == nullptr || sk == nullptr || seed == nullptr || seed_len != kSeedBytes) {
    return PQCFUZZ_INVALID_INPUT;
  }
  GenerateFromSeeds(format, pk, sk, seed);
  return PQCFUZZ_OK;
}

pqcfuzz_status SignSeeded(SkFormat format, uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,
                          const uint8_t *sk, const uint8_t *ctx, size_t ctx_len, const uint8_t *seed,
                          size_t seed_len) {
  if (ctx_len != 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  if (seed == nullptr || seed_len < kSaltBytes) {
    return PQCFUZZ_INVALID_INPUT;
  }
  uint8_t digest[64];
  MessageDigest(msg, msg_len, digest);
  const pqcfuzz_status result = SignDigestInternal(format, sig, sig_len, digest, sizeof(digest), sk, seed);
  std::memset(digest, 0, sizeof(digest));
  return result;
}

pqcfuzz_status VerifyDigest(const uint8_t *sig, size_t sig_len, const uint8_t *digest, size_t digest_len,
                            const uint8_t *pk) {
  if (sig == nullptr || digest == nullptr || pk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (sig_len != kSignatureBytes + kSaltBytes) {
    return PQCFUZZ_REJECT;
  }
  snova_init();
  return verify_signture(digest, digest_len, sig, pk) == 0 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
}

pqcfuzz_status KeygenFromSk(SkFormat format, uint8_t *pk, const uint8_t *sk, size_t sk_len) {
  if (pk == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (format == SkFormat::kSsk) {
    if (sk_len != kSeedBytes) {
      return PQCFUZZ_INVALID_INPUT;
    }
    snova_init();
    generate_pk_with_ssk(pk, sk);
  } else {
    if (sk_len != kEskBytes) {
      return PQCFUZZ_INVALID_INPUT;
    }
    snova_init();
    generate_pk_with_esk(pk, sk);
  }
  return PQCFUZZ_OK;
}

void ExpandPublic(uint8_t *expanded_pk, const uint8_t *pk) {
  if (expanded_pk == nullptr || pk == nullptr) {
    return;
  }
  snova_init();
  expand_public_pack(expanded_pk, pk);
}

const pqcfuzz_snova_api kSnovaApiSsk = {
    PQCFUZZ_SNOVA_IMPLEMENTATION_BASE "_ssk",
    PQCFUZZ_SNOVA_ALGORITHM,
    PQCFUZZ_SNOVA_BACKEND,
    "SSK",
    bytes_pk,
    kSeedBytes,
    kSignatureBytes + kSaltBytes,
    kSignatureBytes,
    bytes_hash,
    bytes_expend_pk,
    FIXED_ABQ ? 1 : 0,
    1,
    1,
    [](uint8_t *sig, size_t *sig_len, const uint8_t *digest, size_t digest_len, const uint8_t *sk,
       const uint8_t *salt) { return SignDigestInternal(SkFormat::kSsk, sig, sig_len, digest, digest_len, sk, salt); },
    VerifyDigest,
    [](uint8_t *pk, const uint8_t *sk, size_t sk_len) {
      return KeygenFromSk(SkFormat::kSsk, pk, sk, sk_len);
    },
    ExpandPublic,
};

const pqcfuzz_snova_api kSnovaApiEsk = {
    PQCFUZZ_SNOVA_IMPLEMENTATION_BASE "_esk",
    PQCFUZZ_SNOVA_ALGORITHM,
    PQCFUZZ_SNOVA_BACKEND,
    "ESK",
    bytes_pk,
    kEskBytes,
    kSignatureBytes + kSaltBytes,
    kSignatureBytes,
    bytes_hash,
    bytes_expend_pk,
    FIXED_ABQ ? 1 : 0,
    1,
    1,
    [](uint8_t *sig, size_t *sig_len, const uint8_t *digest, size_t digest_len, const uint8_t *sk,
       const uint8_t *salt) { return SignDigestInternal(SkFormat::kEsk, sig, sig_len, digest, digest_len, sk, salt); },
    VerifyDigest,
    [](uint8_t *pk, const uint8_t *sk, size_t sk_len) {
      return KeygenFromSk(SkFormat::kEsk, pk, sk, sk_len);
    },
    ExpandPublic,
};

pqcfuzz_status SskKeygen(uint8_t *pk, uint8_t *sk) { return KeygenInternal(SkFormat::kSsk, pk, sk); }
pqcfuzz_status EskKeygen(uint8_t *pk, uint8_t *sk) { return KeygenInternal(SkFormat::kEsk, pk, sk); }
pqcfuzz_status SskSign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk,
                       const uint8_t *ctx, size_t ctx_len) {
  return SignInternal(SkFormat::kSsk, sig, sig_len, msg, msg_len, sk, ctx, ctx_len);
}
pqcfuzz_status EskSign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk,
                       const uint8_t *ctx, size_t ctx_len) {
  return SignInternal(SkFormat::kEsk, sig, sig_len, msg, msg_len, sk, ctx, ctx_len);
}
pqcfuzz_status SskKeygenSeeded(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len) {
  return KeygenSeeded(SkFormat::kSsk, pk, sk, seed, seed_len);
}
pqcfuzz_status EskKeygenSeeded(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len) {
  return KeygenSeeded(SkFormat::kEsk, pk, sk, seed, seed_len);
}
pqcfuzz_status SskSignSeeded(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk,
                             const uint8_t *ctx, size_t ctx_len, const uint8_t *seed, size_t seed_len) {
  return SignSeeded(SkFormat::kSsk, sig, sig_len, msg, msg_len, sk, ctx, ctx_len, seed, seed_len);
}
pqcfuzz_status EskSignSeeded(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk,
                             const uint8_t *ctx, size_t ctx_len, const uint8_t *seed, size_t seed_len) {
  return SignSeeded(SkFormat::kEsk, sig, sig_len, msg, msg_len, sk, ctx, ctx_len, seed, seed_len);
}

const pqcfuzz_sig_adapter kSnovaAdapterSsk = {
    "snova",
    PQCFUZZ_SNOVA_IMPLEMENTATION_BASE "_ssk",
    PQCFUZZ_SNOVA_ALGORITHM,
    bytes_pk,
    kSeedBytes,
    kSignatureBytes + kSaltBytes,
    0,  // supports_context
    1,  // supports_seeded_sign
    0,  // supports_deterministic_sign
    SskKeygen,
    SskSign,
    VerifySignature,
    SskSignSeeded,
    1,  // verify_checks_length (adapter enforces the fixed ABI length)
    0,  // sign_accepts_extended_context
    0,  // verify_accepts_extended_context
    "nist-round2-13182903755ade177e02d1fea77f0bd2e1e1a280",
    SskKeygenSeeded,
};

const pqcfuzz_sig_adapter kSnovaAdapterEsk = {
    "snova",
    PQCFUZZ_SNOVA_IMPLEMENTATION_BASE "_esk",
    PQCFUZZ_SNOVA_ALGORITHM,
    bytes_pk,
    kEskBytes,
    kSignatureBytes + kSaltBytes,
    0,  // supports_context
    1,  // supports_seeded_sign
    0,  // supports_deterministic_sign
    EskKeygen,
    EskSign,
    VerifySignature,
    EskSignSeeded,
    1,  // verify_checks_length (adapter enforces the fixed ABI length)
    0,  // sign_accepts_extended_context
    0,  // verify_accepts_extended_context
    "nist-round2-13182903755ade177e02d1fea77f0bd2e1e1a280",
    EskKeygenSeeded,
};

}  // namespace

#endif  // PQCFUZZ_HAVE_SNOVA

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_snova_sig_adapter(const char *implementation_id) {
#ifdef PQCFUZZ_HAVE_SNOVA
  if (implementation_id != nullptr) {
    if (std::strcmp(implementation_id, PQCFUZZ_SNOVA_IMPLEMENTATION_BASE "_ssk") == 0) {
      return &kSnovaAdapterSsk;
    }
    if (std::strcmp(implementation_id, PQCFUZZ_SNOVA_IMPLEMENTATION_BASE "_esk") == 0) {
      return &kSnovaAdapterEsk;
    }
  }
#else
  (void)implementation_id;
#endif
  return nullptr;
}

extern "C" const pqcfuzz_snova_api *pqcfuzz_get_snova_api(const char *implementation_id) {
#ifdef PQCFUZZ_HAVE_SNOVA
  if (implementation_id != nullptr) {
    if (std::strcmp(implementation_id, PQCFUZZ_SNOVA_IMPLEMENTATION_BASE "_ssk") == 0) {
      return &kSnovaApiSsk;
    }
    if (std::strcmp(implementation_id, PQCFUZZ_SNOVA_IMPLEMENTATION_BASE "_esk") == 0) {
      return &kSnovaApiEsk;
    }
  }
#else
  (void)implementation_id;
#endif
  return nullptr;
}

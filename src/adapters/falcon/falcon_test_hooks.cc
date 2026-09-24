#include "adapters/falcon/falcon_test_hooks.h"

#ifdef PQCFUZZ_HAVE_FALCON

#include <cstring>
#include <vector>

#include "falcon.h"

// inner.h is a C99 header compiled as part of the C reference; wrap it so the
// falcon_inner_* symbols keep C linkage for the C++ test hooks.
#ifndef restrict
#define restrict __restrict__
#endif
extern "C" {
#include "inner.h"
}

namespace pqcfuzz {
namespace falcon_test {
namespace {

bool ValidLogn(unsigned logn) {
  return logn >= 9 && logn <= 10;
}

}  // namespace

bool HookCompDecode(
    const uint8_t *payload,
    size_t payload_len,
    unsigned logn,
    std::vector<int16_t> *coefficients,
    size_t *consumed_bytes) {
  if (payload == nullptr || coefficients == nullptr || !ValidLogn(logn)) {
    return false;
  }
  const size_t n = static_cast<size_t>(1) << logn;
  std::vector<int16_t> out(n, 0);
  size_t v = 0;
  if (logn == 9) {
    v = Zf(comp_decode)(out.data(), logn, payload, payload_len);
  } else {
    v = Zf(comp_decode)(out.data(), logn, payload, payload_len);
  }
  if (v == 0) {
    return false;
  }
  *coefficients = std::move(out);
  if (consumed_bytes != nullptr) {
    *consumed_bytes = v;
  }
  return true;
}

bool HookCompEncode(const std::vector<int16_t> &coefficients, unsigned logn, std::vector<uint8_t> *payload) {
  if (payload == nullptr || !ValidLogn(logn)) {
    return false;
  }
  const size_t n = static_cast<size_t>(1) << logn;
  if (coefficients.size() != n) {
    return false;
  }
  std::vector<uint8_t> out(FALCON_SIG_COMPRESSED_MAXSIZE(logn));
  const size_t written = Zf(comp_encode)(out.data(), out.size(), coefficients.data(), logn);
  if (written == 0) {
    return false;
  }
  out.resize(written);
  *payload = std::move(out);
  return true;
}

bool HookTrimDecode(
    const uint8_t *payload,
    size_t payload_len,
    unsigned logn,
    std::vector<int16_t> *coefficients) {
  if (payload == nullptr || coefficients == nullptr || !ValidLogn(logn)) {
    return false;
  }
  const size_t n = static_cast<size_t>(1) << logn;
  std::vector<int16_t> out(n, 0);
  if (Zf(trim_i16_decode)(out.data(), logn, Zf(max_sig_bits)[logn], payload, payload_len) == 0) {
    return false;
  }
  *coefficients = std::move(out);
  return true;
}

bool HookHashToPoint(
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *message,
    size_t message_len,
    unsigned logn,
    std::vector<uint16_t> *coefficients) {
  if (coefficients == nullptr || !ValidLogn(logn) || (salt == nullptr && salt_len != 0) ||
      (message == nullptr && message_len != 0)) {
    return false;
  }
  const size_t n = static_cast<size_t>(1) << logn;
  std::vector<uint16_t> out(n, 0);
  shake256_context hash_data;
  shake256_init(&hash_data);
  shake256_inject(&hash_data, salt, salt_len);
  shake256_inject(&hash_data, message, message_len);
  shake256_flip(&hash_data);
  Zf(hash_to_point_vartime)((inner_shake256_context *)&hash_data, out.data(), logn);
  *coefficients = std::move(out);
  return true;
}

bool HookKeygenFromSeed(
    const uint8_t seed[48],
    unsigned logn,
    std::vector<uint8_t> *public_key,
    std::vector<uint8_t> *secret_key) {
  if (seed == nullptr || public_key == nullptr || secret_key == nullptr || !ValidLogn(logn)) {
    return false;
  }
  shake256_context rng;
  shake256_init(&rng);
  shake256_inject(&rng, seed, 48);
  shake256_flip(&rng);
  std::vector<uint8_t> pk(FALCON_PUBKEY_SIZE(logn));
  std::vector<uint8_t> sk(FALCON_PRIVKEY_SIZE(logn));
  std::vector<uint8_t> tmp(FALCON_TMPSIZE_KEYGEN(logn));
  if (falcon_keygen_make(&rng, logn, sk.data(), sk.size(), pk.data(), pk.size(), tmp.data(), tmp.size()) != 0) {
    return false;
  }
  *public_key = std::move(pk);
  *secret_key = std::move(sk);
  return true;
}

bool HookSignFromSeed(
    const uint8_t seed[48],
    unsigned logn,
    const uint8_t *secret_key,
    const uint8_t *message,
    size_t message_len,
    int sig_type,
    std::vector<uint8_t> *signature) {
  if (seed == nullptr || secret_key == nullptr || signature == nullptr || !ValidLogn(logn) ||
      (message == nullptr && message_len != 0)) {
    return false;
  }
  const size_t capacity = sig_type == FALCON_SIG_PADDED
                              ? FALCON_SIG_PADDED_SIZE(logn)
                              : (sig_type == FALCON_SIG_CT ? FALCON_SIG_CT_SIZE(logn)
                                                           : FALCON_SIG_COMPRESSED_MAXSIZE(logn));
  std::vector<uint8_t> out(capacity);
  size_t sig_len = capacity;
  shake256_context rng;
  shake256_init(&rng);
  shake256_inject(&rng, seed, 48);
  shake256_flip(&rng);
  std::vector<uint8_t> tmp(FALCON_TMPSIZE_SIGNDYN(logn));
  if (falcon_sign_dyn(&rng, out.data(), &sig_len, sig_type, secret_key, FALCON_PRIVKEY_SIZE(logn), message, message_len,
                      tmp.data(), tmp.size()) != 0) {
    return false;
  }
  out.resize(sig_len);
  *signature = std::move(out);
  return true;
}

bool HookCompletePrivate(
    const uint8_t *secret_key,
    unsigned logn,
    std::vector<int8_t> *f,
    std::vector<int8_t> *g,
    std::vector<int8_t> *F,
    std::vector<int8_t> *G) {
  if (secret_key == nullptr || f == nullptr || g == nullptr || F == nullptr || G == nullptr || !ValidLogn(logn)) {
    return false;
  }
  const size_t n = static_cast<size_t>(1) << logn;
  std::vector<int8_t> out_f(n), out_g(n), out_F(n), out_G(n);
  std::vector<uint8_t> tmp(FALCON_TMPSIZE_KEYGEN(logn));
  size_t u = 1;
  size_t v = Zf(trim_i8_decode)(out_f.data(), logn, Zf(max_fg_bits)[logn], secret_key + u,
                                FALCON_PRIVKEY_SIZE(logn) - u);
  if (v == 0) {
    return false;
  }
  u += v;
  v = Zf(trim_i8_decode)(out_g.data(), logn, Zf(max_fg_bits)[logn], secret_key + u, FALCON_PRIVKEY_SIZE(logn) - u);
  if (v == 0) {
    return false;
  }
  u += v;
  v = Zf(trim_i8_decode)(out_F.data(), logn, Zf(max_FG_bits)[logn], secret_key + u, FALCON_PRIVKEY_SIZE(logn) - u);
  if (v == 0) {
    return false;
  }
  u += v;
  if (u != FALCON_PRIVKEY_SIZE(logn)) {
    return false;
  }
  if (!Zf(complete_private)(out_G.data(), out_f.data(), out_g.data(), out_F.data(), logn, tmp.data())) {
    return false;
  }
  *f = std::move(out_f);
  *g = std::move(out_g);
  *F = std::move(out_F);
  *G = std::move(out_G);
  return true;
}

bool HookVerify(
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *public_key,
    int sig_type) {
  if (signature == nullptr || public_key == nullptr || (message == nullptr && message_len != 0)) {
    return false;
  }
  const int logn = public_key[0] & 0x0F;
  if (!ValidLogn(static_cast<unsigned>(logn))) {
    return false;
  }
  std::vector<uint8_t> tmp(FALCON_TMPSIZE_VERIFY(logn));
  return falcon_verify(signature, signature_len, sig_type, public_key, FALCON_PUBKEY_SIZE(logn), message, message_len,
                       tmp.data(), tmp.size()) == 0;
}

}  // namespace falcon_test
}  // namespace pqcfuzz

#endif  // PQCFUZZ_HAVE_FALCON

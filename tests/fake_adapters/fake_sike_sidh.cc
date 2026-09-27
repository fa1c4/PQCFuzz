// Test-only SIKE/SIDH adapters.  They implement a self-consistent pseudo-
// isogeny algebra (SHAKE-based) so the oracle executor's independent gate
// model can classify candidates, plus configurable mutants that must be
// detected by sike_reencryption_gate, sike_fallback_exact and
// sike_fallback_seed_separation.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "adapters/adapter_interface.h"
#include "adapters/kex_adapter_interface.h"
#include "adapters/rng_control.h"
#include "adapters/sike/reference_adapter.h"
#include "adapters/status.h"
#include "mutators/sha3.h"
#include "mutators/sike_layout.h"

namespace {

enum class FakeMode {
  kHonest = 0,
  kIgnoreGate = 1,
  kAlwaysFallback = 2,
  kDropC1 = 3,
};

pqcfuzz_kem_adapter g_sike = {
    "sike",
    "sike_fake",
    "SIKE-p434",
    0,
    0,
    0,
    16,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    "fake-sike",
};

pqcfuzz_kex_adapter g_sidh = {
    "sidh",
    "sidh_fake",
    "SIDH-p434",
    0,
    0,
    0,
    0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    0,
    0,
    "fake-sidh",
};

FakeMode g_mode = FakeMode::kHonest;
bool g_sidh_broken = false;
size_t g_sike_nsk2 = 16;
size_t g_sidh_bbits = 217;

std::vector<uint8_t> FakeHash(const std::vector<uint8_t> &input, size_t out_len) {
  return pqcfuzz::Shake256(input, out_len);
}

std::vector<uint8_t> Concat(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
  std::vector<uint8_t> out = a;
  out.insert(out.end(), b.begin(), b.end());
  return out;
}

std::vector<uint8_t> FakePk(const std::vector<uint8_t> &scalar, size_t pk_len) {
  return FakeHash(Concat(scalar, {'p', 'k'}), pk_len);
}

std::vector<uint8_t> FakeJ(const std::vector<uint8_t> &c0, size_t out_len) {
  return FakeHash(Concat(c0, {'j'}), out_len);
}

std::vector<uint8_t> FakeIsogen2(const std::vector<uint8_t> &scalar, size_t pk_len) {
  return FakeHash(Concat(scalar, {'2'}), pk_len);
}

void FillRandom(uint8_t *out, size_t out_len) {
  if (pqcfuzz_rng_fill_bytes(out, out_len)) {
    return;
  }
  static uint64_t counter = 0x243f6a8885a308d3ull;
  for (size_t i = 0; i < out_len; ++i) {
    counter ^= counter << 13;
    counter ^= counter >> 7;
    counter ^= counter << 17;
    out[i] = static_cast<uint8_t>(counter + i);
  }
}

pqcfuzz_status SikeKeygen(uint8_t *pk, uint8_t *sk) {
  if (pk == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  const size_t msg = g_sike.ss_len;
  const size_t split = g_sike.sk_len - g_sike.pk_len;
  std::vector<uint8_t> sk3(split - msg, 0);
  FillRandom(sk3.data(), sk3.size());
  FillRandom(sk, msg);
  std::memcpy(sk + msg, sk3.data(), sk3.size());
  const std::vector<uint8_t> pk3 = FakePk(sk3, g_sike.pk_len);
  std::memcpy(sk + split, pk3.data(), pk3.size());
  std::memcpy(pk, pk3.data(), pk3.size());
  return PQCFUZZ_OK;
}

pqcfuzz_status SikeKeygenDerand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
  if (pk == nullptr || sk == nullptr || coins == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  const size_t msg = g_sike.ss_len;
  const size_t split = g_sike.sk_len - g_sike.pk_len;
  const size_t sk3_len = split - msg;
  std::memcpy(sk, coins, msg);
  std::memcpy(sk + msg, coins + msg, sk3_len);
  std::vector<uint8_t> sk3(sk + msg, sk + msg + sk3_len);
  const std::vector<uint8_t> pk3 = FakePk(sk3, g_sike.pk_len);
  std::memcpy(sk + split, pk3.data(), pk3.size());
  std::memcpy(pk, pk3.data(), pk3.size());
  return PQCFUZZ_OK;
}

pqcfuzz_status SikeEncaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
  if (ct == nullptr || ss == nullptr || pk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  const size_t msg = g_sike.ss_len;
  const size_t pk_len = g_sike.pk_len;
  std::vector<uint8_t> pk_bytes(pk, pk + pk_len);
  const std::vector<uint8_t> m = FakeHash(Concat(pk_bytes, {'m'}), msg);
  const std::vector<uint8_t> r = FakeHash(Concat(m, pk_bytes), g_sike_nsk2);
  const std::vector<uint8_t> c0 = FakeIsogen2(r, pk_len);
  std::memcpy(ct, c0.data(), c0.size());
  const std::vector<uint8_t> j = FakeJ(c0, 2 * (pk_len / 6));
  const std::vector<uint8_t> h = FakeHash(j, msg);
  for (size_t i = 0; i < msg; ++i) {
    ct[pk_len + i] = static_cast<uint8_t>(m[i] ^ h[i]);
  }
  std::vector<uint8_t> material = m;
  material.insert(material.end(), ct, ct + pk_len + msg);
  const std::vector<uint8_t> secret = FakeHash(material, g_sike.ss_len);
  std::memcpy(ss, secret.data(), secret.size());
  return PQCFUZZ_OK;
}

pqcfuzz_status SikeEncapsDerand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {
  if (coins == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  // Force m to the first ss_len coins bytes and recompute c0 consistently.
  const size_t msg = g_sike.ss_len;
  const size_t pk_len = g_sike.pk_len;
  std::vector<uint8_t> pk_bytes(pk, pk + pk_len);
  std::vector<uint8_t> m(coins, coins + msg);
  const std::vector<uint8_t> r = FakeHash(Concat(m, pk_bytes), g_sike_nsk2);
  const std::vector<uint8_t> c0 = FakeIsogen2(r, pk_len);
  std::memcpy(ct, c0.data(), c0.size());
  const std::vector<uint8_t> j = FakeJ(c0, 2 * (pk_len / 6));
  const std::vector<uint8_t> h = FakeHash(j, msg);
  for (size_t i = 0; i < msg; ++i) {
    ct[pk_len + i] = static_cast<uint8_t>(m[i] ^ h[i]);
  }
  std::vector<uint8_t> material = m;
  material.insert(material.end(), ct, ct + pk_len + msg);
  const std::vector<uint8_t> secret = FakeHash(material, msg);
  std::memcpy(ss, secret.data(), secret.size());
  return PQCFUZZ_OK;
}

pqcfuzz_status SikeDecaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  if (ss == nullptr || ct == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  const size_t msg = g_sike.ss_len;
  const size_t pk_len = g_sike.pk_len;
  const size_t split = g_sike.sk_len - pk_len;
  std::vector<uint8_t> s(sk, sk + msg);
  std::vector<uint8_t> pk3(sk + split, sk + g_sike.sk_len);
  std::vector<uint8_t> c0(ct, ct + pk_len);
  std::vector<uint8_t> c1(ct + pk_len, ct + pk_len + msg);
  const std::vector<uint8_t> j = FakeJ(c0, 2 * (pk_len / 6));
  const std::vector<uint8_t> h = FakeHash(j, msg);
  std::vector<uint8_t> m(msg, 0);
  for (size_t i = 0; i < msg; ++i) {
    m[i] = static_cast<uint8_t>(c1[i] ^ h[i]);
  }
  const std::vector<uint8_t> r = FakeHash(Concat(m, pk3), g_sike_nsk2);
  const std::vector<uint8_t> c0_prime = FakeIsogen2(r, pk_len);
  bool gate = c0_prime == c0;
  if (g_mode == FakeMode::kIgnoreGate) {
    gate = true;
  } else if (g_mode == FakeMode::kAlwaysFallback) {
    gate = false;
  }
  std::vector<uint8_t> prefix = gate ? m : s;
  if (g_mode == FakeMode::kDropC1) {
    // H input omits c1: deliberately broken.
    const std::vector<uint8_t> secret = FakeHash(prefix, msg);
    std::memcpy(ss, secret.data(), secret.size());
    return PQCFUZZ_OK;
  }
  prefix.insert(prefix.end(), ct, ct + pk_len + msg);
  const std::vector<uint8_t> secret = FakeHash(prefix, msg);
  std::memcpy(ss, secret.data(), secret.size());
  return PQCFUZZ_OK;
}

pqcfuzz_status SidhKeygenA(uint8_t *pk, uint8_t *sk);
pqcfuzz_status SidhKeygenB(uint8_t *pk, uint8_t *sk);

pqcfuzz_status SidhKeygenA(uint8_t *pk, uint8_t *sk) {
  if (pk == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  FillRandom(sk, g_sidh.sk_a_len);
  std::vector<uint8_t> scalar(sk, sk + g_sidh.sk_a_len);
  const std::vector<uint8_t> public_key = FakePk(scalar, g_sidh.pk_len);
  std::memcpy(pk, public_key.data(), public_key.size());
  return PQCFUZZ_OK;
}

pqcfuzz_status SidhKeygenB(uint8_t *pk, uint8_t *sk) {
  if (pk == nullptr || sk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  FillRandom(sk, g_sidh.sk_b_len);
  const size_t remainder = g_sidh_bbits % 8;
  if (g_sidh_bbits > 0 && remainder != 0) {
    sk[g_sidh.sk_b_len - 1] &= static_cast<uint8_t>((1u << remainder) - 1u);
  }
  std::vector<uint8_t> scalar(sk, sk + g_sidh.sk_b_len);
  const std::vector<uint8_t> public_key = FakePk(scalar, g_sidh.pk_len);
  std::memcpy(pk, public_key.data(), public_key.size());
  return PQCFUZZ_OK;
}

pqcfuzz_status SidhDeriveA(uint8_t *shared, const uint8_t *peer_pk_b, const uint8_t *own_sk_a) {
  if (shared == nullptr || peer_pk_b == nullptr || own_sk_a == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  std::vector<uint8_t> own(own_sk_a, own_sk_a + g_sidh.sk_a_len);
  std::vector<uint8_t> peer(peer_pk_b, peer_pk_b + g_sidh.pk_len);
  std::vector<uint8_t> own_pk = FakePk(own, g_sidh.pk_len);
  for (size_t i = 0; i < own_pk.size(); ++i) {
    own_pk[i] ^= peer[i];
  }
  const std::vector<uint8_t> out = FakeHash(own_pk, g_sidh.shared_len);
  std::memcpy(shared, out.data(), out.size());
  return PQCFUZZ_OK;
}

pqcfuzz_status SidhDeriveB(uint8_t *shared, const uint8_t *peer_pk_a, const uint8_t *own_sk_b) {
  if (shared == nullptr || peer_pk_a == nullptr || own_sk_b == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  std::vector<uint8_t> own(own_sk_b, own_sk_b + g_sidh.sk_b_len);
  std::vector<uint8_t> peer(peer_pk_a, peer_pk_a + g_sidh.pk_len);
  std::vector<uint8_t> own_pk = FakePk(own, g_sidh.pk_len);
  if (g_sidh_broken) {
    own_pk.push_back(0x5A);
  }
  for (size_t i = 0; i < own_pk.size() && i < peer.size(); ++i) {
    own_pk[i] ^= peer[i];
  }
  const std::vector<uint8_t> out = FakeHash(own_pk, g_sidh.shared_len);
  std::memcpy(shared, out.data(), out.size());
  return PQCFUZZ_OK;
}

pqcfuzz_status SidhKeygenAScalar(uint8_t *pk, const uint8_t *scalar) {
  if (pk == nullptr || scalar == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  std::vector<uint8_t> s(scalar, scalar + g_sidh.sk_a_len);
  const std::vector<uint8_t> public_key = FakePk(s, g_sidh.pk_len);
  std::memcpy(pk, public_key.data(), public_key.size());
  return PQCFUZZ_OK;
}

pqcfuzz_status SidhKeygenBScalar(uint8_t *pk, const uint8_t *scalar) {
  if (pk == nullptr || scalar == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  std::vector<uint8_t> s(scalar, scalar + g_sidh.sk_b_len);
  const std::vector<uint8_t> public_key = FakePk(s, g_sidh.pk_len);
  std::memcpy(pk, public_key.data(), public_key.size());
  return PQCFUZZ_OK;
}

// Fake reference hooks consistent with the adapter's pseudo algebra.
pqcfuzz_status FakePkeJ(uint8_t *j_out, size_t j_len, const uint8_t *, size_t, const uint8_t *c0, size_t c0_len) {
  if (j_out == nullptr || c0 == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  std::vector<uint8_t> c0_bytes(c0, c0 + c0_len);
  const std::vector<uint8_t> j = FakeJ(c0_bytes, j_len);
  std::memcpy(j_out, j.data(), j.size());
  return PQCFUZZ_OK;
}

pqcfuzz_status FakeIsogen2Hook(uint8_t *pk_out, size_t pk_len, const uint8_t *scalar, size_t scalar_len) {
  if (pk_out == nullptr || scalar == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  std::vector<uint8_t> scalar_bytes(scalar, scalar + scalar_len);
  const std::vector<uint8_t> pk = FakeIsogen2(scalar_bytes, pk_len);
  std::memcpy(pk_out, pk.data(), pk.size());
  return PQCFUZZ_OK;
}

pqcfuzz_status FakeIsogen3Hook(uint8_t *pk_out, size_t pk_len, const uint8_t *scalar, size_t scalar_len) {
  if (pk_out == nullptr || scalar == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  std::vector<uint8_t> scalar_bytes(scalar, scalar + scalar_len);
  const std::vector<uint8_t> pk = FakePk(scalar_bytes, pk_len);
  std::memcpy(pk_out, pk.data(), pk.size());
  return PQCFUZZ_OK;
}

const pqcfuzz::sike_reference::SikeReferenceHooks kFakeHooks = {
    FakePkeJ,
    FakeIsogen2Hook,
    FakeIsogen3Hook,
};

}  // namespace

extern "C" pqcfuzz::sike_reference::SikeReferenceHooks *pqcfuzz_fake_hooks() {
  return const_cast<pqcfuzz::sike_reference::SikeReferenceHooks *>(&kFakeHooks);
}

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_sike_adapter() {
  return &g_sike;
}

extern "C" const pqcfuzz_kex_adapter *pqcfuzz_fake_sidh_adapter() {
  return &g_sidh;
}

extern "C" void pqcfuzz_fake_sike_configure(
    const char *algorithm,
    size_t pk_len,
    size_t sk_len,
    size_t ct_len,
    size_t ss_len,
    size_t e2,
    int mode) {
  g_sike.algorithm = algorithm;
  g_sike_nsk2 = (e2 + 7) / 8;
  g_sike.pk_len = pk_len;
  g_sike.sk_len = sk_len;
  g_sike.ct_len = ct_len;
  g_sike.ss_len = ss_len;
  g_sike.keygen = SikeKeygen;
  g_sike.keygen_derand = SikeKeygenDerand;
  g_sike.encaps = SikeEncaps;
  g_sike.encaps_derand = SikeEncapsDerand;
  g_sike.decaps = SikeDecaps;
  g_mode = static_cast<FakeMode>(mode);
}

extern "C" void pqcfuzz_fake_sidh_set_broken(int broken) {
  g_sidh_broken = broken != 0;
}

extern "C" void pqcfuzz_fake_sidh_configure(
    const char *algorithm,
    size_t pk_len,
    size_t sk_a_len,
    size_t sk_b_len,
    size_t shared_len,
    size_t e3) {
  g_sidh.algorithm = algorithm;
  if (e3 > 0) {
    size_t sbits = 0;
    pqcfuzz::ComputeSikeBobScalarBits(e3, &sbits);
    g_sidh_bbits = sbits;
  }
  g_sidh.pk_len = pk_len;
  g_sidh.sk_a_len = sk_a_len;
  g_sidh.sk_b_len = sk_b_len;
  g_sidh.shared_len = shared_len;
  g_sidh.keygen_a = SidhKeygenA;
  g_sidh.keygen_b = SidhKeygenB;
  g_sidh.derive_a = SidhDeriveA;
  g_sidh.derive_b = SidhDeriveB;
  g_sidh.keygen_a_scalar = SidhKeygenAScalar;
  g_sidh.keygen_b_scalar = SidhKeygenBScalar;
  g_sidh.keygen_a_rng_bytes = sk_a_len;
  g_sidh.keygen_b_rng_bytes = sk_b_len;
}

// The test fake replaces the real reference hooks in the fake-adapter lane.
namespace pqcfuzz {
namespace sike_reference {

const SikeReferenceHooks *GetSikeReferenceHooks() {
  return &kFakeHooks;
}

}  // namespace sike_reference
}  // namespace pqcfuzz

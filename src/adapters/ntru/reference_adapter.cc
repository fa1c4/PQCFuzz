#include "adapters/ntru/reference_adapter.h"

#ifdef PQCFUZZ_HAVE_NTRU_REFERENCE

#include <cstring>

extern "C" {
#include "crypto_hash_sha3256.h"
#include "owcpa.h"
#include "params.h"
#include "poly.h"
#include "sample.h"
}

namespace pqcfuzz {
namespace ntru_reference {
namespace {

uint16_t ModQ(uint16_t value) {
  value &= 2 * NTRU_Q - 1;
  value -= NTRU_Q;
  value += (value >> 15) & NTRU_Q;
  return value;
}

int CheckCiphertextPadding(const uint8_t *ciphertext) {
  uint16_t t = ciphertext[NTRU_CIPHERTEXTBYTES - 1];
  t &= static_cast<uint16_t>(0xFFu << (8 - (7 & (NTRU_LOGQ * NTRU_PACK_DEG))));
  return (1 & ((~t + 1) >> 15));
}

int CheckR(const poly *r) {
  uint32_t t = 0;
  for (int i = 0; i < NTRU_N - 1; ++i) {
    const uint16_t c = r->coeffs[i];
    t |= (c + 1) & (NTRU_Q - 4);
    t |= (c + 2) & 4;
  }
  t |= r->coeffs[NTRU_N - 1];
  return static_cast<int>(1 & ((~t + 1) >> 31));
}

int CheckM(const poly *m) {
#ifdef NTRU_HPS
  uint32_t t = 0;
  uint16_t ps = 0;
  uint16_t ms = 0;
  for (int i = 0; i < NTRU_N; ++i) {
    ps += m->coeffs[i] & 1;
    ms += m->coeffs[i] & 2;
  }
  t |= ps ^ (ms >> 1);
  t |= ms ^ NTRU_WEIGHT;
  return static_cast<int>(1 & ((~t + 1) >> 31));
#else
  (void)m;
  return 0;
#endif
}

}  // namespace

bool IsHps() {
#ifdef NTRU_HPS
  return true;
#else
  return false;
#endif
}

bool SeedKeypair(
    const uint8_t *seed,
    size_t seed_len,
    std::vector<uint8_t> *public_key,
    std::vector<uint8_t> *secret_key) {
  if (seed == nullptr || public_key == nullptr || secret_key == nullptr || seed_len != NTRU_SAMPLE_FG_BYTES) {
    return false;
  }
  public_key->assign(NTRU_PUBLICKEYBYTES, 0);
  std::vector<uint8_t> sk(NTRU_OWCPA_SECRETKEYBYTES);
  owcpa_keypair(public_key->data(), sk.data(), seed);
  *secret_key = std::move(sk);
  return true;
}

bool SeedEncaps(
    const uint8_t *seed,
    size_t seed_len,
    const uint8_t *public_key,
    size_t public_key_len,
    std::vector<uint8_t> *ciphertext,
    std::vector<uint8_t> *shared_secret) {
  if (seed == nullptr || public_key == nullptr || ciphertext == nullptr || shared_secret == nullptr ||
      seed_len != NTRU_SAMPLE_RM_BYTES || public_key_len != NTRU_PUBLICKEYBYTES) {
    return false;
  }
  poly r;
  poly m;
  sample_rm(&r, &m, seed);
  std::vector<uint8_t> rm(NTRU_OWCPA_MSGBYTES);
  poly_S3_tobytes(rm.data(), &r);
  poly_S3_tobytes(rm.data() + NTRU_PACK_TRINARY_BYTES, &m);
  shared_secret->assign(NTRU_SHAREDKEYBYTES, 0);
  crypto_hash_sha3256(shared_secret->data(), rm.data(), rm.size());
  poly_Z3_to_Zq(&r);
  ciphertext->assign(NTRU_CIPHERTEXTBYTES, 0);
  owcpa_enc(ciphertext->data(), &r, &m, public_key);
  return true;
}

bool SampleRm(
    const uint8_t *seed,
    size_t seed_len,
    std::vector<uint8_t> *r,
    std::vector<uint8_t> *m) {
  if (seed == nullptr || r == nullptr || m == nullptr || seed_len != NTRU_SAMPLE_RM_BYTES) {
    return false;
  }
  poly rp;
  poly mp;
  sample_rm(&rp, &mp, seed);
  r->assign(NTRU_N, 0);
  m->assign(NTRU_N, 0);
  for (int i = 0; i < NTRU_N; ++i) {
    (*r)[i] = static_cast<uint8_t>(rp.coeffs[i]);
    (*m)[i] = static_cast<uint8_t>(mp.coeffs[i]);
  }
  return true;
}

bool DpkeDecryptDetailed(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *secret_key,
    size_t secret_key_len,
    std::vector<uint8_t> *r,
    std::vector<uint8_t> *m,
    bool *fail,
    bool *fail_padding,
    bool *fail_m,
    bool *fail_r) {
  if (ciphertext == nullptr || secret_key == nullptr || r == nullptr || m == nullptr ||
      ciphertext_len != NTRU_CIPHERTEXTBYTES || secret_key_len < NTRU_OWCPA_SECRETKEYBYTES) {
    return false;
  }
  poly c;
  poly f;
  poly cf;
  poly mf;
  poly finv3;
  poly invh;
  poly mm;
  poly liftm;
  poly b;
  poly rr;

  poly_Rq_sum_zero_frombytes(&c, ciphertext);
  poly_S3_frombytes(&f, secret_key);
  poly_Z3_to_Zq(&f);
  poly_Rq_mul(&cf, &c, &f);
  poly_Rq_to_S3(&mf, &cf);
  poly_S3_frombytes(&finv3, secret_key + NTRU_PACK_TRINARY_BYTES);
  poly_S3_mul(&mm, &mf, &finv3);

  const int padding_fail = CheckCiphertextPadding(ciphertext);
  const int m_fail = CheckM(&mm);

  poly_lift(&liftm, &mm);
  for (int i = 0; i < NTRU_N; ++i) {
    b.coeffs[i] = c.coeffs[i] - liftm.coeffs[i];
  }
  poly_Sq_frombytes(&invh, secret_key + 2 * NTRU_PACK_TRINARY_BYTES);
  poly_Sq_mul(&rr, &b, &invh);
  const int r_fail = CheckR(&rr);
  poly_trinary_Zq_to_Z3(&rr);

  r->assign(NTRU_N, 0);
  m->assign(NTRU_N, 0);
  for (int i = 0; i < NTRU_N; ++i) {
    (*r)[i] = static_cast<uint8_t>(rr.coeffs[i]);
    (*m)[i] = static_cast<uint8_t>(mm.coeffs[i]);
  }
  const bool any = (padding_fail | m_fail | r_fail) != 0;
  if (fail != nullptr) {
    *fail = any;
  }
  if (fail_padding != nullptr) {
    *fail_padding = padding_fail != 0;
  }
  if (fail_m != nullptr) {
    *fail_m = m_fail != 0;
  }
  if (fail_r != nullptr) {
    *fail_r = r_fail != 0;
  }
  return true;
}

bool Pack3(const std::vector<uint8_t> &trits, std::vector<uint8_t> *payload) {
  if (payload == nullptr || trits.size() != static_cast<size_t>(NTRU_N)) {
    return false;
  }
  poly p;
  for (int i = 0; i < NTRU_N; ++i) {
    p.coeffs[i] = trits[i];
  }
  payload->assign(NTRU_PACK_TRINARY_BYTES, 0);
  poly_S3_tobytes(payload->data(), &p);
  payload->resize(NTRU_PACK_TRINARY_BYTES);
  return true;
}

bool Unpack3(const uint8_t *payload, size_t payload_len, std::vector<uint8_t> *trits) {
  if (payload == nullptr || trits == nullptr || payload_len != NTRU_PACK_TRINARY_BYTES) {
    return false;
  }
  poly p;
  poly_S3_frombytes(&p, payload);
  trits->assign(NTRU_N, 0);
  for (int i = 0; i < NTRU_N; ++i) {
    (*trits)[i] = static_cast<uint8_t>(p.coeffs[i]);
  }
  return true;
}

bool PackQ(const std::vector<uint16_t> &coefficients, std::vector<uint8_t> *payload) {
  if (payload == nullptr || coefficients.size() != static_cast<size_t>(NTRU_N)) {
    return false;
  }
  poly p;
  for (int i = 0; i < NTRU_N; ++i) {
    p.coeffs[i] = coefficients[i];
  }
  payload->assign(NTRU_OWCPA_PUBLICKEYBYTES, 0);
  poly_Rq_sum_zero_tobytes(payload->data(), &p);
  return true;
}

bool UnpackQ(const uint8_t *payload, size_t payload_len, std::vector<uint16_t> *coefficients) {
  if (payload == nullptr || coefficients == nullptr || payload_len != NTRU_OWCPA_PUBLICKEYBYTES) {
    return false;
  }
  poly p;
  poly_Rq_sum_zero_frombytes(&p, payload);
  coefficients->assign(NTRU_N, 0);
  for (int i = 0; i < NTRU_N; ++i) {
    (*coefficients)[i] = p.coeffs[i];
  }
  return true;
}

bool Lift(const std::vector<uint8_t> &trits, std::vector<uint16_t> *coefficients) {
  if (coefficients == nullptr || trits.size() != static_cast<size_t>(NTRU_N)) {
    return false;
  }
  poly a;
  poly out;
  for (int i = 0; i < NTRU_N; ++i) {
    a.coeffs[i] = trits[i];
  }
  poly_lift(&out, &a);
  coefficients->assign(NTRU_N, 0);
  for (int i = 0; i < NTRU_N; ++i) {
    (*coefficients)[i] = out.coeffs[i];
  }
  return true;
}

}  // namespace ntru_reference
}  // namespace pqcfuzz

#endif  // PQCFUZZ_HAVE_NTRU_REFERENCE

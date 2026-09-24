#ifndef PQCFUZZ_MUTATORS_NTRU_LAYOUT_H
#define PQCFUZZ_MUTATORS_NTRU_LAYOUT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {

// One NTRU round-3 parameter set from src/config/scheme_profiles/ntru.json.
// The byte stream is little-endian bit packing: coefficient i of an Rq0/Sq
// vector occupies bits [i*logq, (i+1)*logq); S3 packs five base-3 digits per
// byte with coefficient 5i as the least significant digit.
struct NtruParams {
  const char *algorithm = "";
  const char *variant = "";  // "HPS" or "HRSS"
  size_t n = 0;
  size_t q = 0;
  size_t logq = 0;
  size_t b3 = 0;
  size_t bq = 0;
  size_t pk_len = 0;
  size_t sk_len = 0;
  size_t ct_len = 0;
  size_t ss_len = 32;
  size_t weight = 0;  // HPS message weight; 0 for HRSS
  size_t pack_trinary_bytes = 0;
  size_t tail_unused_bits = 0;
  size_t sample_fg_bytes = 0;
  size_t sample_rm_bytes = 0;
  size_t prf_key_bytes = 32;
  // Derived secret-key segment offsets.
  size_t sk_fp_off = 0;
  size_t sk_hq_off = 0;
  size_t sk_prf_off = 0;
};

bool GetNtruParams(const std::string &algorithm, NtruParams *params);

std::vector<MlKemRegion> NtruPublicKeyRegions(const NtruParams &params);
std::vector<MlKemRegion> NtruCiphertextRegions(const NtruParams &params);
std::vector<MlKemRegion> NtruSecretKeyRegions(const NtruParams &params);

// S3 codec: n-1 trits in {0,1,2}; coefficient n-1 is always zero.
bool DecodeNtruS3(const uint8_t *payload, size_t payload_len, const NtruParams &params,
                  std::vector<uint8_t> *coefficients, std::string *error);
bool EncodeNtruS3(const std::vector<uint8_t> &coefficients, const NtruParams &params,
                  std::vector<uint8_t> *payload, std::string *error);

// Rq0 codec: n-1 coefficients packed in logq bits; coefficient n-1 is
// reconstructed so that the coefficient sum is 0 mod q.
bool DecodeNtruRq0(const uint8_t *payload, size_t payload_len, const NtruParams &params,
                   std::vector<uint16_t> *coefficients, std::string *error);
bool EncodeNtruRq0(const std::vector<uint16_t> &coefficients, const NtruParams &params,
                   std::vector<uint8_t> *payload, std::string *error);

// True when the unused high bits of the final ciphertext byte are zero.
bool NtruCiphertextPaddingValid(const uint8_t *ciphertext, size_t ciphertext_len, const NtruParams &params);
// True when the profile has an unused-bit field at all.
bool NtruHasCiphertextPadding(const NtruParams &params);

}  // namespace pqcfuzz

#endif

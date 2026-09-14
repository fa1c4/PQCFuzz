#ifndef PQCFUZZ_MUTATORS_ML_DSA_LAYOUT_H
#define PQCFUZZ_MUTATORS_ML_DSA_LAYOUT_H

#include <cstddef>
#include <string>
#include <vector>

#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {

struct MlDsaParams {
  const char *algorithm;
  size_t pk_len;
  size_t sk_len;
  size_t sig_max_len;
  // FIPS 204 hint encoding: h = omega + k bytes (cumulative counts followed
  // by sorted position bytes), and c_tilde = lambda/4 bytes (32 for all sets).
  size_t c_bytes = 32;
  size_t omega = 0;
  size_t k = 0;
  // FIPS 204 response bound: |z|_infinity < gamma1 - beta, with z coefficients
  // packed little-endian in gamma1_bits bits.
  size_t gamma1 = 0;
  size_t beta = 0;
  size_t gamma1_bits = 0;
};

bool GetMlDsaParams(const std::string &algorithm, MlDsaParams *params);
std::vector<MlKemRegion> MlDsaSignatureRegions(const MlDsaParams &params, size_t signature_len);
std::vector<MlKemRegion> MlDsaPublicKeyRegions(const MlDsaParams &params);

}  // namespace pqcfuzz

#endif

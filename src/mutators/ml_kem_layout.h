#ifndef PQCFUZZ_MUTATORS_ML_KEM_LAYOUT_H
#define PQCFUZZ_MUTATORS_ML_KEM_LAYOUT_H

#include <cstddef>
#include <string>
#include <vector>

namespace pqcfuzz {

struct MlKemParams {
  const char *algorithm;
  size_t pk_len;
  size_t sk_len;
  size_t ct_len;
  size_t ss_len;
  size_t k;
  size_t du;
  size_t dv;
  // Implicit-rejection secret z, per FIPS 203 dk = dkPKE || ek || H(ek) || z.
  size_t z_offset = 0;
  size_t z_len = 0;
};

struct MlKemRegion {
  std::string name;
  size_t offset;
  size_t length;
};

bool GetMlKemParams(const std::string &algorithm, MlKemParams *params);
std::vector<MlKemRegion> PublicKeyRegions(const MlKemParams &params);
std::vector<MlKemRegion> CiphertextRegions(const MlKemParams &params);

// FIPS 203 ByteEncode12/ByteDecode12 helpers for the encapsulation-key
// polynomial prefix.  Coefficients are packed as pairs into three bytes.
bool DecodeMlKemCoefficient12(const std::vector<uint8_t> &public_key, size_t coefficient_index, uint16_t *value);
bool EncodeMlKemCoefficient12(std::vector<uint8_t> *public_key, size_t coefficient_index, uint16_t value);

}  // namespace pqcfuzz

#endif

#include "mutators/ml_dsa_layout.h"

#include <algorithm>

namespace pqcfuzz {
namespace {

constexpr MlDsaParams kMlDsaParams[] = {
    {"ML-DSA-44", 1312, 2560, 2420, 32, 80, 4, 1u << 17, 78, 18},
    {"ML-DSA-65", 1952, 4032, 3309, 32, 55, 6, 1u << 19, 196, 20},
    {"ML-DSA-87", 2592, 4896, 4627, 32, 75, 8, 1u << 19, 120, 20},
};

}  // namespace

bool GetMlDsaParams(const std::string &algorithm, MlDsaParams *params) {
  for (const auto &candidate : kMlDsaParams) {
    if (algorithm == candidate.algorithm) {
      if (params != nullptr) {
        *params = candidate;
      }
      return true;
    }
  }
  return false;
}

std::vector<MlKemRegion> MlDsaSignatureRegions(const MlDsaParams &params, size_t signature_len) {
  const size_t c_len = std::min(params.c_bytes, signature_len);
  const size_t h_len = std::min(params.omega + params.k, signature_len > c_len ? signature_len - c_len : 0);
  const size_t z_len = signature_len > c_len + h_len ? signature_len - c_len - h_len : 0;
  return {
      {"signature.c", 0, c_len},
      {"signature.z", c_len, z_len},
      {"signature.h", c_len + z_len, h_len},
  };
}

std::vector<MlKemRegion> MlDsaPublicKeyRegions(const MlDsaParams &params) {
  return {
      {"public_key", 0, params.pk_len},
  };
}

}  // namespace pqcfuzz

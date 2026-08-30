#include "mutators/aigis_enc_layout.h"

namespace pqcfuzz {
namespace {

constexpr AigisEncParams kAigisEncParams[] = {
    {"AIGIS-ENC-1", 672, 1568, 736, 32, 256, 7681, 2, 10, 3, 10, 416},
    {"AIGIS-ENC-2", 896, 2208, 992, 32, 256, 7681, 3, 9, 4, 9, 416},
    {"AIGIS-ENC-3", 992, 2304, 1056, 32, 256, 7681, 3, 10, 3, 10, 416},
    {"AIGIS-ENC-4", 1440, 3168, 1568, 32, 256, 7681, 4, 11, 5, 11, 416},
};

}  // namespace

bool GetAigisEncParams(const std::string &algorithm, AigisEncParams *params) {
  for (const auto &candidate : kAigisEncParams) {
    if (algorithm == candidate.algorithm) {
      if (params != nullptr) {
        *params = candidate;
      }
      return true;
    }
  }
  return false;
}

std::vector<MlKemRegion> AigisEncPublicKeyRegions(const AigisEncParams &params) {
  const size_t seed_len = 32;
  const size_t t_len = params.pk_len - seed_len;
  return {
      {"public_key.t", 0, t_len},
      {"public_key.seed", t_len, seed_len},
  };
}

std::vector<MlKemRegion> AigisEncCiphertextRegions(const AigisEncParams &params) {
  const size_t u_len = params.k * params.n * params.c1_bits / 8;
  const size_t v_len = params.n * params.c2_bits / 8;
  return {
      {"ciphertext.u", 0, u_len},
      {"ciphertext.v", u_len, v_len},
  };
}

}  // namespace pqcfuzz

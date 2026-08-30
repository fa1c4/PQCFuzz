#ifndef PQCFUZZ_MUTATORS_AIGIS_SIG_LAYOUT_H
#define PQCFUZZ_MUTATORS_AIGIS_SIG_LAYOUT_H

#include <cstddef>
#include <string>
#include <vector>

#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {

struct AigisSigParams {
  const char *algorithm;
  size_t pk_len;
  size_t sk_len;
  size_t sig_max_len;
  size_t n;          // polynomial degree (256)
  size_t l;          // z vector dimension (polynomials)
  size_t k;          // hint vector dimension (polynomials)
  size_t omega;      // maximum number of nonzero hint entries
  size_t z_bytes;    // l * n * 18 / 8
  size_t hint_bytes; // omega + k
  size_t c_bytes;    // n / 8 + 8 (support bitmap + sign bytes)
};

bool GetAigisSigParams(const std::string &algorithm, AigisSigParams *params);
std::vector<MlKemRegion> AigisSigSignatureRegions(const AigisSigParams &params);
std::vector<MlKemRegion> AigisSigPublicKeyRegions(const AigisSigParams &params);

}  // namespace pqcfuzz

#endif

#ifndef PQCFUZZ_MUTATORS_AIGIS_ENC_LAYOUT_H
#define PQCFUZZ_MUTATORS_AIGIS_ENC_LAYOUT_H

#include <cstddef>
#include <string>
#include <vector>

#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {

struct AigisEncParams {
  const char *algorithm;
  size_t pk_len;
  size_t sk_len;
  size_t ct_len;
  size_t ss_len;
  size_t n;            // polynomial degree (256)
  size_t q;            // modulus (7681)
  size_t k;            // module rank
  size_t c1_bits;      // compressed ciphertext polynomial coefficient bits
  size_t c2_bits;      // compressed ciphertext noise polynomial coefficient bits
  size_t pk_bits;      // compressed public key polynomial coefficient bits
  size_t poly_bytes;   // unpacked secret polynomial encoding (n * 13 / 8 = 416)
  // Implicit-rejection secret z, per PQMagic kem/aigis-enc/std/kem.c:
  // sk = s_vec || pk || H(pk) || z, with z in the final SEED_BYTES.
  size_t z_offset = 0;
  size_t z_len = 0;
};

bool GetAigisEncParams(const std::string &algorithm, AigisEncParams *params);
std::vector<MlKemRegion> AigisEncPublicKeyRegions(const AigisEncParams &params);
std::vector<MlKemRegion> AigisEncCiphertextRegions(const AigisEncParams &params);

}  // namespace pqcfuzz

#endif

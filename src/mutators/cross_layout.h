#ifndef PQCFUZZ_MUTATORS_CROSS_LAYOUT_H
#define PQCFUZZ_MUTATORS_CROSS_LAYOUT_H

#include <cstddef>
#include <string>
#include <vector>

#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {

// One CROSS parameter set.  Derived offsets follow the pinned CROSS_sig_t
// layout: salt | digest_cmt | digest_chall2 | path | proof | resp1 | resp0.
struct CrossParams {
  const char *algorithm;
  const char *variant;  // "RSDP" or "RSDPG"
  const char *corner;   // "FAST", "BALANCED", "SMALL"
  size_t category;
  size_t security_level;
  size_t p;
  size_t z;
  size_t n;
  size_t k;
  size_t m;  // 0 for RSDP
  size_t g;  // 2 for RSDP, 16 for RSDPG
  size_t t;
  size_t w;
  size_t pk_len;
  size_t sk_len;
  size_t sig_max_len;
  size_t seed_bytes;
  size_t salt_bytes;
  size_t digest_bytes;
  size_t y_bits;
  size_t v_bits;
  size_t s_bits;
  size_t y_bytes;
  size_t v_bytes;
  size_t syn_bytes;
  size_t tree_nodes_to_store;
  // Derived byte offsets inside the signature.
  size_t salt_off;
  size_t digest_cmt_off;
  size_t digest_chall2_off;
  size_t path_off;
  size_t proof_off;
  size_t resp1_off;
  size_t resp0_off;
  size_t resp0_round_bytes;
  size_t resp_rounds;  // t - w
};

bool GetCrossParams(const std::string &algorithm, CrossParams *params);

std::vector<MlKemRegion> CrossSignatureRegions(const CrossParams &params, size_t signature_len);
std::vector<MlKemRegion> CrossPublicKeyRegions(const CrossParams &params);

// Byte offsets of the y/v (or vG) sub-vector of one zero-challenge round.
size_t CrossYRoundOffset(const CrossParams &params, size_t round);
size_t CrossVRoundOffset(const CrossParams &params, size_t round);

// Number of unused padding bits at the end of a densely packed vector.
size_t CrossVectorPaddingBits(const CrossParams &params, bool is_y);

}  // namespace pqcfuzz

#endif

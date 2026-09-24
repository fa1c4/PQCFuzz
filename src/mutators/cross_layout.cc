#include "mutators/cross_layout.h"

namespace pqcfuzz {
namespace {

// Parameter table mirrored from src/config/scheme_profiles/cross.json, which
// in turn mirrors Additional_Implementations/Parameter_Generation_Scripts/
// code_parameters.csv and the pinned reference headers.  Pinned source:
// projects/CROSS/reference (NIST round-2 submission, archive sha256
// 682e19f8deba19f543960687abcf6d81d44edbd16d8ae006f4c1dfeca8c957e6).
constexpr CrossParams kCrossParams[] = {
    {"CROSS-RSDP-1-FAST", "RSDP", "FAST", 1, 128, 127, 7, 127, 76, 0, 2, 157, 82,
     77, 32, 18432, 16, 32, 32, 7, 3, 7, 112, 48, 45, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDP-1-BALANCED", "RSDP", "BALANCED", 1, 128, 127, 7, 127, 76, 0, 2, 256, 215,
     77, 32, 13152, 16, 32, 32, 7, 3, 7, 112, 48, 45, 108, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDP-1-SMALL", "RSDP", "SMALL", 1, 128, 127, 7, 127, 76, 0, 2, 520, 488,
     77, 32, 12432, 16, 32, 32, 7, 3, 7, 112, 48, 45, 129, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDP-3-FAST", "RSDP", "FAST", 3, 192, 127, 7, 187, 111, 0, 2, 239, 125,
     115, 48, 41406, 24, 48, 48, 7, 3, 7, 164, 71, 67, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDP-3-BALANCED", "RSDP", "BALANCED", 3, 192, 127, 7, 187, 111, 0, 2, 384, 321,
     115, 48, 29853, 24, 48, 48, 7, 3, 7, 164, 71, 67, 165, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDP-3-SMALL", "RSDP", "SMALL", 3, 192, 127, 7, 187, 111, 0, 2, 580, 527,
     115, 48, 28391, 24, 48, 48, 7, 3, 7, 164, 71, 67, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDP-5-FAST", "RSDP", "FAST", 5, 256, 127, 7, 251, 150, 0, 2, 321, 167,
     153, 64, 74590, 32, 64, 64, 7, 3, 7, 220, 95, 89, 167, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDP-5-BALANCED", "RSDP", "BALANCED", 5, 256, 127, 7, 251, 150, 0, 2, 512, 427,
     153, 64, 53527, 32, 64, 64, 7, 3, 7, 220, 95, 89, 220, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDP-5-SMALL", "RSDP", "SMALL", 5, 256, 127, 7, 251, 150, 0, 2, 832, 762,
     153, 64, 50818, 32, 64, 64, 7, 3, 7, 220, 95, 89, 251, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDPG-1-FAST", "RSDPG", "FAST", 1, 128, 509, 127, 55, 36, 25, 16, 147, 76,
     54, 32, 11980, 16, 32, 32, 9, 7, 9, 62, 22, 22, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDPG-1-BALANCED", "RSDPG", "BALANCED", 1, 128, 509, 127, 55, 36, 25, 16, 256, 220,
     54, 32, 9120, 16, 32, 32, 9, 7, 9, 62, 22, 22, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDPG-1-SMALL", "RSDPG", "SMALL", 1, 128, 509, 127, 55, 36, 25, 16, 512, 484,
     54, 32, 8960, 16, 32, 32, 9, 7, 9, 62, 22, 22, 117, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDPG-3-FAST", "RSDPG", "FAST", 3, 192, 509, 127, 79, 48, 40, 16, 224, 119,
     83, 48, 26772, 24, 48, 48, 9, 7, 9, 89, 35, 35, 119, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDPG-3-BALANCED", "RSDPG", "BALANCED", 3, 192, 509, 127, 79, 48, 40, 16, 268, 196,
     83, 48, 22464, 24, 48, 48, 9, 7, 9, 89, 35, 35, 138, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDPG-3-SMALL", "RSDPG", "SMALL", 3, 192, 509, 127, 79, 48, 40, 16, 512, 463,
     83, 48, 20452, 24, 48, 48, 9, 7, 9, 89, 35, 35, 165, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDPG-5-FAST", "RSDPG", "FAST", 5, 256, 509, 127, 106, 69, 48, 16, 300, 153,
     106, 64, 48102, 32, 64, 64, 9, 7, 9, 120, 42, 42, 153, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDPG-5-BALANCED", "RSDPG", "BALANCED", 5, 256, 509, 127, 106, 69, 48, 16, 356, 258,
     106, 64, 40100, 32, 64, 64, 9, 7, 9, 120, 42, 42, 185, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"CROSS-RSDPG-5-SMALL", "RSDPG", "SMALL", 5, 256, 509, 127, 106, 69, 48, 16, 642, 575,
     106, 64, 36454, 32, 64, 64, 9, 7, 9, 120, 42, 42, 220, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

void FinalizeCrossParams(CrossParams *params) {
  params->digest_cmt_off = params->salt_bytes;
  params->digest_chall2_off = params->digest_cmt_off + params->digest_bytes;
  params->path_off = params->digest_chall2_off + params->digest_bytes;
  params->proof_off = params->path_off + params->tree_nodes_to_store * params->seed_bytes;
  params->resp1_off = params->proof_off + params->tree_nodes_to_store * params->digest_bytes;
  params->resp0_off = params->resp1_off + (params->t - params->w) * params->digest_bytes;
  params->resp0_round_bytes = params->y_bytes + params->v_bytes;
  params->resp_rounds = params->t - params->w;
  params->salt_off = 0;
}

}  // namespace

bool GetCrossParams(const std::string &algorithm, CrossParams *params) {
  for (const auto &candidate : kCrossParams) {
    if (algorithm == candidate.algorithm) {
      if (params != nullptr) {
        *params = candidate;
        FinalizeCrossParams(params);
      }
      return true;
    }
  }
  return false;
}

std::vector<MlKemRegion> CrossSignatureRegions(const CrossParams &params, size_t signature_len) {
  std::vector<MlKemRegion> regions;
  regions.push_back({"signature.salt", params.salt_off, params.salt_bytes});
  regions.push_back({"signature.digest_cmt", params.digest_cmt_off, params.digest_bytes});
  regions.push_back({"signature.digest_chall2", params.digest_chall2_off, params.digest_bytes});
  regions.push_back({"signature.path", params.path_off, params.tree_nodes_to_store * params.seed_bytes});
  regions.push_back({"signature.proof", params.proof_off, params.tree_nodes_to_store * params.digest_bytes});
  regions.push_back({"signature.resp1", params.resp1_off, params.resp_rounds * params.digest_bytes});
  regions.push_back({"signature.resp0", params.resp0_off, params.resp_rounds * params.resp0_round_bytes});
  // Keep the caller-visible length separate from the fixed capacity: an
  // oversized buffer proves the profile capacity, while a shorter slice proves
  // the active layout.
  const size_t capacity = params.sig_max_len;
  if (signature_len > 0 && signature_len < capacity) {
    for (auto &region : regions) {
      if (region.offset >= signature_len) {
        region.length = 0;
      } else if (region.offset + region.length > signature_len) {
        region.length = signature_len - region.offset;
      }
    }
  }
  return regions;
}

std::vector<MlKemRegion> CrossPublicKeyRegions(const CrossParams &params) {
  return {
      {"public_key.seed", 0, params.seed_bytes},
      {"public_key.syndrome", params.seed_bytes, params.syn_bytes},
  };
}

size_t CrossYRoundOffset(const CrossParams &params, size_t round) {
  return params.resp0_off + round * params.resp0_round_bytes;
}

size_t CrossVRoundOffset(const CrossParams &params, size_t round) {
  return CrossYRoundOffset(params, round) + params.y_bytes;
}

size_t CrossVectorPaddingBits(const CrossParams &params, bool is_y) {
  const size_t width = is_y ? params.y_bits : params.v_bits;
  const size_t count = is_y ? params.n : (params.m > 0 ? params.m : params.n);
  const size_t total_bits = width * count;
  return (8 - (total_bits % 8)) % 8;
}

}  // namespace pqcfuzz

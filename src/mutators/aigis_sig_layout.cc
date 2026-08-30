#include "mutators/aigis_sig_layout.h"

namespace pqcfuzz {
namespace {

// Signature packing order (sig/aigis-sig/std/packing.c pack_sig): z | h | c
// with z = L * (N * 18 / 8) bytes, h = OMEGA + K bytes, c = N/8 + 8 bytes.
constexpr AigisSigParams kAigisSigParams[] = {
    {"AIGIS-SIG-1", 1056, 2448, 1852, 256, 3, 4, 80, 1728, 84, 40},
    {"AIGIS-SIG-2", 1312, 3376, 2445, 256, 4, 5, 96, 2304, 101, 40},
    {"AIGIS-SIG-3", 1568, 3888, 3046, 256, 5, 6, 120, 2880, 126, 40},
};

}  // namespace

bool GetAigisSigParams(const std::string &algorithm, AigisSigParams *params) {
  for (const auto &candidate : kAigisSigParams) {
    if (algorithm == candidate.algorithm) {
      if (params != nullptr) {
        *params = candidate;
      }
      return true;
    }
  }
  return false;
}

std::vector<MlKemRegion> AigisSigSignatureRegions(const AigisSigParams &params) {
  return {
      {"signature.z", 0, params.z_bytes},
      {"signature.h", params.z_bytes, params.hint_bytes},
      {"signature.c", params.z_bytes + params.hint_bytes, params.c_bytes},
  };
}

std::vector<MlKemRegion> AigisSigPublicKeyRegions(const AigisSigParams &params) {
  return {
      {"public_key", 0, params.pk_len},
  };
}

}  // namespace pqcfuzz

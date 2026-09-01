#ifndef PQCFUZZ_MUTATORS_ML_KEM_MUTATOR_H
#define PQCFUZZ_MUTATORS_ML_KEM_MUTATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "mutators/digest.h"
#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {

struct MutationRecord {
  std::string operation;
  std::string target;
  size_t offset = 0;
  size_t length = 0;
  bool skipped = false;
  // `effective` is the semantic guard for mutation-based oracles.  It is
  // deliberately independent of the planned operation: a set-zero on an
  // already-zero byte is not an intervention.
  bool effective = false;
  std::string reason;
  std::string field_parse_status;
  size_t original_length = 0;
  size_t mutated_length = 0;
  std::string original_sha256;
  std::string mutated_sha256;
};

inline void RecordMutationEffect(
    MutationRecord *record,
    const std::vector<uint8_t> &original,
    const std::vector<uint8_t> &mutated) {
  if (record == nullptr) {
    return;
  }
  record->original_length = original.size();
  record->mutated_length = mutated.size();
  record->original_sha256 = MutationSha256Hex(original);
  record->mutated_sha256 = MutationSha256Hex(mutated);
  record->effective = original != mutated;
  if (!record->effective) {
    record->skipped = true;
    record->reason = "no_effect";
  }
}

// Little-endian 16-bit value from a mutation plan starting at `index`, so
// offsets/positions can cover objects larger than 255 bytes.
inline size_t PlanU16(const std::vector<uint8_t> &plan, size_t index, size_t fallback) {
  const size_t lo = index < plan.size() ? plan[index] : static_cast<uint8_t>(fallback);
  const size_t hi = index + 1 < plan.size() ? plan[index + 1] : static_cast<uint8_t>(fallback >> 8);
  return lo | (hi << 8);
}

std::vector<MutationRecord> MutateMlKemCiphertext(
    const MlKemParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *ciphertext);
std::vector<MutationRecord> MutateMlKemPublicKey(
    const MlKemParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key);

}  // namespace pqcfuzz

#endif

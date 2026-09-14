#ifndef PQCFUZZ_MUTATORS_ML_DSA_MUTATOR_H
#define PQCFUZZ_MUTATORS_ML_DSA_MUTATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "mutators/ml_dsa_layout.h"
#include "mutators/ml_kem_mutator.h"

namespace pqcfuzz {

std::vector<MutationRecord> MutateMlDsaSignature(
    const MlDsaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signature);
std::vector<MutationRecord> MutateMlDsaMessage(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *message);
std::vector<MutationRecord> MutateMlDsaContext(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *context);
std::vector<MutationRecord> MutateMlDsaOid(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *oid);
std::vector<MutationRecord> MutateMlDsaPublicKey(
    const MlDsaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key);

// FIPS 204 Algorithm 21 HintBitUnpack canonicality mutations.  Each call
// applies exactly one mutation class to a valid signature and records it.
enum class MlDsaHintMutation {
  kCountRollback,
  kCountOverflow,
  kNonIncreasingIndex,
  kTrailingNonZero,
};

std::vector<MutationRecord> MutateMlDsaHintCanonical(
    const MlDsaParams &params,
    MlDsaHintMutation mutation,
    std::vector<uint8_t> *signature);

// FIPS 204 response norm boundary mutation: rewrites the first packed z
// coefficient (gamma1_bits little-endian bits).
enum class MlDsaZNormMutation {
  kValidBoundary,          // z = gamma1 - beta - 1 (within the norm bound)
  kOverBoundary,           // z = gamma1 - beta (outside the bound)
  kNegativeOverBoundary,   // z = -(gamma1 - beta) (outside the bound)
};

std::vector<MutationRecord> MutateMlDsaZNormBoundary(
    const MlDsaParams &params,
    MlDsaZNormMutation mutation,
    std::vector<uint8_t> *signature);

}  // namespace pqcfuzz

#endif

#ifndef PQCFUZZ_MUTATORS_AIGIS_SIG_MUTATOR_H
#define PQCFUZZ_MUTATORS_AIGIS_SIG_MUTATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "mutators/aigis_sig_layout.h"
#include "mutators/ml_kem_mutator.h"

namespace pqcfuzz {

std::vector<MutationRecord> MutateAigisSigSignature(
    const AigisSigParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signature);
std::vector<MutationRecord> MutateAigisSigMessage(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *message);
std::vector<MutationRecord> MutateAigisSigContext(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *context);
std::vector<MutationRecord> MutateAigisSigPublicKey(
    const AigisSigParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key);

}  // namespace pqcfuzz

#endif

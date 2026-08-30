#ifndef PQCFUZZ_MUTATORS_AIGIS_ENC_MUTATOR_H
#define PQCFUZZ_MUTATORS_AIGIS_ENC_MUTATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "mutators/aigis_enc_layout.h"
#include "mutators/ml_kem_mutator.h"

namespace pqcfuzz {

std::vector<MutationRecord> MutateAigisEncCiphertext(
    const AigisEncParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *ciphertext);
std::vector<MutationRecord> MutateAigisEncPublicKey(
    const AigisEncParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key);
// Set coefficient 0 of secret polynomial 0 to the non-canonical encoded value
// q (= 7681) inside the 13-bit-packed s vector at the front of the secret key.
std::vector<MutationRecord> MutateAigisEncSkNoncanonicalCoefficient(
    const AigisEncParams &params,
    std::vector<uint8_t> *secret_key);

}  // namespace pqcfuzz

#endif

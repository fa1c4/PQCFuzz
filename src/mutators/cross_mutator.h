#ifndef PQCFUZZ_MUTATORS_CROSS_MUTATOR_H
#define PQCFUZZ_MUTATORS_CROSS_MUTATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "mutators/cross_layout.h"
#include "mutators/ml_kem_mutator.h"
#include "mutators/scheme_mutation.h"

namespace pqcfuzz {

// Applies a structured recipe v1 to a CROSS signature using the registered
// layout.  Unknown fields fall back to the whole signature so the recipe still
// has a well-defined target.
std::vector<MutationRecord> MutateCrossSignature(
    const CrossParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signature);

std::vector<MutationRecord> MutateCrossPublicKey(
    const CrossParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key);

std::vector<MutationRecord> MutateCrossMessage(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *message);

// Sets every bit of one packed coefficient to 1, which is out of range for
// both Fp (p=127/509) and Fz (z=7/127).  `round` selects a zero-challenge
// response block, `coefficient` is reduced modulo the vector dimension.
std::vector<MutationRecord> MutateCrossPackedCoefficient(
    const CrossParams &params,
    bool is_y,
    size_t round,
    size_t coefficient,
    std::vector<uint8_t> *signature);

// Sets one unused high padding bit of a packed vector to 1.
std::vector<MutationRecord> MutateCrossPaddingBit(
    const CrossParams &params,
    bool is_y,
    size_t round,
    size_t padding_index,
    std::vector<uint8_t> *signature);

// Flips a bit at an arbitrary byte offset inside the whole signature; used to
// prove that offsets beyond 65535 reach the target layout.
std::vector<MutationRecord> MutateCrossAbsoluteByte(
    const CrossParams &params,
    size_t byte_offset,
    uint8_t xor_value,
    std::vector<uint8_t> *signature);

}  // namespace pqcfuzz

#endif

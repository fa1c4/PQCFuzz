#ifndef PQCFUZZ_MUTATORS_SNOVA_MUTATOR_H
#define PQCFUZZ_MUTATORS_SNOVA_MUTATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "mutators/ml_kem_mutator.h"
#include "mutators/snova_layout.h"

namespace pqcfuzz {

// Structured mutation for SNOVA objects.  Signature/secret-key fields are
// nibble-exact for GF16 data and fall back to byte operations otherwise.
// Mutations that do not address a field of the family are reported as skipped
// rather than silently applied to the whole buffer.
std::vector<MutationRecord> MutateSnovaSignature(
    const SnovaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signature);

std::vector<MutationRecord> MutateSnovaPublicKey(
    const SnovaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key);

// seed_format selects the SSK (seed) or ESK (expanded) private-key layout.
std::vector<MutationRecord> MutateSnovaPrivateKey(
    const SnovaParams &params,
    bool seed_format,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *private_key);

std::vector<MutationRecord> MutateSnovaMessage(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *message);

// Set one GF16 nibble of a signature matrix (row/col inside the l x l matrix).
std::vector<MutationRecord> MutateSnovaSignatureNibble(
    const SnovaParams &params,
    size_t nibble_index,
    uint8_t value,
    std::vector<uint8_t> *signature);

// Set one GF16 nibble of P22 inside the public key.
std::vector<MutationRecord> MutateSnovaP22Nibble(
    const SnovaParams &params,
    size_t nibble_index,
    uint8_t value,
    std::vector<uint8_t> *public_key);

// Set the unused high-nibble pad of an odd-nibble signature (no-op when the
// signature is nibble aligned).
std::vector<MutationRecord> MutateSnovaSignaturePadding(
    const SnovaParams &params,
    uint8_t value,
    std::vector<uint8_t> *signature);

// XOR one absolute byte in an arbitrary-size buffer; reaches offsets above
// 65535 for the large public keys and expanded secret keys.
std::vector<MutationRecord> MutateSnovaAbsoluteByte(
    const SnovaParams &params,
    size_t byte_offset,
    uint8_t xor_value,
    std::vector<uint8_t> *buffer);

}  // namespace pqcfuzz

#endif

#ifndef PQCFUZZ_MUTATORS_NTRU_MUTATOR_H
#define PQCFUZZ_MUTATORS_NTRU_MUTATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "mutators/ml_kem_mutator.h"
#include "mutators/ntru_layout.h"

namespace pqcfuzz {

std::vector<MutationRecord> MutateNtruCiphertext(
    const NtruParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *ciphertext);
std::vector<MutationRecord> MutateNtruPublicKey(
    const NtruParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key);
std::vector<MutationRecord> MutateNtruSecretKey(
    const NtruParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *secret_key);

MutationRecord SetNtruCiphertextCoefficient(
    const NtruParams &params,
    size_t index,
    uint16_t value,
    std::vector<uint8_t> *ciphertext);
MutationRecord SetNtruCiphertextPaddingBit(
    const NtruParams &params,
    size_t bit_index,
    std::vector<uint8_t> *ciphertext);
MutationRecord SetNtruPublicKeyCoefficient(
    const NtruParams &params,
    size_t index,
    uint16_t value,
    std::vector<uint8_t> *public_key);
MutationRecord WriteNtruSecretKeyByte(
    const NtruParams &params,
    size_t offset,
    uint8_t value,
    std::vector<uint8_t> *secret_key);
MutationRecord CorruptNtruS3Group(
    const NtruParams &params,
    size_t group_index,
    uint8_t value,
    std::vector<uint8_t> *secret_key);
MutationRecord WriteNtruPrfKeyByte(
    const NtruParams &params,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *secret_key);
MutationRecord TruncateNtruBuffer(std::vector<uint8_t> *buffer, size_t new_length);

}  // namespace pqcfuzz

#endif

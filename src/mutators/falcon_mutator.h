#ifndef PQCFUZZ_MUTATORS_FALCON_MUTATOR_H
#define PQCFUZZ_MUTATORS_FALCON_MUTATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "mutators/falcon_layout.h"
#include "mutators/ml_kem_mutator.h"

namespace pqcfuzz {

// Format-aware Falcon mutators.  The compressed payload is re-encoded through
// the bit codec rather than patched at fixed offsets, so mutations stay valid
// on every profile (512/1024, compressed/padded/CT) and on variable-length
// compressed signatures.
std::vector<MutationRecord> MutateFalconSignature(
    const FalconParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signature);
std::vector<MutationRecord> MutateFalconPublicKey(
    const FalconParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key);
std::vector<MutationRecord> MutateFalconMessage(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *message);
std::vector<MutationRecord> MutateFalconSignedMessage(
    const FalconParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signed_message);

MutationRecord MutateFalconSignatureHeader(
    const FalconParams &params,
    uint8_t header,
    std::vector<uint8_t> *signature);
MutationRecord MutateFalconSaltByte(
    const FalconParams &params,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *signature);
MutationRecord MutateFalconCoefficient(
    const FalconParams &params,
    size_t index,
    int16_t value,
    std::vector<uint8_t> *signature);
MutationRecord SetFalconCompressedNegativeZeroBit(
    const FalconParams &params,
    size_t coefficient_index,
    std::vector<uint8_t> *signature);
MutationRecord ClearFalconCompressedTerminatorBit(
    const FalconParams &params,
    size_t coefficient_index,
    std::vector<uint8_t> *signature);
MutationRecord SetFalconCompressedPaddingBit(
    const FalconParams &params,
    size_t bit_index,
    std::vector<uint8_t> *signature);
MutationRecord ShiftFalconCompressedPayload(
    const FalconParams &params,
    int direction,
    std::vector<uint8_t> *signature);
MutationRecord MutateFalconPublicKeyHeader(
    const FalconParams &params,
    uint8_t header,
    std::vector<uint8_t> *public_key);
MutationRecord WriteFalconPublicKeyCoefficient(
    const FalconParams &params,
    size_t index,
    uint16_t value,
    std::vector<uint8_t> *public_key);
MutationRecord TruncateFalconBuffer(std::vector<uint8_t> *buffer, size_t new_length);
MutationRecord AppendFalconByte(std::vector<uint8_t> *buffer, uint8_t value);

// Returns the index of a zero coefficient in a compressed payload, or false.
bool FindFalconCompressedZeroCoefficient(
    const FalconParams &params,
    const std::vector<uint8_t> &signature,
    size_t *index);

}  // namespace pqcfuzz

#endif

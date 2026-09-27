#ifndef PQCFUZZ_MUTATORS_SIKE_MUTATOR_H
#define PQCFUZZ_MUTATORS_SIKE_MUTATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "mutators/ml_kem_mutator.h"
#include "mutators/sike_layout.h"

namespace pqcfuzz {

// Fp2 coordinate writers for c0 / pk3 / the embedded pk.  A boundary value
// selects p-1 (0), p (1), p+1 (2) or an all-FF limb (3) so field-encoding
// oracles can exercise canonical and non-canonical encodings explicitly.
enum class SikeFpValue {
  kPrimeMinusOne = 0,
  kPrime = 1,
  kPrimePlusOne = 2,
  kAllOnes = 3,
};

MutationRecord SetSikeCiphertextCoordinate(
    const SikeParams &params,
    size_t coordinate,
    const std::vector<uint8_t> &value,
    std::vector<uint8_t> *ciphertext);
MutationRecord SetSikeCiphertextCoordinateBoundary(
    const SikeParams &params,
    size_t coordinate,
    SikeFpValue value,
    std::vector<uint8_t> *ciphertext);
MutationRecord SetSikePublicKeyCoordinateBoundary(
    const SidhParams &params,
    size_t coordinate,
    SikeFpValue value,
    std::vector<uint8_t> *public_key);
MutationRecord SetSikeCiphertextC1Byte(
    const SikeParams &params,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *ciphertext);
MutationRecord FlipSikeCiphertextC1Bit(
    const SikeParams &params,
    size_t bit_index,
    std::vector<uint8_t> *ciphertext);
MutationRecord WriteSikeSecretKeySByte(
    const SikeParams &params,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *secret_key);
MutationRecord WriteSikeSecretKeySk3Byte(
    const SikeParams &params,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *secret_key);
MutationRecord WriteSikeSecretKeyEmbeddedPkByte(
    const SikeParams &params,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *secret_key);
MutationRecord WriteSidhSecretKeyScalarByte(
    size_t scalar_len,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *secret_key);
MutationRecord TruncateSikeBuffer(std::vector<uint8_t> *buffer, size_t new_length);
MutationRecord AppendSikeBufferByte(std::vector<uint8_t> *buffer, uint8_t value);

// Structured mutation plan entry points.  The plan decoder is the shared
// scheme_mutation recipe; a malformed recipe is a skipped record, never a
// silent no-op that counts as an intervention.
std::vector<MutationRecord> MutateSikeCiphertext(
    const SikeParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *ciphertext);
std::vector<MutationRecord> MutateSikeSecretKey(
    const SikeParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *secret_key);
std::vector<MutationRecord> MutateSikePublicKey(
    const SikeParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key);

}  // namespace pqcfuzz

#endif

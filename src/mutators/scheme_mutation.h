#ifndef PQCFUZZ_MUTATORS_SCHEME_MUTATION_H
#define PQCFUZZ_MUTATORS_SCHEME_MUTATION_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pqcfuzz {

// Structured mutation recipe v1 (plan section 1.4):
//   op:u8, field:u8, index:u32le, aux:u32le, payload...
// The recipe is version-tagged in the profile/trace; the legacy envelope
// version=1 mutation segment keeps its original opaque decoder.
enum class SchemeMutationOp : uint8_t {
  kNone = 0,
  kFlipBit = 1,
  kXorByte = 2,
  kSetZero = 3,
  kSetAllOnes = 4,
  kTruncate = 5,
  kAppendByte = 6,
  kSetByte = 7,
  kSetCoefficient = 8,
  kSetPaddingBit = 9,
  kSwapWords = 10,
  kRotateBytes = 11,
};

enum class SchemeMutationField : uint8_t {
  kNone = 0,
  kSignature = 1,
  kSignatureSalt = 2,
  kSignatureDigestCmt = 3,
  kSignatureDigestChall2 = 4,
  kSignatureY = 5,
  kSignatureV = 6,
  kSignatureResp1 = 7,
  kSignaturePath = 8,
  kSignatureProof = 9,
  kSignatureUnusedSlot = 10,
  kPublicKey = 11,
  kPublicKeySeed = 12,
  kPublicKeySyndrome = 13,
  kMessage = 14,
  kContext = 15,
};

struct SchemeMutation {
  SchemeMutationOp op = SchemeMutationOp::kNone;
  SchemeMutationField field = SchemeMutationField::kNone;
  uint32_t index = 0;
  uint32_t aux = 0;
  std::vector<uint8_t> payload;
};

const char *SchemeMutationOpName(SchemeMutationOp op);
const char *SchemeMutationFieldName(SchemeMutationField field);

// Returns false only for structurally malformed recipes.  An empty input is a
// valid no-op recipe.  Unknown enum bytes are rejected.
bool DecodeSchemeMutation(const uint8_t *data, size_t size, SchemeMutation *out, std::string *error);
bool DecodeSchemeMutation(const std::vector<uint8_t> &input, SchemeMutation *out, std::string *error);
std::vector<uint8_t> EncodeSchemeMutation(const SchemeMutation &mutation);

}  // namespace pqcfuzz

#endif

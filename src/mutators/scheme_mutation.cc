#include "mutators/scheme_mutation.h"

namespace pqcfuzz {
namespace {

constexpr size_t kRecipeHeaderSize = 10;

uint32_t ReadU32Le(const uint8_t *data) {
  return static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) | (static_cast<uint32_t>(data[3]) << 24);
}

void WriteU32Le(uint8_t *out, uint32_t value) {
  out[0] = static_cast<uint8_t>(value & 0xffu);
  out[1] = static_cast<uint8_t>((value >> 8) & 0xffu);
  out[2] = static_cast<uint8_t>((value >> 16) & 0xffu);
  out[3] = static_cast<uint8_t>((value >> 24) & 0xffu);
}

bool IsKnownOp(uint8_t value) {
  return value <= static_cast<uint8_t>(SchemeMutationOp::kRotateBytes);
}

bool IsKnownField(uint8_t value) {
  return value <= static_cast<uint8_t>(SchemeMutationField::kContext);
}

}  // namespace

const char *SchemeMutationOpName(SchemeMutationOp op) {
  switch (op) {
    case SchemeMutationOp::kNone:
      return "none";
    case SchemeMutationOp::kFlipBit:
      return "flip_bit";
    case SchemeMutationOp::kXorByte:
      return "xor_byte";
    case SchemeMutationOp::kSetZero:
      return "set_zero";
    case SchemeMutationOp::kSetAllOnes:
      return "set_all_ones";
    case SchemeMutationOp::kTruncate:
      return "truncate";
    case SchemeMutationOp::kAppendByte:
      return "append_byte";
    case SchemeMutationOp::kSetByte:
      return "set_byte";
    case SchemeMutationOp::kSetCoefficient:
      return "set_coefficient";
    case SchemeMutationOp::kSetPaddingBit:
      return "set_padding_bit";
    case SchemeMutationOp::kSwapWords:
      return "swap_words";
    case SchemeMutationOp::kRotateBytes:
      return "rotate_bytes";
  }
  return "unknown";
}

const char *SchemeMutationFieldName(SchemeMutationField field) {
  switch (field) {
    case SchemeMutationField::kNone:
      return "none";
    case SchemeMutationField::kSignature:
      return "signature";
    case SchemeMutationField::kSignatureSalt:
      return "signature.salt";
    case SchemeMutationField::kSignatureDigestCmt:
      return "signature.digest_cmt";
    case SchemeMutationField::kSignatureDigestChall2:
      return "signature.digest_chall2";
    case SchemeMutationField::kSignatureY:
      return "signature.y";
    case SchemeMutationField::kSignatureV:
      return "signature.v";
    case SchemeMutationField::kSignatureResp1:
      return "signature.resp1";
    case SchemeMutationField::kSignaturePath:
      return "signature.path";
    case SchemeMutationField::kSignatureProof:
      return "signature.proof";
    case SchemeMutationField::kSignatureUnusedSlot:
      return "signature.unused_slot";
    case SchemeMutationField::kPublicKey:
      return "public_key";
    case SchemeMutationField::kPublicKeySeed:
      return "public_key.seed";
    case SchemeMutationField::kPublicKeySyndrome:
      return "public_key.syndrome";
    case SchemeMutationField::kMessage:
      return "message";
    case SchemeMutationField::kContext:
      return "context";
  }
  return "unknown";
}

bool DecodeSchemeMutation(const uint8_t *data, size_t size, SchemeMutation *out, std::string *error) {
  if (out == nullptr) {
    if (error != nullptr) {
      *error = "scheme mutation output pointer is null";
    }
    return false;
  }
  if (size == 0) {
    *out = SchemeMutation{};
    return true;
  }
  if (size < kRecipeHeaderSize) {
    if (error != nullptr) {
      *error = "scheme mutation recipe shorter than its 10-byte header";
    }
    return false;
  }
  if (!IsKnownOp(data[0])) {
    if (error != nullptr) {
      *error = "unknown scheme mutation operation";
    }
    return false;
  }
  if (!IsKnownField(data[1])) {
    if (error != nullptr) {
      *error = "unknown scheme mutation field";
    }
    return false;
  }
  SchemeMutation parsed;
  parsed.op = static_cast<SchemeMutationOp>(data[0]);
  parsed.field = static_cast<SchemeMutationField>(data[1]);
  parsed.index = ReadU32Le(data + 2);
  parsed.aux = ReadU32Le(data + 6);
  parsed.payload.assign(data + kRecipeHeaderSize, data + size);
  *out = std::move(parsed);
  return true;
}

bool DecodeSchemeMutation(const std::vector<uint8_t> &input, SchemeMutation *out, std::string *error) {
  return DecodeSchemeMutation(input.data(), input.size(), out, error);
}

std::vector<uint8_t> EncodeSchemeMutation(const SchemeMutation &mutation) {
  std::vector<uint8_t> out(kRecipeHeaderSize + mutation.payload.size(), 0);
  out[0] = static_cast<uint8_t>(mutation.op);
  out[1] = static_cast<uint8_t>(mutation.field);
  WriteU32Le(out.data() + 2, mutation.index);
  WriteU32Le(out.data() + 6, mutation.aux);
  for (size_t i = 0; i < mutation.payload.size(); ++i) {
    out[kRecipeHeaderSize + i] = mutation.payload[i];
  }
  return out;
}

}  // namespace pqcfuzz

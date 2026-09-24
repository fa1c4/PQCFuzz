#include "mutators/cross_mutator.h"

namespace pqcfuzz {
namespace {

void SetBit(std::vector<uint8_t> *buffer, size_t bit_index) {
  if (buffer == nullptr || bit_index / 8 >= buffer->size()) {
    return;
  }
  (*buffer)[bit_index / 8] |= static_cast<uint8_t>(1u << (bit_index % 8));
}

MutationRecord MakeRecord(
    const std::string &operation,
    const std::string &target,
    size_t offset,
    size_t length) {
  MutationRecord record;
  record.operation = operation;
  record.target = target;
  record.offset = offset;
  record.length = length;
  record.field_parse_status = "ok";
  return record;
}

void ApplyByteOp(
    const SchemeMutation &mutation,
    const std::string &target,
    size_t offset,
    std::vector<uint8_t> *buffer,
    std::vector<MutationRecord> *records) {
  if (buffer == nullptr) {
    return;
  }
  const bool length_changing = mutation.op == SchemeMutationOp::kAppendByte ||
                               mutation.op == SchemeMutationOp::kTruncate;
  if (!length_changing && offset >= buffer->size()) {
    MutationRecord record = MakeRecord(SchemeMutationOpName(mutation.op), target, offset, 0);
    record.skipped = true;
    record.reason = "offset_out_of_range";
    records->push_back(record);
    return;
  }
  const std::vector<uint8_t> original = *buffer;
  MutationRecord record = MakeRecord(SchemeMutationOpName(mutation.op), target, offset, 1);
  switch (mutation.op) {
    case SchemeMutationOp::kSetZero:
      (*buffer)[offset] = 0;
      break;
    case SchemeMutationOp::kSetAllOnes:
      (*buffer)[offset] = 0xFF;
      break;
    case SchemeMutationOp::kXorByte:
      (*buffer)[offset] ^= mutation.payload.empty() ? 0xFF : mutation.payload[0];
      break;
    case SchemeMutationOp::kSetByte:
      (*buffer)[offset] = mutation.payload.empty() ? 0x01 : mutation.payload[0];
      break;
    case SchemeMutationOp::kFlipBit:
      (*buffer)[offset] ^= static_cast<uint8_t>(1u << (mutation.aux % 8));
      record.operation = "flip_bit";
      break;
    case SchemeMutationOp::kAppendByte:
      buffer->push_back(mutation.payload.empty() ? 0xA5 : mutation.payload[0]);
      record.offset = original.size();
      record.length = 1;
      break;
    case SchemeMutationOp::kTruncate:
      buffer->pop_back();
      record.offset = buffer->size();
      break;
    case SchemeMutationOp::kRotateBytes: {
      const uint8_t first = (*buffer)[offset];
      for (size_t i = offset; i + 1 < buffer->size(); ++i) {
        (*buffer)[i] = (*buffer)[i + 1];
      }
      (*buffer)[buffer->size() - 1] = first;
      break;
    }
    default:
      record.skipped = true;
      record.reason = "unsupported_op";
      records->push_back(record);
      return;
  }
  RecordMutationEffect(&record, original, *buffer);
  records->push_back(record);
}

}  // namespace

std::vector<MutationRecord> MutateCrossSignature(
    const CrossParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signature) {
  std::vector<MutationRecord> records;
  if (signature == nullptr || signature->empty()) {
    return records;
  }
  SchemeMutation mutation;
  std::string error;
  if (!DecodeSchemeMutation(mutation_plan, &mutation, &error)) {
    MutationRecord record = MakeRecord("decode", "signature", 0, 0);
    record.skipped = true;
    record.reason = error;
    record.field_parse_status = "decode_error";
    records.push_back(record);
    return records;
  }
  if (mutation.op == SchemeMutationOp::kNone) {
    return records;
  }
  const std::vector<MlKemRegion> regions = CrossSignatureRegions(params, signature->size());
  const auto find_region = [&regions](const std::string &name) -> const MlKemRegion * {
    for (const auto &region : regions) {
      if (region.name == name) {
        return &region;
      }
    }
    return nullptr;
  };
  const size_t append_anchor = signature->size() - 1;

  switch (mutation.field) {
    case SchemeMutationField::kSignature:
      ApplyByteOp(mutation, "signature",
                  (mutation.op == SchemeMutationOp::kAppendByte ||
                   mutation.op == SchemeMutationOp::kTruncate)
                      ? append_anchor
                      : mutation.index,
                  signature, &records);
      return records;
    case SchemeMutationField::kSignatureSalt:
    case SchemeMutationField::kSignatureDigestCmt:
    case SchemeMutationField::kSignatureDigestChall2:
    case SchemeMutationField::kSignaturePath:
    case SchemeMutationField::kSignatureProof:
    case SchemeMutationField::kSignatureResp1: {
      const char *name = mutation.field == SchemeMutationField::kSignatureSalt ? "signature.salt"
                         : mutation.field == SchemeMutationField::kSignatureDigestCmt ? "signature.digest_cmt"
                         : mutation.field == SchemeMutationField::kSignatureDigestChall2 ? "signature.digest_chall2"
                         : mutation.field == SchemeMutationField::kSignaturePath ? "signature.path"
                         : mutation.field == SchemeMutationField::kSignatureProof ? "signature.proof"
                                                                                  : "signature.resp1";
      const MlKemRegion *region = find_region(name);
      if (region == nullptr || region->length == 0) {
        MutationRecord record = MakeRecord(SchemeMutationOpName(mutation.op), name, 0, 0);
        record.skipped = true;
        record.reason = "empty_region";
        records.push_back(record);
        return records;
      }
      const size_t offset = (mutation.op == SchemeMutationOp::kAppendByte ||
                             mutation.op == SchemeMutationOp::kTruncate)
                                ? region->offset + region->length - 1
                                : region->offset + (mutation.index % region->length);
      ApplyByteOp(mutation, name, offset, signature, &records);
      return records;
    }
    case SchemeMutationField::kSignatureUnusedSlot: {
      const MlKemRegion *region = find_region("signature.proof");
      if (region == nullptr || region->length == 0) {
        MutationRecord record = MakeRecord(SchemeMutationOpName(mutation.op), "signature.unused_slot", 0, 0);
        record.skipped = true;
        record.reason = "empty_region";
        records.push_back(record);
        return records;
      }
      const size_t offset = region->offset + region->length - 1 - (mutation.index % region->length);
      ApplyByteOp(mutation, "signature.unused_slot", offset, signature, &records);
      return records;
    }
    case SchemeMutationField::kSignatureY:
    case SchemeMutationField::kSignatureV: {
      const bool is_y = mutation.field == SchemeMutationField::kSignatureY;
      const char *name = is_y ? "signature.y" : "signature.v";
      if (mutation.op == SchemeMutationOp::kSetCoefficient) {
        return MutateCrossPackedCoefficient(params, is_y, mutation.index % params.resp_rounds, mutation.aux, signature);
      }
      if (mutation.op == SchemeMutationOp::kSetPaddingBit) {
        const size_t padding = CrossVectorPaddingBits(params, is_y);
        if (padding == 0) {
          MutationRecord record = MakeRecord("set_padding_bit", name, 0, 0);
          record.skipped = true;
          record.reason = "byte_aligned_vector";
          records.push_back(record);
          return records;
        }
        return MutateCrossPaddingBit(params, is_y, mutation.index % params.resp_rounds,
                                     mutation.aux % padding, signature);
      }
      const size_t round = mutation.index % params.resp_rounds;
      const size_t vector_bytes = is_y ? params.y_bytes : params.v_bytes;
      const size_t base = is_y ? CrossYRoundOffset(params, round) : CrossVRoundOffset(params, round);
      const size_t offset = base + (mutation.aux % vector_bytes);
      ApplyByteOp(mutation, name, offset, signature, &records);
      return records;
    }
    default: {
      MutationRecord record = MakeRecord(SchemeMutationOpName(mutation.op), "signature", mutation.index, 0);
      record.skipped = true;
      record.reason = "field_not_a_signature_region";
      records.push_back(record);
      return records;
    }
  }
}

std::vector<MutationRecord> MutateCrossPublicKey(
    const CrossParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key) {
  std::vector<MutationRecord> records;
  if (public_key == nullptr || public_key->empty()) {
    return records;
  }
  SchemeMutation mutation;
  std::string error;
  if (!DecodeSchemeMutation(mutation_plan, &mutation, &error)) {
    MutationRecord record = MakeRecord("decode", "public_key", 0, 0);
    record.skipped = true;
    record.reason = error;
    record.field_parse_status = "decode_error";
    records.push_back(record);
    return records;
  }
  if (mutation.op == SchemeMutationOp::kNone) {
    return records;
  }
  std::string name = "public_key";
  size_t offset = mutation.index % public_key->size();
  if (mutation.field == SchemeMutationField::kPublicKeySeed) {
    name = "public_key.seed";
    offset = mutation.index % params.seed_bytes;
  } else if (mutation.field == SchemeMutationField::kPublicKeySyndrome) {
    name = "public_key.syndrome";
    offset = params.seed_bytes + (mutation.index % params.syn_bytes);
  }
  ApplyByteOp(mutation, name, offset, public_key, &records);
  return records;
}

std::vector<MutationRecord> MutateCrossMessage(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *message) {
  std::vector<MutationRecord> records;
  if (message == nullptr) {
    return records;
  }
  SchemeMutation mutation;
  std::string error;
  if (!DecodeSchemeMutation(mutation_plan, &mutation, &error)) {
    MutationRecord record = MakeRecord("decode", "message", 0, 0);
    record.skipped = true;
    record.reason = error;
    record.field_parse_status = "decode_error";
    records.push_back(record);
    return records;
  }
  if (mutation.op == SchemeMutationOp::kNone) {
    return records;
  }
  if (mutation.op == SchemeMutationOp::kAppendByte) {
    ApplyByteOp(mutation, "message", message->empty() ? 0 : message->size() - 1, message, &records);
    return records;
  }
  if (message->empty()) {
    MutationRecord record = MakeRecord(SchemeMutationOpName(mutation.op), "message", 0, 0);
    record.skipped = true;
    record.reason = "empty_message";
    records.push_back(record);
    return records;
  }
  ApplyByteOp(mutation, "message", mutation.index % message->size(), message, &records);
  return records;
}

std::vector<MutationRecord> MutateCrossPackedCoefficient(
    const CrossParams &params,
    bool is_y,
    size_t round,
    size_t coefficient,
    std::vector<uint8_t> *signature) {
  std::vector<MutationRecord> records;
  if (signature == nullptr || signature->empty()) {
    return records;
  }
  const size_t width = is_y ? params.y_bits : params.v_bits;
  const size_t count = is_y ? params.n : (params.m > 0 ? params.m : params.n);
  const size_t vector_bytes = is_y ? params.y_bytes : params.v_bytes;
  const size_t base = is_y ? CrossYRoundOffset(params, round % params.resp_rounds)
                           : CrossVRoundOffset(params, round % params.resp_rounds);
  const std::string target = is_y ? "signature.y" : "signature.v";
  if (base + vector_bytes > signature->size()) {
    MutationRecord record = MakeRecord("set_coefficient", target, base, vector_bytes);
    record.skipped = true;
    record.reason = "round_out_of_range";
    records.push_back(record);
    return records;
  }
  const std::vector<uint8_t> original = *signature;
  const size_t first_bit = (coefficient % count) * width;
  for (size_t bit = 0; bit < width; ++bit) {
    SetBit(signature, base * 8 + first_bit + bit);
  }
  MutationRecord record = MakeRecord("set_coefficient", target, base + first_bit / 8, (width + 7) / 8);
  RecordMutationEffect(&record, original, *signature);
  records.push_back(record);
  return records;
}

std::vector<MutationRecord> MutateCrossPaddingBit(
    const CrossParams &params,
    bool is_y,
    size_t round,
    size_t padding_index,
    std::vector<uint8_t> *signature) {
  std::vector<MutationRecord> records;
  if (signature == nullptr || signature->empty()) {
    return records;
  }
  const std::string target = is_y ? "signature.y" : "signature.v";
  const size_t padding_bits = CrossVectorPaddingBits(params, is_y);
  if (padding_bits == 0) {
    MutationRecord record = MakeRecord("set_padding_bit", target, 0, 0);
    record.skipped = true;
    record.reason = "byte_aligned_vector";
    records.push_back(record);
    return records;
  }
  const size_t width = is_y ? params.y_bits : params.v_bits;
  const size_t count = is_y ? params.n : (params.m > 0 ? params.m : params.n);
  const size_t vector_bytes = is_y ? params.y_bytes : params.v_bytes;
  const size_t base = is_y ? CrossYRoundOffset(params, round % params.resp_rounds)
                           : CrossVRoundOffset(params, round % params.resp_rounds);
  if (base + vector_bytes > signature->size()) {
    MutationRecord record = MakeRecord("set_padding_bit", target, base, vector_bytes);
    record.skipped = true;
    record.reason = "round_out_of_range";
    records.push_back(record);
    return records;
  }
  const std::vector<uint8_t> original = *signature;
  const size_t bit_index = width * count + (padding_index % padding_bits);
  SetBit(signature, base * 8 + bit_index);
  MutationRecord record = MakeRecord("set_padding_bit", target, base + bit_index / 8, 1);
  RecordMutationEffect(&record, original, *signature);
  records.push_back(record);
  return records;
}

std::vector<MutationRecord> MutateCrossAbsoluteByte(
    const CrossParams &params,
    size_t byte_offset,
    uint8_t xor_value,
    std::vector<uint8_t> *signature) {
  (void)params;
  std::vector<MutationRecord> records;
  if (signature == nullptr || signature->empty()) {
    return records;
  }
  MutationRecord record = MakeRecord("xor_byte", "signature", byte_offset, 1);
  if (byte_offset >= signature->size()) {
    record.skipped = true;
    record.reason = "offset_out_of_range";
    records.push_back(record);
    return records;
  }
  const std::vector<uint8_t> original = *signature;
  (*signature)[byte_offset] ^= xor_value;
  RecordMutationEffect(&record, original, *signature);
  records.push_back(record);
  return records;
}

}  // namespace pqcfuzz

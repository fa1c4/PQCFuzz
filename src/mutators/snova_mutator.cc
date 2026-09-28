#include "mutators/snova_mutator.h"

#include <cstring>

#include "mutators/scheme_mutation.h"

namespace pqcfuzz {
namespace {

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

bool DecodePlan(const std::vector<uint8_t> &plan, SchemeMutation *mutation, std::vector<MutationRecord> *records,
                const std::string &target) {
  std::string error;
  if (!DecodeSchemeMutation(plan, mutation, &error)) {
    MutationRecord record = MakeRecord("decode", target, 0, 0);
    record.skipped = true;
    record.reason = error;
    record.field_parse_status = "decode_error";
    records->push_back(record);
    return false;
  }
  return mutation->op != SchemeMutationOp::kNone;
}

MutationRecord SetNibbleRecord(
    const std::string &target,
    size_t offset,
    uint8_t value,
    const std::vector<uint8_t> &original,
    const std::vector<uint8_t> &mutated) {
  MutationRecord record = MakeRecord("set_coefficient", target, offset, 1);
  if (offset < original.size()) {
    record.operation = "set_nibble";
    (void)value;
  }
  RecordMutationEffect(&record, original, mutated);
  return record;
}

}  // namespace

std::vector<MutationRecord> MutateSnovaSignature(
    const SnovaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signature) {
  std::vector<MutationRecord> records;
  if (signature == nullptr || signature->empty()) {
    return records;
  }
  SchemeMutation mutation;
  if (!DecodePlan(mutation_plan, &mutation, &records, "signature")) {
    return records;
  }
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
    case SchemeMutationField::kSnovaSignatureSalt: {
      const size_t offset = params.salt_off + (mutation.index % params.salt_bytes);
      ApplyByteOp(mutation, "signature.salt", offset, signature, &records);
      return records;
    }
    case SchemeMutationField::kSnovaSignatureNibble: {
      if (mutation.op == SchemeMutationOp::kSetCoefficient) {
        return MutateSnovaSignatureNibble(params, mutation.index, static_cast<uint8_t>(mutation.aux & 0x0F),
                                          signature);
      }
      if (mutation.op == SchemeMutationOp::kSetPaddingBit) {
        return MutateSnovaSignaturePadding(params, static_cast<uint8_t>(mutation.aux & 0x0F), signature);
      }
      if (mutation.op == SchemeMutationOp::kAppendByte || mutation.op == SchemeMutationOp::kTruncate) {
        ApplyByteOp(mutation, "signature.u", append_anchor, signature, &records);
        return records;
      }
      const size_t nibbles = params.n_matrices * params.sq_rank;
      const size_t offset = SnovaSignatureNibbleOffset(params, mutation.index % (nibbles == 0 ? 1 : nibbles));
      ApplyByteOp(mutation, "signature.u", offset, signature, &records);
      return records;
    }
    case SchemeMutationField::kSignatureUnusedSlot: {
      if (!SnovaSignatureUsesPadding(params)) {
        MutationRecord record = MakeRecord("set_padding_bit", "signature.padding", 0, 0);
        record.skipped = true;
        record.reason = "byte_aligned_signature";
        records.push_back(record);
        return records;
      }
      return MutateSnovaSignaturePadding(params, static_cast<uint8_t>(mutation.aux & 0x0F), signature);
    }
    default: {
      MutationRecord record = MakeRecord(SchemeMutationOpName(mutation.op), "signature", mutation.index, 0);
      record.skipped = true;
      record.reason = "field_not_a_snova_signature_region";
      records.push_back(record);
      return records;
    }
  }
}

std::vector<MutationRecord> MutateSnovaPublicKey(
    const SnovaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key) {
  std::vector<MutationRecord> records;
  if (public_key == nullptr || public_key->empty()) {
    return records;
  }
  SchemeMutation mutation;
  if (!DecodePlan(mutation_plan, &mutation, &records, "public_key")) {
    return records;
  }
  switch (mutation.field) {
    case SchemeMutationField::kSnovaPublicKeySpublic:
    case SchemeMutationField::kPublicKeySeed: {
      const size_t offset = params.spublic_off + (mutation.index % params.public_seed_bytes);
      ApplyByteOp(mutation, "public_key.spublic", offset, public_key, &records);
      return records;
    }
    case SchemeMutationField::kSnovaPublicKeyP22Nibble: {
      if (mutation.op == SchemeMutationOp::kSetCoefficient) {
        return MutateSnovaP22Nibble(params, mutation.index, static_cast<uint8_t>(mutation.aux & 0x0F), public_key);
      }
      const size_t offset = params.p22_off + (mutation.index % (params.pk_len - params.p22_off));
      ApplyByteOp(mutation, "public_key.p22", offset, public_key, &records);
      return records;
    }
    case SchemeMutationField::kPublicKeySyndrome: {
      const size_t offset = params.p22_off + (mutation.index % (params.pk_len - params.p22_off));
      ApplyByteOp(mutation, "public_key.p22", offset, public_key, &records);
      return records;
    }
    default: {
      const size_t offset = mutation.index % public_key->size();
      ApplyByteOp(mutation, "public_key", offset, public_key, &records);
      return records;
    }
  }
}

std::vector<MutationRecord> MutateSnovaPrivateKey(
    const SnovaParams &params,
    bool seed_format,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *private_key) {
  std::vector<MutationRecord> records;
  if (private_key == nullptr || private_key->empty()) {
    return records;
  }
  SchemeMutation mutation;
  if (!DecodePlan(mutation_plan, &mutation, &records, "private_key")) {
    return records;
  }
  const size_t seed_off = params.esk_len - (params.public_seed_bytes + params.private_seed_bytes);
  const size_t pk_seed_off = seed_format ? 0 : seed_off;
  const size_t sk_seed_off = seed_format ? params.public_seed_bytes : seed_off + params.public_seed_bytes;
  switch (mutation.field) {
    case SchemeMutationField::kSnovaPrivateKeyPkSeed:
      ApplyByteOp(mutation, "private_key.pk_seed",
                  pk_seed_off + (mutation.index % params.public_seed_bytes), private_key, &records);
      return records;
    case SchemeMutationField::kSnovaPrivateKeySkSeed:
      ApplyByteOp(mutation, "private_key.sk_seed",
                  sk_seed_off + (mutation.index % params.private_seed_bytes), private_key, &records);
      return records;
    case SchemeMutationField::kSnovaPrivateKeyExpandedByte: {
      if (seed_format) {
        MutationRecord record = MakeRecord(SchemeMutationOpName(mutation.op), "private_key.expanded", 0, 0);
        record.skipped = true;
        record.reason = "seed_format_has_no_expanded_section";
        records.push_back(record);
        return records;
      }
      const size_t expanded_bytes = private_key->size() > seed_off ? seed_off : private_key->size();
      const size_t offset = mutation.index % (expanded_bytes == 0 ? 1 : expanded_bytes);
      ApplyByteOp(mutation, "private_key.expanded", offset, private_key, &records);
      return records;
    }
    case SchemeMutationField::kSecretKey:
    default: {
      ApplyByteOp(mutation, "private_key", mutation.index % private_key->size(), private_key, &records);
      return records;
    }
  }
}

std::vector<MutationRecord> MutateSnovaMessage(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *message) {
  std::vector<MutationRecord> records;
  if (message == nullptr) {
    return records;
  }
  SchemeMutation mutation;
  if (!DecodePlan(mutation_plan, &mutation, &records, "message")) {
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

std::vector<MutationRecord> MutateSnovaSignatureNibble(
    const SnovaParams &params,
    size_t nibble_index,
    uint8_t value,
    std::vector<uint8_t> *signature) {
  std::vector<MutationRecord> records;
  if (signature == nullptr || signature->empty()) {
    return records;
  }
  const size_t nibbles = params.n_matrices * params.sq_rank;
  if (nibbles == 0 || nibble_index >= nibbles) {
    MutationRecord record = MakeRecord("set_nibble", "signature.u", 0, 0);
    record.skipped = true;
    record.reason = "nibble_out_of_range";
    records.push_back(record);
    return records;
  }
  const std::vector<uint8_t> original = *signature;
  if (!SnovaEncodeSignatureNibble(params, signature, nibble_index, value)) {
    MutationRecord record = MakeRecord("set_nibble", "signature.u", SnovaSignatureNibbleOffset(params, nibble_index), 1);
    record.skipped = true;
    record.reason = "nibble_out_of_range";
    records.push_back(record);
    return records;
  }
  records.push_back(SetNibbleRecord("signature.u", SnovaSignatureNibbleOffset(params, nibble_index), value, original,
                                    *signature));
  return records;
}

std::vector<MutationRecord> MutateSnovaP22Nibble(
    const SnovaParams &params,
    size_t nibble_index,
    uint8_t value,
    std::vector<uint8_t> *public_key) {
  std::vector<MutationRecord> records;
  if (public_key == nullptr || public_key->empty()) {
    return records;
  }
  if (params.p22_nibbles == 0 || nibble_index >= params.p22_nibbles) {
    MutationRecord record = MakeRecord("set_nibble", "public_key.p22", 0, 0);
    record.skipped = true;
    record.reason = "nibble_out_of_range";
    records.push_back(record);
    return records;
  }
  const std::vector<uint8_t> original = *public_key;
  if (!SnovaEncodeP22Nibble(params, public_key, nibble_index, value)) {
    MutationRecord record = MakeRecord("set_nibble", "public_key.p22", params.p22_off + nibble_index / 2, 1);
    record.skipped = true;
    record.reason = "nibble_out_of_range";
    records.push_back(record);
    return records;
  }
  records.push_back(SetNibbleRecord("public_key.p22", params.p22_off + nibble_index / 2, value, original, *public_key));
  return records;
}

std::vector<MutationRecord> MutateSnovaSignaturePadding(
    const SnovaParams &params,
    uint8_t value,
    std::vector<uint8_t> *signature) {
  std::vector<MutationRecord> records;
  if (signature == nullptr || signature->empty()) {
    return records;
  }
  if (!SnovaSignatureUsesPadding(params)) {
    MutationRecord record = MakeRecord("set_padding_bit", "signature.padding", 0, 0);
    record.skipped = true;
    record.reason = "byte_aligned_signature";
    records.push_back(record);
    return records;
  }
  const size_t nibbles = params.n_matrices * params.sq_rank;
  const size_t offset = SnovaSignatureNibbleOffset(params, nibbles);
  if (offset >= signature->size()) {
    MutationRecord record = MakeRecord("set_padding_bit", "signature.padding", offset, 1);
    record.skipped = true;
    record.reason = "offset_out_of_range";
    records.push_back(record);
    return records;
  }
  const std::vector<uint8_t> original = *signature;
  (*signature)[offset] = static_cast<uint8_t>(((*signature)[offset] & 0x0F) | ((value & 0x0F) << 4));
  MutationRecord record = MakeRecord("set_padding_bit", "signature.padding", offset, 1);
  RecordMutationEffect(&record, original, *signature);
  records.push_back(record);
  return records;
}

std::vector<MutationRecord> MutateSnovaAbsoluteByte(
    const SnovaParams &params,
    size_t byte_offset,
    uint8_t xor_value,
    std::vector<uint8_t> *buffer) {
  (void)params;
  std::vector<MutationRecord> records;
  if (buffer == nullptr || buffer->empty()) {
    return records;
  }
  MutationRecord record = MakeRecord("xor_byte", "absolute", byte_offset, 1);
  if (byte_offset >= buffer->size()) {
    record.skipped = true;
    record.reason = "offset_out_of_range";
    records.push_back(record);
    return records;
  }
  const std::vector<uint8_t> original = *buffer;
  (*buffer)[byte_offset] ^= xor_value;
  RecordMutationEffect(&record, original, *buffer);
  records.push_back(record);
  return records;
}

}  // namespace pqcfuzz

#include "mutators/ntru_mutator.h"

#include <algorithm>

#include "mutators/scheme_mutation.h"

namespace pqcfuzz {
namespace {

MutationRecord MakeRecord(const std::string &operation, const std::string &target) {
  MutationRecord record;
  record.operation = operation;
  record.target = target;
  return record;
}

MutationRecord SkippedRecord(const std::string &operation, const std::string &target, const std::string &reason) {
  MutationRecord record = MakeRecord(operation, target);
  record.skipped = true;
  record.reason = reason;
  return record;
}

MutationRecord ApplyByteOp(
    std::vector<uint8_t> *buffer,
    size_t offset,
    SchemeMutationOp op,
    uint8_t value,
    const std::string &target) {
  MutationRecord record = MakeRecord(SchemeMutationOpName(op), target);
  record.offset = offset;
  record.length = 1;
  if (buffer == nullptr || offset >= buffer->size()) {
    record.skipped = true;
    record.reason = "offset_out_of_range";
    return record;
  }
  const std::vector<uint8_t> original = *buffer;
  switch (op) {
    case SchemeMutationOp::kSetZero:
      (*buffer)[offset] = 0;
      break;
    case SchemeMutationOp::kSetAllOnes:
      (*buffer)[offset] = 0xFF;
      break;
    case SchemeMutationOp::kXorByte:
      (*buffer)[offset] ^= value;
      break;
    case SchemeMutationOp::kSetByte:
      (*buffer)[offset] = value;
      break;
    case SchemeMutationOp::kFlipBit:
      (*buffer)[offset] ^= static_cast<uint8_t>(1u << (value & 7u));
      break;
    default:
      record.skipped = true;
      record.reason = "unsupported_byte_op";
      return record;
  }
  RecordMutationEffect(&record, original, *buffer);
  return record;
}

}  // namespace

std::vector<MutationRecord> MutateNtruCiphertext(
    const NtruParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *ciphertext) {
  std::vector<MutationRecord> records;
  if (ciphertext == nullptr) {
    return records;
  }
  SchemeMutation recipe;
  std::string decode_error;
  if (!DecodeSchemeMutation(mutation_plan, &recipe, &decode_error)) {
    records.push_back(SkippedRecord("decode", "ciphertext", decode_error));
    return records;
  }
  if (recipe.op == SchemeMutationOp::kNone) {
    records.push_back(SkippedRecord("none", "ciphertext", "no_effect"));
    return records;
  }
  const uint8_t value = recipe.payload.empty() ? static_cast<uint8_t>(recipe.aux & 0xFFu) : recipe.payload[0];
  switch (recipe.field) {
    case SchemeMutationField::kKemCiphertextCoefficient:
    case SchemeMutationField::kSignatureY:
    case SchemeMutationField::kSignatureV:
      records.push_back(
          SetNtruCiphertextCoefficient(params, recipe.index, static_cast<uint16_t>(recipe.aux & 0xFFFFu), ciphertext));
      break;
    case SchemeMutationField::kKemCiphertextPadding:
      records.push_back(SetNtruCiphertextPaddingBit(params, recipe.index, ciphertext));
      break;
    case SchemeMutationField::kKemCiphertext:
    case SchemeMutationField::kSignature:
      records.push_back(ApplyByteOp(ciphertext, recipe.index % std::max<size_t>(ciphertext->size(), 1), recipe.op,
                                    value, "ciphertext"));
      break;
    default:
      records.push_back(SkippedRecord(SchemeMutationFieldName(recipe.field), "ciphertext",
                                      "field_not_a_ciphertext_region"));
      break;
  }
  return records;
}

std::vector<MutationRecord> MutateNtruPublicKey(
    const NtruParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key) {
  std::vector<MutationRecord> records;
  if (public_key == nullptr) {
    return records;
  }
  SchemeMutation recipe;
  std::string decode_error;
  if (!DecodeSchemeMutation(mutation_plan, &recipe, &decode_error)) {
    records.push_back(SkippedRecord("decode", "public_key", decode_error));
    return records;
  }
  if (recipe.op == SchemeMutationOp::kNone) {
    records.push_back(SkippedRecord("none", "public_key", "no_effect"));
    return records;
  }
  const uint8_t value = recipe.payload.empty() ? static_cast<uint8_t>(recipe.aux & 0xFFu) : recipe.payload[0];
  switch (recipe.field) {
    case SchemeMutationField::kKemPublicKeyCoefficient:
      records.push_back(SetNtruPublicKeyCoefficient(params, recipe.index, static_cast<uint16_t>(recipe.aux & 0xFFFFu),
                                                    public_key));
      break;
    case SchemeMutationField::kPublicKey:
    case SchemeMutationField::kPublicKeyPayload:
      records.push_back(ApplyByteOp(public_key, recipe.index % std::max<size_t>(public_key->size(), 1), recipe.op,
                                    value, "public_key"));
      break;
    default:
      records.push_back(SkippedRecord(SchemeMutationFieldName(recipe.field), "public_key",
                                      "field_not_a_public_key_region"));
      break;
  }
  return records;
}

std::vector<MutationRecord> MutateNtruSecretKey(
    const NtruParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *secret_key) {
  std::vector<MutationRecord> records;
  if (secret_key == nullptr) {
    return records;
  }
  SchemeMutation recipe;
  std::string decode_error;
  if (!DecodeSchemeMutation(mutation_plan, &recipe, &decode_error)) {
    records.push_back(SkippedRecord("decode", "secret_key", decode_error));
    return records;
  }
  if (recipe.op == SchemeMutationOp::kNone) {
    records.push_back(SkippedRecord("none", "secret_key", "no_effect"));
    return records;
  }
  const uint8_t value = recipe.payload.empty() ? static_cast<uint8_t>(recipe.aux & 0xFFu) : recipe.payload[0];
  switch (recipe.field) {
    case SchemeMutationField::kKemSecretKeyS3:
      records.push_back(CorruptNtruS3Group(params, recipe.index, value, secret_key));
      break;
    case SchemeMutationField::kKemSecretKeyPrf:
      records.push_back(WriteNtruPrfKeyByte(params, recipe.index, value, secret_key));
      break;
    case SchemeMutationField::kKemSecretKey:
      records.push_back(
          ApplyByteOp(secret_key, recipe.index % std::max<size_t>(secret_key->size(), 1), recipe.op, value,
                      "secret_key"));
      break;
    default:
      records.push_back(SkippedRecord(SchemeMutationFieldName(recipe.field), "secret_key",
                                      "field_not_a_secret_key_region"));
      break;
  }
  return records;
}

MutationRecord SetNtruCiphertextCoefficient(
    const NtruParams &params,
    size_t index,
    uint16_t value,
    std::vector<uint8_t> *ciphertext) {
  MutationRecord record = MakeRecord("set_coefficient", "ciphertext.coefficient");
  if (ciphertext == nullptr || ciphertext->size() < params.bq) {
    record.skipped = true;
    record.reason = "ciphertext_too_short";
    return record;
  }
  std::vector<uint16_t> coefficients;
  std::string error;
  if (!DecodeNtruRq0(ciphertext->data(), ciphertext->size(), params, &coefficients, &error)) {
    record.skipped = true;
    record.reason = "decode_failed";
    record.field_parse_status = error;
    return record;
  }
  const size_t coefficient_index = index % params.n;
  coefficients[coefficient_index] = static_cast<uint16_t>(value % params.q);
  std::vector<uint8_t> payload;
  if (!EncodeNtruRq0(coefficients, params, &payload, &error)) {
    record.skipped = true;
    record.reason = "encode_failed";
    record.field_parse_status = error;
    return record;
  }
  const std::vector<uint8_t> original = *ciphertext;
  for (size_t i = 0; i < payload.size() && i < ciphertext->size(); ++i) {
    (*ciphertext)[i] = payload[i];
  }
  record.offset = 0;
  record.length = payload.size();
  RecordMutationEffect(&record, original, *ciphertext);
  return record;
}

MutationRecord SetNtruCiphertextPaddingBit(
    const NtruParams &params,
    size_t bit_index,
    std::vector<uint8_t> *ciphertext) {
  MutationRecord record = MakeRecord("set_padding_bit", "ciphertext.padding");
  if (!NtruHasCiphertextPadding(params)) {
    record.skipped = true;
    record.reason = "profile_has_no_ciphertext_padding";
    return record;
  }
  if (ciphertext == nullptr || ciphertext->size() < params.ct_len) {
    record.skipped = true;
    record.reason = "ciphertext_too_short";
    return record;
  }
  const size_t local = bit_index % params.tail_unused_bits;
  const unsigned bit = static_cast<unsigned>(8 - params.tail_unused_bits + local);
  const std::vector<uint8_t> original = *ciphertext;
  (*ciphertext)[params.ct_len - 1] |= static_cast<uint8_t>(1u << bit);
  record.offset = params.ct_len - 1;
  record.length = 1;
  RecordMutationEffect(&record, original, *ciphertext);
  return record;
}

MutationRecord SetNtruPublicKeyCoefficient(
    const NtruParams &params,
    size_t index,
    uint16_t value,
    std::vector<uint8_t> *public_key) {
  MutationRecord record = MakeRecord("set_coefficient", "public_key.coefficient");
  if (public_key == nullptr || public_key->size() < params.bq) {
    record.skipped = true;
    record.reason = "public_key_too_short";
    return record;
  }
  std::vector<uint16_t> coefficients;
  std::string error;
  if (!DecodeNtruRq0(public_key->data(), public_key->size(), params, &coefficients, &error)) {
    record.skipped = true;
    record.reason = "decode_failed";
    record.field_parse_status = error;
    return record;
  }
  coefficients[index % params.n] = static_cast<uint16_t>(value % params.q);
  std::vector<uint8_t> payload;
  if (!EncodeNtruRq0(coefficients, params, &payload, &error)) {
    record.skipped = true;
    record.reason = "encode_failed";
    record.field_parse_status = error;
    return record;
  }
  const std::vector<uint8_t> original = *public_key;
  for (size_t i = 0; i < payload.size() && i < public_key->size(); ++i) {
    (*public_key)[i] = payload[i];
  }
  record.offset = 0;
  record.length = payload.size();
  RecordMutationEffect(&record, original, *public_key);
  return record;
}

MutationRecord WriteNtruSecretKeyByte(
    const NtruParams &params,
    size_t offset,
    uint8_t value,
    std::vector<uint8_t> *secret_key) {
  MutationRecord record = MakeRecord("set_byte", "secret_key");
  if (secret_key == nullptr || offset >= secret_key->size() || offset >= params.sk_len) {
    record.skipped = true;
    record.reason = "offset_out_of_range";
    return record;
  }
  const std::vector<uint8_t> original = *secret_key;
  (*secret_key)[offset] = value;
  record.offset = offset;
  record.length = 1;
  RecordMutationEffect(&record, original, *secret_key);
  return record;
}

MutationRecord CorruptNtruS3Group(
    const NtruParams &params,
    size_t group_index,
    uint8_t value,
    std::vector<uint8_t> *secret_key) {
  MutationRecord record = MakeRecord("set_byte", "secret_key.s3");
  const size_t full_groups = (params.n - 1) / 5;
  const bool tail_group = group_index == full_groups && (params.n - 1) % 5 != 0;
  if (secret_key == nullptr || group_index > full_groups || (!tail_group && group_index >= full_groups)) {
    record.skipped = true;
    record.reason = "s3_group_out_of_range";
    return record;
  }
  const size_t offset = group_index;
  if (offset >= secret_key->size()) {
    record.skipped = true;
    record.reason = "offset_out_of_range";
    return record;
  }
  const std::vector<uint8_t> original = *secret_key;
  // Complete 5-trit groups have exactly 243 legal byte values; anything in
  // 243..255 is out of range.  The tail group has only 3^(remaining) legal
  // values; the caller passes the raw byte.
  (*secret_key)[offset] = value;
  record.offset = offset;
  record.length = 1;
  RecordMutationEffect(&record, original, *secret_key);
  return record;
}

MutationRecord WriteNtruPrfKeyByte(
    const NtruParams &params,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *secret_key) {
  MutationRecord record = MakeRecord("set_byte", "secret_key.prf");
  if (secret_key == nullptr || secret_key->size() < params.sk_prf_off + params.prf_key_bytes) {
    record.skipped = true;
    record.reason = "secret_key_too_short";
    return record;
  }
  const size_t offset = params.sk_prf_off + (index % params.prf_key_bytes);
  const std::vector<uint8_t> original = *secret_key;
  (*secret_key)[offset] = value;
  record.offset = offset;
  record.length = 1;
  RecordMutationEffect(&record, original, *secret_key);
  return record;
}

MutationRecord TruncateNtruBuffer(std::vector<uint8_t> *buffer, size_t new_length) {
  MutationRecord record = MakeRecord("truncate", "buffer");
  if (buffer == nullptr || new_length >= buffer->size()) {
    record.skipped = true;
    record.reason = "not_shorter";
    return record;
  }
  const std::vector<uint8_t> original = *buffer;
  buffer->resize(new_length);
  record.length = new_length;
  RecordMutationEffect(&record, original, *buffer);
  return record;
}

}  // namespace pqcfuzz

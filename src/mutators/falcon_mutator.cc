#include "mutators/falcon_mutator.h"

#include <algorithm>
#include <cstring>

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

bool SetPayloadBit(std::vector<uint8_t> *buffer, size_t payload_off, size_t byte_index, unsigned bit_index) {
  const size_t absolute = payload_off + byte_index;
  if (bit_index > 7 || absolute >= buffer->size()) {
    return false;
  }
  (*buffer)[absolute] |= static_cast<uint8_t>(1u << bit_index);
  return true;
}

bool ClearPayloadBit(std::vector<uint8_t> *buffer, size_t payload_off, size_t byte_index, unsigned bit_index) {
  const size_t absolute = payload_off + byte_index;
  if (bit_index > 7 || absolute >= buffer->size()) {
    return false;
  }
  (*buffer)[absolute] &= static_cast<uint8_t>(~(1u << bit_index));
  return true;
}

bool ReadStreamBit(const std::vector<uint8_t> &buffer, size_t payload_off, size_t stream_index) {
  const size_t absolute = payload_off + (stream_index >> 3);
  if (absolute >= buffer.size()) {
    return false;
  }
  return ((buffer[absolute] >> (7 - (stream_index & 7))) & 1u) != 0;
}

bool WriteStreamBit(std::vector<uint8_t> *buffer, size_t payload_off, size_t stream_index, bool value) {
  const size_t absolute = payload_off + (stream_index >> 3);
  if (absolute >= buffer->size()) {
    return false;
  }
  const uint8_t mask = static_cast<uint8_t>(1u << (7 - (stream_index & 7)));
  if (value) {
    (*buffer)[absolute] |= mask;
  } else {
    (*buffer)[absolute] &= static_cast<uint8_t>(~mask);
  }
  return true;
}

MutationRecord ApplyByteOp(
    std::vector<uint8_t> *buffer,
    size_t offset,
    const SchemeMutationOp op,
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

size_t PayloadLengthFor(const FalconParams &params, size_t signature_len) {
  if (signature_len <= params.sig_payload_off) {
    return 0;
  }
  return signature_len - params.sig_payload_off;
}

}  // namespace

std::vector<MutationRecord> MutateFalconSignature(
    const FalconParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signature) {
  std::vector<MutationRecord> records;
  if (signature == nullptr) {
    return records;
  }
  SchemeMutation recipe;
  std::string decode_error;
  if (!DecodeSchemeMutation(mutation_plan, &recipe, &decode_error)) {
    records.push_back(SkippedRecord("decode", "signature", decode_error));
    return records;
  }
  if (recipe.op == SchemeMutationOp::kNone) {
    records.push_back(SkippedRecord("none", "signature", "no_effect"));
    return records;
  }
  const size_t payload_len = PayloadLengthFor(params, signature->size());
  const uint8_t value = recipe.payload.empty() ? static_cast<uint8_t>(recipe.aux & 0xFFu) : recipe.payload[0];

  const auto emit = [&records](MutationRecord record) { records.push_back(std::move(record)); };

  switch (recipe.field) {
    case SchemeMutationField::kSignature:
      emit(ApplyByteOp(signature, recipe.index % std::max<size_t>(signature->size(), 1), recipe.op, value,
                       "signature"));
      break;
    case SchemeMutationField::kSignatureHeader:
      emit(ApplyByteOp(signature, 0, recipe.op == SchemeMutationOp::kXorByte ? SchemeMutationOp::kXorByte
                                                                            : SchemeMutationOp::kSetByte,
                       value, "signature.header"));
      break;
    case SchemeMutationField::kSignatureSalt:
      emit(ApplyByteOp(signature, params.sig_salt_off + (recipe.index % params.salt_len), recipe.op, value,
                       "signature.salt"));
      break;
    case SchemeMutationField::kSignaturePayload:
    case SchemeMutationField::kSignatureUnusedSlot:
      if (payload_len == 0) {
        emit(SkippedRecord(SchemeMutationOpName(recipe.op), "signature.payload", "empty_payload"));
      } else {
        emit(ApplyByteOp(signature, params.sig_payload_off + (recipe.index % payload_len), recipe.op, value,
                         "signature.payload"));
      }
      break;
    case SchemeMutationField::kSignatureCompressedCoefficient:
    case SchemeMutationField::kSignatureY:
    case SchemeMutationField::kSignatureV:
      emit(MutateFalconCoefficient(params, recipe.index, static_cast<int16_t>(recipe.aux & 0xFFFFu), signature));
      break;
    case SchemeMutationField::kSignatureCompressedPadding:
      emit(SetFalconCompressedPaddingBit(params, recipe.index, signature));
      break;
    case SchemeMutationField::kPublicKey:
      break;  // handled by MutateFalconPublicKey
    case SchemeMutationField::kPublicKeyHeader:
      emit(MutateFalconPublicKeyHeader(params, value, signature));
      break;
    case SchemeMutationField::kPublicKeyCoefficient:
      // Reuse the helper on the public key via the caller.
      emit(SkippedRecord("set_coefficient", "public_key.coefficient", "wrong_buffer"));
      break;
    case SchemeMutationField::kMessage:
      emit(SkippedRecord("message", "message", "wrong_buffer"));
      break;
    default:
      emit(SkippedRecord(SchemeMutationFieldName(recipe.field), "signature", "field_not_a_signature_region"));
      break;
  }
  return records;
}

std::vector<MutationRecord> MutateFalconPublicKey(
    const FalconParams &params,
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
    case SchemeMutationField::kPublicKeyHeader:
      records.push_back(MutateFalconPublicKeyHeader(params, value, public_key));
      break;
    case SchemeMutationField::kPublicKeyCoefficient:
      records.push_back(WriteFalconPublicKeyCoefficient(params, recipe.index, static_cast<uint16_t>(recipe.aux & 0xFFFFu),
                                                        public_key));
      break;
    case SchemeMutationField::kPublicKey:
    case SchemeMutationField::kPublicKeyPayload:
      records.push_back(ApplyByteOp(public_key, params.pk_payload_off + (recipe.index % std::max<size_t>(params.pk_payload_len, 1)),
                                    recipe.op, value, "public_key"));
      break;
    case SchemeMutationField::kPublicKeySeed:
    case SchemeMutationField::kPublicKeySyndrome:
      records.push_back(ApplyByteOp(public_key, params.pk_payload_off + (recipe.index % std::max<size_t>(params.pk_payload_len, 1)),
                                    recipe.op, value, "public_key.coefficients"));
      break;
    default:
      records.push_back(SkippedRecord(SchemeMutationFieldName(recipe.field), "public_key", "field_not_a_public_key_region"));
      break;
  }
  return records;
}

std::vector<MutationRecord> MutateFalconMessage(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *message) {
  std::vector<MutationRecord> records;
  if (message == nullptr) {
    return records;
  }
  SchemeMutation recipe;
  std::string decode_error;
  if (!DecodeSchemeMutation(mutation_plan, &recipe, &decode_error)) {
    records.push_back(SkippedRecord("decode", "message", decode_error));
    return records;
  }
  MutationRecord record = MakeRecord(SchemeMutationOpName(recipe.op), "message");
  const std::vector<uint8_t> original = *message;
  switch (recipe.op) {
    case SchemeMutationOp::kNone:
      record.skipped = true;
      record.reason = "no_effect";
      break;
    case SchemeMutationOp::kAppendByte:
      message->push_back(recipe.payload.empty() ? 0x00 : recipe.payload[0]);
      break;
    case SchemeMutationOp::kTruncate:
      if (!message->empty()) {
        message->pop_back();
      }
      break;
    case SchemeMutationOp::kFlipBit: {
      if (message->empty()) {
        record.skipped = true;
        record.reason = "empty_message";
      } else {
        const size_t index = recipe.index % message->size();
        (*message)[index] ^= static_cast<uint8_t>(1u << (recipe.aux & 7u));
        record.offset = index;
      }
      break;
    }
    case SchemeMutationOp::kXorByte:
    case SchemeMutationOp::kSetZero:
    case SchemeMutationOp::kSetAllOnes:
    case SchemeMutationOp::kSetByte: {
      if (message->empty()) {
        record.skipped = true;
        record.reason = "empty_message";
      } else {
        const size_t index = recipe.index % message->size();
        const uint8_t value = recipe.payload.empty() ? static_cast<uint8_t>(recipe.aux & 0xFFu) : recipe.payload[0];
        if (recipe.op == SchemeMutationOp::kXorByte) {
          (*message)[index] ^= value;
        } else if (recipe.op == SchemeMutationOp::kSetZero) {
          (*message)[index] = 0;
        } else if (recipe.op == SchemeMutationOp::kSetAllOnes) {
          (*message)[index] = 0xFF;
        } else {
          (*message)[index] = value;
        }
        record.offset = index;
      }
      break;
    }
    default:
      record.skipped = true;
      record.reason = "unsupported_message_op";
      break;
  }
  RecordMutationEffect(&record, original, *message);
  records.push_back(record);
  return records;
}

std::vector<MutationRecord> MutateFalconSignedMessage(
    const FalconParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signed_message) {
  std::vector<MutationRecord> records;
  if (signed_message == nullptr) {
    return records;
  }
  SchemeMutation recipe;
  std::string decode_error;
  if (!DecodeSchemeMutation(mutation_plan, &recipe, &decode_error)) {
    records.push_back(SkippedRecord("decode", "signed_message", decode_error));
    return records;
  }
  if (recipe.op == SchemeMutationOp::kNone) {
    records.push_back(SkippedRecord("none", "signed_message", "no_effect"));
    return records;
  }
  if (signed_message->size() < 2) {
    records.push_back(SkippedRecord(SchemeMutationOpName(recipe.op), "signed_message.frame", "frame_too_short"));
    return records;
  }
  const uint8_t value = recipe.payload.empty() ? static_cast<uint8_t>(recipe.aux & 0xFFu) : recipe.payload[0];
  if (recipe.field == SchemeMutationField::kSignedMessageFrame) {
    records.push_back(ApplyByteOp(signed_message, recipe.index % signed_message->size(), recipe.op, value,
                                  "signed_message.frame"));
    return records;
  }
  records.push_back(ApplyByteOp(signed_message, recipe.index % signed_message->size(), recipe.op, value,
                                "signed_message"));
  return records;
}

MutationRecord MutateFalconSignatureHeader(
    const FalconParams &params,
    uint8_t header,
    std::vector<uint8_t> *signature) {
  MutationRecord record = MakeRecord("set_header", "signature.header");
  if (signature == nullptr || signature->empty()) {
    record.skipped = true;
    record.reason = "empty_signature";
    return record;
  }
  const std::vector<uint8_t> original = *signature;
  (void)params;
  (*signature)[0] = header;
  record.offset = 0;
  record.length = 1;
  RecordMutationEffect(&record, original, *signature);
  return record;
}

MutationRecord MutateFalconSaltByte(
    const FalconParams &params,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *signature) {
  MutationRecord record = MakeRecord("set_byte", "signature.salt");
  if (signature == nullptr || params.salt_len == 0 || signature->size() < params.sig_salt_off + params.salt_len) {
    record.skipped = true;
    record.reason = "signature_too_short";
    return record;
  }
  const size_t offset = params.sig_salt_off + (index % params.salt_len);
  const std::vector<uint8_t> original = *signature;
  (*signature)[offset] = value;
  record.offset = offset;
  record.length = 1;
  RecordMutationEffect(&record, original, *signature);
  return record;
}

MutationRecord MutateFalconCoefficient(
    const FalconParams &params,
    size_t index,
    int16_t value,
    std::vector<uint8_t> *signature) {
  MutationRecord record = MakeRecord("set_coefficient", "signature.payload");
  if (signature == nullptr || signature->size() <= params.sig_payload_off) {
    record.skipped = true;
    record.reason = "empty_payload";
    return record;
  }
  const std::vector<uint8_t> original = *signature;
  std::vector<int16_t> coefficients;
  size_t consumed = 0;
  std::string error;
  const uint8_t *payload = signature->data() + params.sig_payload_off;
  const size_t payload_len = signature->size() - params.sig_payload_off;
  bool ok = params.format == FalconFormat::kCt
                ? DecodeFalconCtPayload(payload, payload_len, params, &coefficients, &consumed, &error)
                : DecodeFalconCompressedPayload(payload, payload_len, params, &coefficients, &consumed, &error);
  if (!ok) {
    record.skipped = true;
    record.reason = "payload_decode_failed";
    record.field_parse_status = error;
    return record;
  }
  const size_t coefficient_index = index % static_cast<size_t>(params.n);
  coefficients[coefficient_index] = value;
  std::vector<uint8_t> payload_out;
  ok = params.format == FalconFormat::kCt
           ? EncodeFalconCtPayload(coefficients, params, &payload_out, &error)
           : EncodeFalconCompressedPayload(coefficients, params, &payload_out, &error);
  if (!ok) {
    record.skipped = true;
    record.reason = "payload_encode_failed";
    record.field_parse_status = error;
    return record;
  }
  std::vector<uint8_t> rebuilt = *signature;
  const size_t rebuilt_payload_len = payload_out.size() + params.sig_payload_off;
  if (rebuilt.size() > rebuilt_payload_len) {
    rebuilt.resize(rebuilt_payload_len);
  } else {
    rebuilt.resize(std::max(rebuilt.size(), rebuilt_payload_len), 0);
  }
  for (size_t i = 0; i < payload_out.size(); ++i) {
    rebuilt[params.sig_payload_off + i] = payload_out[i];
  }
  *signature = std::move(rebuilt);
  record.offset = params.sig_payload_off;
  record.length = payload_out.size();
  RecordMutationEffect(&record, original, *signature);
  return record;
}

MutationRecord SetFalconCompressedNegativeZeroBit(
    const FalconParams &params,
    size_t coefficient_index,
    std::vector<uint8_t> *signature) {
  MutationRecord record = MakeRecord("set_sign_bit", "signature.compressed_negative_zero");
  if (signature == nullptr || signature->size() <= params.sig_payload_off) {
    record.skipped = true;
    record.reason = "empty_payload";
    return record;
  }
  const uint8_t *payload = signature->data() + params.sig_payload_off;
  const size_t payload_len = signature->size() - params.sig_payload_off;
  std::vector<int16_t> coefficients;
  size_t consumed = 0;
  std::vector<size_t> coefficient_offsets;
  std::string error;
  if (!DecodeFalconCompressedPayloadEx(payload, payload_len, params, &coefficients, &consumed, nullptr,
                                       &coefficient_offsets, nullptr, &error)) {
    record.skipped = true;
    record.reason = "payload_decode_failed";
    record.field_parse_status = error;
    return record;
  }
  const size_t index = coefficient_index % static_cast<size_t>(params.n);
  if (coefficients[index] != 0) {
    record.skipped = true;
    record.reason = "coefficient_not_zero";
    return record;
  }
  const size_t bit_offset = coefficient_offsets[index];
  const size_t byte_index = bit_offset >> 3;
  const unsigned bit_index = static_cast<unsigned>(bit_offset & 7);
  const std::vector<uint8_t> original = *signature;
  if (!SetPayloadBit(signature, params.sig_payload_off, byte_index, bit_index)) {
    record.skipped = true;
    record.reason = "bit_offset_out_of_range";
    return record;
  }
  record.offset = params.sig_payload_off + byte_index;
  record.length = 1;
  RecordMutationEffect(&record, original, *signature);
  return record;
}

MutationRecord ClearFalconCompressedTerminatorBit(
    const FalconParams &params,
    size_t coefficient_index,
    std::vector<uint8_t> *signature) {
  MutationRecord record = MakeRecord("clear_terminator", "signature.compressed_terminator");
  if (signature == nullptr || signature->size() <= params.sig_payload_off) {
    record.skipped = true;
    record.reason = "empty_payload";
    return record;
  }
  const uint8_t *payload = signature->data() + params.sig_payload_off;
  const size_t payload_len = signature->size() - params.sig_payload_off;
  std::vector<int16_t> coefficients;
  size_t consumed = 0;
  std::vector<size_t> terminator_offsets;
  std::string error;
  if (!DecodeFalconCompressedPayloadEx(payload, payload_len, params, &coefficients, &consumed, nullptr, nullptr,
                                       &terminator_offsets, &error)) {
    record.skipped = true;
    record.reason = "payload_decode_failed";
    record.field_parse_status = error;
    return record;
  }
  const size_t index = coefficient_index % static_cast<size_t>(params.n);
  const size_t bit_offset = terminator_offsets[index];
  const size_t byte_index = bit_offset >> 3;
  const unsigned bit_index = static_cast<unsigned>(bit_offset & 7);
  const std::vector<uint8_t> original = *signature;
  if (!ClearPayloadBit(signature, params.sig_payload_off, byte_index, bit_index)) {
    record.skipped = true;
    record.reason = "bit_offset_out_of_range";
    return record;
  }
  record.offset = params.sig_payload_off + byte_index;
  record.length = 1;
  RecordMutationEffect(&record, original, *signature);
  return record;
}

MutationRecord SetFalconCompressedPaddingBit(
    const FalconParams &params,
    size_t bit_index,
    std::vector<uint8_t> *signature) {
  MutationRecord record = MakeRecord("set_padding_bit", "signature.compressed_padding");
  if (signature == nullptr || signature->size() <= params.sig_payload_off) {
    record.skipped = true;
    record.reason = "empty_payload";
    return record;
  }
  const uint8_t *payload = signature->data() + params.sig_payload_off;
  const size_t payload_len = signature->size() - params.sig_payload_off;
  std::vector<int16_t> coefficients;
  size_t consumed = 0;
  size_t trailing_bits = 0;
  std::string error;
  if (!DecodeFalconCompressedPayloadEx(payload, payload_len, params, &coefficients, &consumed, &trailing_bits,
                                       nullptr, nullptr, &error)) {
    record.skipped = true;
    record.reason = "payload_decode_failed";
    record.field_parse_status = error;
    return record;
  }
  if (trailing_bits == 0 || consumed == 0) {
    record.skipped = true;
    record.reason = "byte_aligned_payload";
    return record;
  }
  const size_t local_bit = bit_index % trailing_bits;
  const std::vector<uint8_t> original = *signature;
  if (!SetPayloadBit(signature, params.sig_payload_off, consumed - 1, static_cast<unsigned>(local_bit))) {
    record.skipped = true;
    record.reason = "bit_offset_out_of_range";
    return record;
  }
  record.offset = params.sig_payload_off + consumed - 1;
  record.length = 1;
  RecordMutationEffect(&record, original, *signature);
  return record;
}

MutationRecord ShiftFalconCompressedPayload(
    const FalconParams &params,
    int direction,
    std::vector<uint8_t> *signature) {
  MutationRecord record = MakeRecord(direction >= 0 ? "insert_bit" : "delete_bit", "signature.compressed_bits");
  if (signature == nullptr || signature->size() <= params.sig_payload_off) {
    record.skipped = true;
    record.reason = "empty_payload";
    return record;
  }
  const std::vector<uint8_t> original = *signature;
  const size_t payload_bits = (signature->size() - params.sig_payload_off) * 8;
  if (direction >= 0) {
    for (size_t i = payload_bits; i > 1; --i) {
      WriteStreamBit(signature, params.sig_payload_off, i - 1,
                     ReadStreamBit(*signature, params.sig_payload_off, i - 2));
    }
    WriteStreamBit(signature, params.sig_payload_off, 0, false);
  } else {
    for (size_t i = 1; i < payload_bits; ++i) {
      WriteStreamBit(signature, params.sig_payload_off, i - 1,
                     ReadStreamBit(*signature, params.sig_payload_off, i));
    }
    WriteStreamBit(signature, params.sig_payload_off, payload_bits - 1, false);
  }
  record.offset = params.sig_payload_off;
  record.length = signature->size() - params.sig_payload_off;
  RecordMutationEffect(&record, original, *signature);
  return record;
}

MutationRecord MutateFalconPublicKeyHeader(
    const FalconParams &params,
    uint8_t header,
    std::vector<uint8_t> *public_key) {
  MutationRecord record = MakeRecord("set_header", "public_key.header");
  if (public_key == nullptr || public_key->empty()) {
    record.skipped = true;
    record.reason = "empty_public_key";
    return record;
  }
  const std::vector<uint8_t> original = *public_key;
  (void)params;
  (*public_key)[0] = header;
  record.offset = 0;
  record.length = 1;
  RecordMutationEffect(&record, original, *public_key);
  return record;
}

MutationRecord WriteFalconPublicKeyCoefficient(
    const FalconParams &params,
    size_t index,
    uint16_t value,
    std::vector<uint8_t> *public_key) {
  MutationRecord record = MakeRecord("set_coefficient", "public_key.coefficients");
  if (public_key == nullptr || public_key->size() < params.pk_payload_off + params.pk_payload_len) {
    record.skipped = true;
    record.reason = "public_key_too_short";
    return record;
  }
  const size_t coefficient_index = index % static_cast<size_t>(params.n);
  const size_t bit_offset = coefficient_index * 14;
  const std::vector<uint8_t> original = *public_key;
  for (size_t i = 0; i < 14; ++i) {
    const size_t stream = bit_offset + i;
    const size_t byte = params.pk_payload_off + (stream >> 3);
    const unsigned bit = static_cast<unsigned>(7 - (stream & 7));
    const bool set = ((value >> (13 - i)) & 1u) != 0;
    if (set) {
      (*public_key)[byte] |= static_cast<uint8_t>(1u << bit);
    } else {
      (*public_key)[byte] &= static_cast<uint8_t>(~(1u << bit));
    }
  }
  record.offset = params.pk_payload_off + (bit_offset >> 3);
  record.length = 2;
  RecordMutationEffect(&record, original, *public_key);
  return record;
}

MutationRecord TruncateFalconBuffer(std::vector<uint8_t> *buffer, size_t new_length) {
  MutationRecord record = MakeRecord("truncate", "buffer");
  if (buffer == nullptr) {
    record.skipped = true;
    record.reason = "null_buffer";
    return record;
  }
  const std::vector<uint8_t> original = *buffer;
  if (new_length >= buffer->size()) {
    record.skipped = true;
    record.reason = "not_shorter";
    return record;
  }
  buffer->resize(new_length);
  record.length = new_length;
  RecordMutationEffect(&record, original, *buffer);
  return record;
}

MutationRecord AppendFalconByte(std::vector<uint8_t> *buffer, uint8_t value) {
  MutationRecord record = MakeRecord("append_byte", "buffer");
  if (buffer == nullptr) {
    record.skipped = true;
    record.reason = "null_buffer";
    return record;
  }
  const std::vector<uint8_t> original = *buffer;
  buffer->push_back(value);
  record.offset = buffer->size() - 1;
  record.length = 1;
  RecordMutationEffect(&record, original, *buffer);
  return record;
}

bool FindFalconCompressedZeroCoefficient(
    const FalconParams &params,
    const std::vector<uint8_t> &signature,
    size_t *index) {
  if (index == nullptr || signature.size() <= params.sig_payload_off) {
    return false;
  }
  std::vector<int16_t> coefficients;
  size_t consumed = 0;
  std::string error;
  if (!DecodeFalconCompressedPayload(signature.data() + params.sig_payload_off,
                                     signature.size() - params.sig_payload_off, params, &coefficients, &consumed,
                                     &error)) {
    return false;
  }
  for (size_t i = 0; i < coefficients.size(); ++i) {
    if (coefficients[i] == 0) {
      *index = i;
      return true;
    }
  }
  return false;
}

}  // namespace pqcfuzz

#include "mutators/sike_mutator.h"

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

void SikeBigAddOne(SikeBig *value) {
  for (size_t i = 0; i < SikeBig::kLimbs; ++i) {
    if (value->limb[i] != ~static_cast<uint64_t>(0)) {
      value->limb[i] += 1;
      return;
    }
    value->limb[i] = 0;
  }
}

void SikeBigSubOne(SikeBig *value) {
  for (size_t i = 0; i < SikeBig::kLimbs; ++i) {
    if (value->limb[i] != 0) {
      value->limb[i] -= 1;
      return;
    }
    value->limb[i] = ~static_cast<uint64_t>(0);
  }
}

bool BoundaryBytes(const SikeBig &p, SikeFpValue value, size_t np, std::vector<uint8_t> *out) {
  if (out == nullptr || np == 0) {
    return false;
  }
  out->assign(np, 0);
  switch (value) {
    case SikeFpValue::kPrimeMinusOne: {
      SikeBig q = p;
      SikeBigSubOne(&q);
      SikeBigToLeBytes(q, out->data(), np);
      break;
    }
    case SikeFpValue::kPrime:
      SikeBigToLeBytes(p, out->data(), np);
      break;
    case SikeFpValue::kPrimePlusOne: {
      SikeBig q = p;
      SikeBigAddOne(&q);
      SikeBigToLeBytes(q, out->data(), np);
      break;
    }
    case SikeFpValue::kAllOnes:
      std::fill(out->begin(), out->end(), 0xFF);
      break;
  }
  return true;
}

MutationRecord WriteCoordinate(
    const std::string &target,
    size_t offset,
    const std::vector<uint8_t> &value,
    std::vector<uint8_t> *buffer) {
  MutationRecord record = MakeRecord("set_fp2_coordinate", target);
  record.offset = offset;
  record.length = value.size();
  if (buffer == nullptr || value.empty() || offset > buffer->size() || value.size() > buffer->size() - offset) {
    record.skipped = true;
    record.reason = "coordinate_out_of_range";
    return record;
  }
  const std::vector<uint8_t> original = *buffer;
  std::copy(value.begin(), value.end(), buffer->begin() + static_cast<long>(offset));
  RecordMutationEffect(&record, original, *buffer);
  return record;
}

MutationRecord WriteByte(
    const std::string &target,
    size_t offset,
    uint8_t value,
    std::vector<uint8_t> *buffer,
    size_t limit) {
  MutationRecord record = MakeRecord("set_byte", target);
  record.offset = offset;
  record.length = 1;
  if (buffer == nullptr || offset >= limit || offset >= buffer->size()) {
    record.skipped = true;
    record.reason = "offset_out_of_range";
    return record;
  }
  const std::vector<uint8_t> original = *buffer;
  (*buffer)[offset] = value;
  RecordMutationEffect(&record, original, *buffer);
  return record;
}

}  // namespace

MutationRecord SetSikeCiphertextCoordinate(
    const SikeParams &params,
    size_t coordinate,
    const std::vector<uint8_t> &value,
    std::vector<uint8_t> *ciphertext) {
  if (ciphertext == nullptr || coordinate >= 2 * SikeCiphertextCoordinateCount()) {
    return SkippedRecord("set_fp2_coordinate", "sike.ciphertext.coordinate", "coordinate_out_of_range");
  }
  // Fp2 coordinate `coordinate / 2`, limb `coordinate % 2` (real then imag).
  const size_t offset = coordinate * params.np;
  return WriteCoordinate("sike.ciphertext.coordinate", offset, value, ciphertext);
}

MutationRecord SetSikeCiphertextCoordinateBoundary(
    const SikeParams &params,
    size_t coordinate,
    SikeFpValue value,
    std::vector<uint8_t> *ciphertext) {
  SikeBig p;
  std::vector<uint8_t> bytes;
  if (!ComputeSikeFieldPrime(params.e2, params.e3, &p) || !BoundaryBytes(p, value, params.np, &bytes)) {
    return SkippedRecord("set_fp2_coordinate", "sike.ciphertext.coordinate", "field_prime_unavailable");
  }
  return SetSikeCiphertextCoordinate(params, coordinate, bytes, ciphertext);
}

MutationRecord SetSikePublicKeyCoordinateBoundary(
    const SidhParams &params,
    size_t coordinate,
    SikeFpValue value,
    std::vector<uint8_t> *public_key) {
  if (public_key == nullptr || coordinate >= 6) {
    return SkippedRecord("set_fp2_coordinate", "sidh.peer_public_key", "coordinate_out_of_range");
  }
  SikeBig p;
  std::vector<uint8_t> bytes;
  if (!ComputeSikeFieldPrime(params.e2, params.e3, &p) || !BoundaryBytes(p, value, params.np, &bytes)) {
    return SkippedRecord("set_fp2_coordinate", "sidh.peer_public_key", "field_prime_unavailable");
  }
  return WriteCoordinate("sidh.peer_public_key", coordinate * params.np, bytes, public_key);
}

MutationRecord SetSikeCiphertextC1Byte(
    const SikeParams &params,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *ciphertext) {
  return WriteByte("sike.ciphertext.c1", params.c1_off + index, value, ciphertext, params.c1_off + params.msg_bytes);
}

MutationRecord FlipSikeCiphertextC1Bit(
    const SikeParams &params,
    size_t bit_index,
    std::vector<uint8_t> *ciphertext) {
  const size_t byte_index = bit_index / 8;
  MutationRecord record = MakeRecord("flip_bit", "sike.ciphertext.c1");
  record.offset = params.c1_off + byte_index;
  record.length = 1;
  if (ciphertext == nullptr || byte_index >= params.msg_bytes ||
      params.c1_off + byte_index >= ciphertext->size()) {
    record.skipped = true;
    record.reason = "offset_out_of_range";
    return record;
  }
  const std::vector<uint8_t> original = *ciphertext;
  (*ciphertext)[params.c1_off + byte_index] ^= static_cast<uint8_t>(1u << (bit_index % 8));
  RecordMutationEffect(&record, original, *ciphertext);
  return record;
}

MutationRecord WriteSikeSecretKeySByte(
    const SikeParams &params,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *secret_key) {
  return WriteByte("sike.secret_key.s", params.sk_s_off + index, value, secret_key,
                   params.sk_s_off + params.msg_bytes);
}

MutationRecord WriteSikeSecretKeySk3Byte(
    const SikeParams &params,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *secret_key) {
  return WriteByte("sike.secret_key.sk3", params.sk_sk3_off + index, value, secret_key,
                   params.sk_sk3_off + params.nsk3);
}

MutationRecord WriteSikeSecretKeyEmbeddedPkByte(
    const SikeParams &params,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *secret_key) {
  return WriteByte("sike.secret_key.pk3", params.sk_pk_off + index, value, secret_key,
                   params.sk_pk_off + params.pk_len);
}

MutationRecord WriteSidhSecretKeyScalarByte(
    size_t scalar_len,
    size_t index,
    uint8_t value,
    std::vector<uint8_t> *secret_key) {
  return WriteByte("sidh.secret_key.scalar", index, value, secret_key, scalar_len);
}

MutationRecord TruncateSikeBuffer(std::vector<uint8_t> *buffer, size_t new_length) {
  MutationRecord record = MakeRecord("truncate", "buffer");
  if (buffer == nullptr) {
    record.skipped = true;
    record.reason = "null_buffer";
    return record;
  }
  record.offset = new_length;
  record.length = buffer->size() > new_length ? buffer->size() - new_length : 0;
  if (new_length >= buffer->size()) {
    record.skipped = true;
    record.reason = "not_a_truncation";
    return record;
  }
  const std::vector<uint8_t> original = *buffer;
  buffer->resize(new_length);
  RecordMutationEffect(&record, original, *buffer);
  return record;
}

MutationRecord AppendSikeBufferByte(std::vector<uint8_t> *buffer, uint8_t value) {
  MutationRecord record = MakeRecord("append_byte", "buffer");
  if (buffer == nullptr) {
    record.skipped = true;
    record.reason = "null_buffer";
    return record;
  }
  record.offset = buffer->size();
  record.length = 1;
  const std::vector<uint8_t> original = *buffer;
  buffer->push_back(value);
  RecordMutationEffect(&record, original, *buffer);
  return record;
}

namespace {

MutationRecord ApplyByteOp(
    std::vector<uint8_t> *buffer,
    size_t offset,
    size_t limit,
    SchemeMutationOp op,
    uint8_t value,
    const std::string &target) {
  if (op == SchemeMutationOp::kTruncate) {
    return TruncateSikeBuffer(buffer, offset);
  }
  if (op == SchemeMutationOp::kAppendByte) {
    return AppendSikeBufferByte(buffer, value);
  }
  MutationRecord record = MakeRecord(SchemeMutationOpName(op), target);
  record.offset = offset;
  record.length = 1;
  if (buffer == nullptr || offset >= buffer->size() || offset >= limit) {
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

std::vector<MutationRecord> MutateSikeCiphertext(
    const SikeParams &params,
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
    case SchemeMutationField::kSikeCiphertextCoordinate:
      records.push_back(SetSikeCiphertextCoordinateBoundary(
          params, recipe.index % (2 * SikeCiphertextCoordinateCount()),
          static_cast<SikeFpValue>(recipe.aux % 4), ciphertext));
      break;
    case SchemeMutationField::kSikeCiphertextC1:
      records.push_back(ApplyByteOp(ciphertext, params.c1_off + (recipe.index % std::max<size_t>(params.msg_bytes, 1)),
                                    params.c1_off + params.msg_bytes, recipe.op, value, "sike.ciphertext.c1"));
      break;
    case SchemeMutationField::kSikeCiphertextC0:
    case SchemeMutationField::kKemCiphertext:
    case SchemeMutationField::kSignature:
      records.push_back(ApplyByteOp(ciphertext, recipe.index % std::max<size_t>(params.c0_len, 1), params.c0_len,
                                    recipe.op, value, "sike.ciphertext.c0"));
      break;
    default:
      records.push_back(SkippedRecord(SchemeMutationFieldName(recipe.field), "ciphertext",
                                      "field_not_a_ciphertext_region"));
      break;
  }
  return records;
}

std::vector<MutationRecord> MutateSikeSecretKey(
    const SikeParams &params,
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
    case SchemeMutationField::kSikeSecretKeyS:
      records.push_back(WriteSikeSecretKeySByte(params, recipe.index % std::max<size_t>(params.msg_bytes, 1), value,
                                                secret_key));
      break;
    case SchemeMutationField::kSikeSecretKeySk3:
      records.push_back(WriteSikeSecretKeySk3Byte(params, recipe.index % std::max<size_t>(params.nsk3, 1), value,
                                                  secret_key));
      break;
    case SchemeMutationField::kSikeSecretKeyPk3:
      records.push_back(WriteSikeSecretKeyEmbeddedPkByte(
          params, recipe.index % std::max<size_t>(params.pk_len, 1), value, secret_key));
      break;
    case SchemeMutationField::kKemSecretKey:
    case SchemeMutationField::kSecretKey:
      records.push_back(ApplyByteOp(secret_key, recipe.index % std::max<size_t>(params.sk_len, 1), params.sk_len,
                                    recipe.op, value, "secret_key"));
      break;
    default:
      records.push_back(SkippedRecord(SchemeMutationFieldName(recipe.field), "secret_key",
                                      "field_not_a_secret_key_region"));
      break;
  }
  return records;
}

std::vector<MutationRecord> MutateSikePublicKey(
    const SikeParams &params,
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
    case SchemeMutationField::kSikePublicKeyCoordinate:
    case SchemeMutationField::kSikeCiphertextCoordinate: {
      std::vector<uint8_t> bytes;
      SikeBig p;
      if (!ComputeSikeFieldPrime(params.e2, params.e3, &p) ||
          !BoundaryBytes(p, static_cast<SikeFpValue>(recipe.aux % 4), params.np, &bytes)) {
        records.push_back(SkippedRecord("set_fp2_coordinate", "sike.public_key.coordinate",
                                        "field_prime_unavailable"));
        break;
      }
      records.push_back(WriteCoordinate("sike.public_key.coordinate",
                                        (recipe.index % (2 * SikePublicKeyCoordinateCount())) * params.np, bytes,
                                        public_key));
      break;
    }
    case SchemeMutationField::kPublicKey:
      records.push_back(ApplyByteOp(public_key, recipe.index % std::max<size_t>(params.pk_len, 1), params.pk_len,
                                    recipe.op, value, "public_key"));
      break;
    default:
      records.push_back(SkippedRecord(SchemeMutationFieldName(recipe.field), "public_key",
                                      "field_not_a_public_key_region"));
      break;
  }
  return records;
}

}  // namespace pqcfuzz

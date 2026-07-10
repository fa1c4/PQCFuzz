#include "mutators/ml_kem_mutator.h"

#include <algorithm>

namespace pqcfuzz {
namespace {

const char *OperationName(uint8_t op) {
  switch (op % 8) {
    case 0:
      return "flip_bit";
    case 1:
      return "xor_byte";
    case 2:
      return "set_zero";
    case 3:
      return "set_0xff";
    case 4:
      return "truncate";
    case 5:
      return "append_trailing_garbage";
    case 6:
      return "coefficient_region_xor";
    case 7:
      return "coefficient_region_zero";
  }
  return "flip_bit";
}

size_t ByteFromPlan(const std::vector<uint8_t> &plan, size_t index, size_t fallback) {
  if (index < plan.size()) {
    return plan[index];
  }
  return fallback;
}

MutationRecord ApplyMutationToRegions(
    const std::vector<MlKemRegion> &regions,
    const std::vector<uint8_t> &plan,
    std::vector<uint8_t> *buffer) {
  MutationRecord record;
  const std::vector<uint8_t> original = buffer == nullptr ? std::vector<uint8_t>{} : *buffer;
  if (buffer == nullptr) {
    record.skipped = true;
    record.reason = "missing buffer";
    RecordMutationEffect(&record, original, original);
    return record;
  }
  if (regions.empty()) {
    record.skipped = true;
    record.reason = "missing ML-KEM regions";
    RecordMutationEffect(&record, original, *buffer);
    return record;
  }
  const uint8_t op_byte = static_cast<uint8_t>(ByteFromPlan(plan, 0, 0));
  const auto &region = regions[ByteFromPlan(plan, 1, 0) % regions.size()];
  record.operation = OperationName(op_byte);
  record.target = region.name;
  record.offset = region.offset;
  record.length = region.length;

  if (region.offset >= buffer->size() || region.length == 0) {
    record.skipped = true;
    record.reason = "target region outside buffer";
    RecordMutationEffect(&record, original, *buffer);
    return record;
  }

  const size_t region_len = std::min(region.length, buffer->size() - region.offset);
  const size_t relative = ByteFromPlan(plan, 2, 0) % region_len;
  const size_t offset = region.offset + relative;
  const uint8_t value = static_cast<uint8_t>(ByteFromPlan(plan, 3, 0xa5));
  record.offset = offset;
  record.length = 1;

  switch (op_byte % 8) {
    case 0:
      (*buffer)[offset] ^= static_cast<uint8_t>(1u << (value % 8));
      break;
    case 1:
      (*buffer)[offset] ^= value;
      break;
    case 2:
      (*buffer)[offset] = 0;
      break;
    case 3:
      (*buffer)[offset] = 0xff;
      break;
    case 4: {
      const size_t new_size = region.offset + (ByteFromPlan(plan, 2, 0) % (region_len + 1));
      const size_t bounded_new_size = std::min(new_size, buffer->size());
      record.length = buffer->size() - bounded_new_size;
      buffer->resize(bounded_new_size);
      break;
    }
    case 5:
      buffer->push_back(value);
      record.offset = buffer->size() - 1;
      break;
    case 6:
      for (size_t i = 0; i < region_len; ++i) {
        (*buffer)[region.offset + i] ^= value;
      }
      record.offset = region.offset;
      record.length = region_len;
      break;
    case 7:
      std::fill(buffer->begin() + static_cast<std::ptrdiff_t>(region.offset),
                buffer->begin() + static_cast<std::ptrdiff_t>(region.offset + region_len),
                0);
      record.offset = region.offset;
      record.length = region_len;
      break;
  }
  RecordMutationEffect(&record, original, *buffer);
  return record;
}

}  // namespace

std::vector<MutationRecord> MutateMlKemCiphertext(
    const MlKemParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *ciphertext) {
  return {ApplyMutationToRegions(CiphertextRegions(params), mutation_plan, ciphertext)};
}

std::vector<MutationRecord> MutateMlKemPublicKey(
    const MlKemParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key) {
  return {ApplyMutationToRegions(PublicKeyRegions(params), mutation_plan, public_key)};
}

}  // namespace pqcfuzz

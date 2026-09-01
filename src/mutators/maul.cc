#include "mutators/maul.h"

#include <algorithm>

namespace pqcfuzz {
namespace {

size_t PlanByte(const std::vector<uint8_t> &mutation, size_t index, size_t fallback) {
  if (index < mutation.size()) {
    return mutation[index];
  }
  return fallback;
}

const char *OperationName(size_t op) {
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
      return "replace_with_all_zero";
    case 7:
      return "replace_with_reused_seed";
  }
  return "flip_bit";
}

const char *FixedSizeOperationName(size_t op) {
  switch (op % 6) {
    case 0:
      return "flip_bit";
    case 1:
      return "xor_byte";
    case 2:
      return "set_zero";
    case 3:
      return "set_0xff";
    case 4:
      return "replace_with_all_zero";
    case 5:
      return "replace_with_reused_seed";
  }
  return "flip_bit";
}

void ApplyFixedSizeOperation(
    size_t op,
    size_t offset,
    uint8_t value,
    const std::vector<uint8_t> &mutation,
    std::vector<uint8_t> *mutated,
    MutationRecord *record) {
  record->operation = FixedSizeOperationName(op);
  record->offset = offset;
  record->length = mutated->empty() ? 0 : 1;
  switch (op % 6) {
    case 0:
      (*mutated)[offset] ^= static_cast<uint8_t>(1u << (value % 8));
      break;
    case 1:
      (*mutated)[offset] ^= value;
      break;
    case 2:
      (*mutated)[offset] = 0;
      break;
    case 3:
      (*mutated)[offset] = 0xff;
      break;
    case 4:
      std::fill(mutated->begin(), mutated->end(), 0);
      record->offset = 0;
      record->length = mutated->size();
      break;
    case 5:
      if (mutation.empty()) {
        std::fill(mutated->begin(), mutated->end(), 0);
      } else {
        for (size_t i = 0; i < mutated->size(); ++i) {
          (*mutated)[i] = mutation[i % mutation.size()];
        }
      }
      record->offset = 0;
      record->length = mutated->size();
      break;
  }
}

}  // namespace

MaulResult MaulBytes(
    const std::vector<uint8_t> &input,
    const std::vector<uint8_t> &mutation,
    const std::string &field_name) {
  MaulResult result;
  result.mutated = input;
  const size_t op = PlanByte(mutation, 0, 0);
  result.record.operation = OperationName(op);
  result.record.target = field_name;
  result.record.offset = 0;
  result.record.length = input.empty() ? 0 : 1;
  result.record.field_parse_status = "generic_byte_field";

  if (input.empty() && op % 8 != 5 && op % 8 != 7) {
    result.record.skipped = true;
    result.record.reason = "empty field";
    RecordMutationEffect(&result.record, input, result.mutated);
    return result;
  }

  const uint8_t value = static_cast<uint8_t>(PlanByte(mutation, 3, 0xa5));
  const size_t offset = input.empty() ? 0 : PlanU16(mutation, 1, 0) % input.size();
  result.record.offset = offset;

  switch (op % 8) {
    case 0:
      result.mutated[offset] ^= static_cast<uint8_t>(1u << (value % 8));
      break;
    case 1:
      result.mutated[offset] ^= value;
      break;
    case 2:
      result.mutated[offset] = 0;
      break;
    case 3:
      result.mutated[offset] = 0xff;
      break;
    case 4: {
      // Include the original size in the planned domain so the common
      // equality check can explicitly quarantine a no-op truncation.
      const size_t new_size = input.empty() ? 0 : PlanU16(mutation, 1, 0) % (input.size() + 1);
      result.mutated.resize(new_size);
      result.record.length = input.size() - new_size;
      break;
    }
    case 5:
      result.mutated.push_back(value);
      result.record.offset = result.mutated.size() - 1;
      break;
    case 6:
      std::fill(result.mutated.begin(), result.mutated.end(), 0);
      result.record.offset = 0;
      result.record.length = result.mutated.size();
      break;
    case 7:
      if (mutation.empty()) {
        result.mutated.assign(input.size(), 0);
      } else {
        result.mutated.resize(input.size());
        for (size_t i = 0; i < result.mutated.size(); ++i) {
          result.mutated[i] = mutation[i % mutation.size()];
        }
      }
      result.record.offset = 0;
      result.record.length = result.mutated.size();
      break;
  }
  RecordMutationEffect(&result.record, input, result.mutated);
  return result;
}

MaulResult MaulBytesFixedSize(
    const std::vector<uint8_t> &input,
    const std::vector<uint8_t> &mutation,
    const std::string &field_name) {
  MaulResult result;
  result.mutated = input;
  const size_t op = PlanByte(mutation, 0, 0);
  result.record.operation = FixedSizeOperationName(op);
  result.record.target = field_name;
  result.record.offset = 0;
  result.record.length = input.empty() ? 0 : 1;
  result.record.field_parse_status = "fixed_size_byte_field";

  if (input.empty()) {
    result.record.skipped = true;
    result.record.reason = "empty field";
    RecordMutationEffect(&result.record, input, result.mutated);
    return result;
  }

  const uint8_t value = static_cast<uint8_t>(PlanByte(mutation, 3, 0xa5));
  const size_t offset = PlanU16(mutation, 1, 0) % input.size();
  ApplyFixedSizeOperation(op, offset, value, mutation, &result.mutated, &result.record);
  RecordMutationEffect(&result.record, input, result.mutated);
  if (result.record.effective) {
    return result;
  }

  result.mutated = input;
  ApplyFixedSizeOperation(0, offset, value == 0 ? 1 : value, mutation, &result.mutated, &result.record);
  RecordMutationEffect(&result.record, input, result.mutated);
  return result;
}

}  // namespace pqcfuzz

#include "mutators/slh_dsa_mutator.h"

#include <algorithm>

namespace pqcfuzz {
namespace {

const char *OperationName(uint8_t op) {
  switch (op % 12) {
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
      return "mutate_R";
    case 7:
      return "mutate_SIGFORS";
    case 8:
      return "mutate_SIGHT";
    case 9:
      return "mutate_WOTS";
    case 10:
      return "mutate_XMSS_AUTH_PATH";
    case 11:
      return "mutate_ctx";
  }
  return "flip_bit";
}

size_t ByteFromPlan(const std::vector<uint8_t> &plan, size_t index, size_t fallback) {
  if (index < plan.size()) {
    return plan[index];
  }
  return fallback;
}

MutationRecord ApplyRegionMutation(
    const std::vector<MlKemRegion> &regions,
    const std::vector<uint8_t> &plan,
    const std::string &fallback_target,
    std::vector<uint8_t> *buffer) {
  MutationRecord record;
  const std::vector<uint8_t> original = buffer == nullptr ? std::vector<uint8_t>{} : *buffer;
  record.field_parse_status = "parsed";
  if (buffer == nullptr) {
    record.skipped = true;
    record.reason = "missing buffer";
    RecordMutationEffect(&record, original, original);
    return record;
  }
  if (buffer->empty()) {
    buffer->push_back(static_cast<uint8_t>(ByteFromPlan(plan, 3, 0xa5)));
    record.field_parse_status = "fallback_byte_range";
  }

  const uint8_t op_byte = static_cast<uint8_t>(ByteFromPlan(plan, 0, 0));
  size_t region_index = ByteFromPlan(plan, 1, 0);
  if (op_byte % 12 >= 6 && op_byte % 12 <= 10) {
    region_index = (op_byte % 12) - 6;
  }

  MlKemRegion region{fallback_target, 0, buffer->size()};
  if (!regions.empty()) {
    region = regions[region_index % regions.size()];
  }
  if (region.length == 0 || region.offset >= buffer->size()) {
    region = {fallback_target, 0, buffer->size()};
    record.field_parse_status = "fallback_byte_range";
  }

  record.operation = OperationName(op_byte);
  record.target = region.name;
  const size_t region_len = std::min(region.length, buffer->size() - region.offset);
  const size_t relative = ByteFromPlan(plan, 2, 0) % std::max<size_t>(region_len, 1);
  const size_t offset = std::min(region.offset + relative, buffer->size() - 1);
  const uint8_t value = static_cast<uint8_t>(ByteFromPlan(plan, 3, 0xa5));
  record.offset = offset;
  record.length = 1;

  switch (op_byte % 12) {
    case 0:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
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
      const size_t new_size = ByteFromPlan(plan, 2, 0) % (buffer->size() + 1);
      record.length = buffer->size() - new_size;
      buffer->resize(new_size);
      break;
    }
    case 5:
      buffer->push_back(value);
      record.offset = buffer->size() - 1;
      break;
  }
  RecordMutationEffect(&record, original, *buffer);
  return record;
}

std::vector<MlKemRegion> SingleRegion(const std::string &name, const std::vector<uint8_t> *buffer) {
  return {{name, 0, buffer == nullptr ? 0 : buffer->size()}};
}

}  // namespace

std::vector<MutationRecord> MutateSlhDsaSignature(
    const SlhDsaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signature) {
  const size_t sig_len = signature == nullptr ? params.sig_max_len : signature->size();
  return {ApplyRegionMutation(SlhDsaSignatureRegions(params, sig_len), mutation_plan, "signature", signature)};
}

std::vector<MutationRecord> MutateSlhDsaMessage(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *message) {
  return {ApplyRegionMutation(SingleRegion("message", message), mutation_plan, "message", message)};
}

std::vector<MutationRecord> MutateSlhDsaContext(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *context) {
  return {ApplyRegionMutation(SingleRegion("ctx", context), mutation_plan, "ctx", context)};
}

std::vector<MutationRecord> MutateSlhDsaPublicKey(
    const SlhDsaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key) {
  return {ApplyRegionMutation(SlhDsaPublicKeyRegions(params), mutation_plan, "public_key", public_key)};
}

}  // namespace pqcfuzz

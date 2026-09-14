#include "mutators/ml_dsa_mutator.h"

#include <algorithm>

namespace pqcfuzz {
namespace {

const char *OperationName(uint8_t op) {
  switch (op % 11) {
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
      return "mutate_signature_c";
    case 7:
      return "mutate_signature_z";
    case 8:
      return "mutate_signature_h";
    case 9:
      return "mutate_ctx";
    case 10:
      return "mutate_oid";
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
  record.field_parse_status = "fallback_byte_range";
  if (buffer == nullptr) {
    record.skipped = true;
    record.reason = "missing buffer";
    RecordMutationEffect(&record, original, original);
    return record;
  }
  if (buffer->empty()) {
    buffer->push_back(static_cast<uint8_t>(ByteFromPlan(plan, 4, 0xa5)));
  }

  const uint8_t op_byte = static_cast<uint8_t>(ByteFromPlan(plan, 0, 0));
  size_t region_index = ByteFromPlan(plan, 1, 0);
  if (op_byte % 11 == 6 && regions.size() > 0) {
    region_index = 0;
  } else if (op_byte % 11 == 7 && regions.size() > 1) {
    region_index = 1;
  } else if (op_byte % 11 == 8 && regions.size() > 2) {
    region_index = 2;
  }

  MlKemRegion region{fallback_target, 0, buffer->size()};
  if (!regions.empty()) {
    region = regions[region_index % regions.size()];
  }
  if (region.length == 0 || region.offset >= buffer->size()) {
    region = {fallback_target, 0, buffer->size()};
  }

  record.operation = OperationName(op_byte);
  record.target = region.name;
  const size_t region_len = std::min(region.length, buffer->size() - region.offset);
  const size_t relative = PlanU16(plan, 2, 0) % std::max<size_t>(region_len, 1);
  const size_t offset = std::min(region.offset + relative, buffer->size() - 1);
  const uint8_t value = static_cast<uint8_t>(ByteFromPlan(plan, 4, 0xa5));
  record.offset = offset;
  record.length = 1;

  switch (op_byte % 11) {
    case 0:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
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
      const size_t new_size = PlanU16(plan, 2, 0) % (buffer->size() + 1);
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

std::vector<MutationRecord> MutateMlDsaSignature(
    const MlDsaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signature) {
  const size_t sig_len = signature == nullptr ? params.sig_max_len : signature->size();
  return {ApplyRegionMutation(MlDsaSignatureRegions(params, sig_len), mutation_plan, "signature", signature)};
}

std::vector<MutationRecord> MutateMlDsaMessage(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *message) {
  return {ApplyRegionMutation(SingleRegion("message", message), mutation_plan, "message", message)};
}

std::vector<MutationRecord> MutateMlDsaContext(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *context) {
  return {ApplyRegionMutation(SingleRegion("ctx", context), mutation_plan, "ctx", context)};
}

std::vector<MutationRecord> MutateMlDsaOid(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *oid) {
  return {ApplyRegionMutation(SingleRegion("oid", oid), mutation_plan, "oid", oid)};
}

std::vector<MutationRecord> MutateMlDsaPublicKey(
    const MlDsaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key) {
  return {ApplyRegionMutation(MlDsaPublicKeyRegions(params), mutation_plan, "public_key", public_key)};
}

std::vector<MutationRecord> MutateMlDsaHintCanonical(
    const MlDsaParams &params,
    MlDsaHintMutation mutation,
    std::vector<uint8_t> *signature) {
  MutationRecord record;
  record.target = "signature.h";
  const std::vector<uint8_t> original = signature == nullptr ? std::vector<uint8_t>{} : *signature;
  if (signature == nullptr) {
    record.skipped = true;
    record.reason = "missing buffer";
    RecordMutationEffect(&record, original, original);
    return {record};
  }
  const size_t h_offset = params.c_bytes + (signature->size() > params.c_bytes + params.omega + params.k
                                                 ? signature->size() - params.c_bytes - (params.omega + params.k)
                                                 : 0);
  const size_t h_len = params.omega + params.k;
  if (signature->size() < h_offset + h_len || params.k < 2 || params.omega == 0) {
    record.skipped = true;
    record.reason = "signature is not full size for hint canonicality mutation";
    RecordMutationEffect(&record, original, *signature);
    return {record};
  }
  uint8_t *h = signature->data() + h_offset;
  const size_t first_count = std::min<size_t>(h[0], params.omega);
  const size_t second_count = std::min<size_t>(h[1], params.omega);

  switch (mutation) {
    case MlDsaHintMutation::kCountRollback:
      record.operation = "hint_count_rollback";
      if (h[0] > 0) {
        // Make the second cumulative count smaller than the first.
        h[1] = static_cast<uint8_t>(h[0] - 1);
        record.offset = h_offset + 1;
      } else {
        // Raise the first count above a zero second count.
        h[0] = 1;
        record.offset = h_offset;
      }
      record.length = 1;
      break;
    case MlDsaHintMutation::kCountOverflow:
      record.operation = "hint_count_overflow";
      h[0] = static_cast<uint8_t>(params.omega + 1);
      record.offset = h_offset;
      record.length = 1;
      break;
    case MlDsaHintMutation::kNonIncreasingIndex:
      record.operation = "hint_non_increasing_index";
      if (second_count <= first_count + 1) {
        record.skipped = true;
        record.reason = "no polynomial has two or more hint positions";
        break;
      }
      // Duplicate an adjacent position inside the second polynomial.
      h[params.k + first_count] = h[params.k + first_count + 1];
      record.offset = h_offset + params.k + first_count;
      record.length = 1;
      break;
    case MlDsaHintMutation::kTrailingNonZero:
      record.operation = "hint_trailing_non_zero";
      if (second_count >= params.omega) {
        record.skipped = true;
        record.reason = "hint position array is full";
        break;
      }
      h[params.k + second_count] = 0xFF;
      record.offset = h_offset + params.k + second_count;
      record.length = 1;
      break;
  }
  RecordMutationEffect(&record, original, *signature);
  return {record};
}

namespace {

void WriteBitsLittleEndian(uint8_t *buffer, size_t bit_offset, size_t bit_count, uint64_t value) {
  for (size_t i = 0; i < bit_count; ++i) {
    const size_t bit = bit_offset + i;
    const uint8_t mask = static_cast<uint8_t>(1u << (bit % 8));
    if (((value >> i) & 1u) != 0) {
      buffer[bit / 8] |= mask;
    } else {
      buffer[bit / 8] &= static_cast<uint8_t>(~mask);
    }
  }
}

}  // namespace

std::vector<MutationRecord> MutateMlDsaZNormBoundary(
    const MlDsaParams &params,
    MlDsaZNormMutation mutation,
    std::vector<uint8_t> *signature) {
  MutationRecord record;
  record.target = "signature.z";
  const std::vector<uint8_t> original = signature == nullptr ? std::vector<uint8_t>{} : *signature;
  if (signature == nullptr) {
    record.skipped = true;
    record.reason = "missing buffer";
    RecordMutationEffect(&record, original, original);
    return {record};
  }
  const size_t h_len = params.omega + params.k;
  if (params.gamma1_bits == 0 || params.gamma1 == 0 || signature->size() < params.c_bytes + h_len) {
    record.skipped = true;
    record.reason = "signature is not full size or profile lacks response bounds";
    RecordMutationEffect(&record, original, *signature);
    return {record};
  }
  const size_t z_offset = params.c_bytes;
  const size_t z_len = signature->size() - z_offset - h_len;
  const size_t z_bits = z_len * 8;
  if (params.gamma1_bits > z_bits) {
    record.skipped = true;
    record.reason = "signature z region is too small for a packed coefficient";
    RecordMutationEffect(&record, original, *signature);
    return {record};
  }
  uint64_t encoded = 0;
  switch (mutation) {
    case MlDsaZNormMutation::kValidBoundary:
      record.operation = "z_norm_valid_boundary";
      encoded = static_cast<uint64_t>(params.beta) + 1;
      break;
    case MlDsaZNormMutation::kOverBoundary:
      record.operation = "z_norm_over_boundary";
      encoded = static_cast<uint64_t>(params.beta);
      break;
    case MlDsaZNormMutation::kNegativeOverBoundary:
      record.operation = "z_norm_negative_over_boundary";
      encoded = 2ull * params.gamma1 - params.beta;
      break;
  }
  const uint64_t limit = 1ull << params.gamma1_bits;
  if (encoded >= limit) {
    record.skipped = true;
    record.reason = "encoded boundary value does not fit the packed coefficient";
    RecordMutationEffect(&record, original, *signature);
    return {record};
  }
  WriteBitsLittleEndian(signature->data() + z_offset, 0, params.gamma1_bits, encoded);
  record.offset = z_offset;
  record.length = (params.gamma1_bits + 7) / 8;
  record.field_parse_status = "packed z coefficient boundary value";
  RecordMutationEffect(&record, original, *signature);
  return {record};
}

}  // namespace pqcfuzz

#include "mutators/snova_layout.h"

#include <algorithm>
#include <cstring>

namespace pqcfuzz {
namespace {

constexpr size_t kPublicSeedBytes = 16;
constexpr size_t kPrivateSeedBytes = 32;
constexpr size_t kSaltBytes = 16;

constexpr SnovaParams kSnovaParams[] = {
    {"SNOVA-R2-37-17-16-2-AES", "AES", 37, 17, 2, 1, 9842, 48, 91440, 124, false},
    {"SNOVA-R2-37-17-16-2-SHAKE", "SHAKE", 37, 17, 2, 1, 9842, 48, 91440, 124, true},
    {"SNOVA-R2-25-8-16-3-AES", "AES", 25, 8, 3, 1, 2320, 48, 39576, 165, false},
    {"SNOVA-R2-25-8-16-3-SHAKE", "SHAKE", 25, 8, 3, 1, 2320, 48, 39576, 165, true},
    {"SNOVA-R2-24-5-16-4-AES", "AES", 24, 5, 4, 1, 1016, 48, 36848, 248, false},
    {"SNOVA-R2-24-5-16-4-SHAKE", "SHAKE", 24, 5, 4, 1, 1016, 48, 36848, 248, true},
    {"SNOVA-R2-56-25-16-2-AES", "AES", 56, 25, 2, 3, 31266, 48, 300848, 178, false},
    {"SNOVA-R2-56-25-16-2-SHAKE", "SHAKE", 56, 25, 2, 3, 31266, 48, 300848, 178, true},
    {"SNOVA-R2-49-11-16-3-AES", "AES", 49, 11, 3, 3, 6006, 48, 177060, 286, false},
    {"SNOVA-R2-49-11-16-3-SHAKE", "SHAKE", 49, 11, 3, 3, 6006, 48, 177060, 286, true},
    {"SNOVA-R2-37-8-16-4-AES", "AES", 37, 8, 4, 3, 4112, 48, 133040, 376, false},
    {"SNOVA-R2-37-8-16-4-SHAKE", "SHAKE", 37, 8, 4, 3, 4112, 48, 133040, 376, true},
    {"SNOVA-R2-24-5-16-5-AES", "AES", 24, 5, 5, 3, 1579, 48, 60048, 379, false},
    {"SNOVA-R2-24-5-16-5-SHAKE", "SHAKE", 24, 5, 5, 3, 1579, 48, 60048, 379, true},
    {"SNOVA-R2-75-33-16-2-AES", "AES", 75, 33, 2, 5, 71890, 48, 704532, 232, false},
    {"SNOVA-R2-75-33-16-2-SHAKE", "SHAKE", 75, 33, 2, 5, 71890, 48, 704532, 232, true},
    {"SNOVA-R2-66-15-16-3-AES", "AES", 66, 15, 3, 5, 15204, 48, 435423, 381, false},
    {"SNOVA-R2-66-15-16-3-SHAKE", "SHAKE", 66, 15, 3, 5, 15204, 48, 435423, 381, true},
    {"SNOVA-R2-60-10-16-4-AES", "AES", 60, 10, 4, 5, 8016, 48, 395248, 576, false},
    {"SNOVA-R2-60-10-16-4-SHAKE", "SHAKE", 60, 10, 4, 5, 8016, 48, 395248, 576, true},
    {"SNOVA-R2-29-6-16-5-AES", "AES", 29, 6, 5, 5, 2716, 48, 100398, 454, false},
    {"SNOVA-R2-29-6-16-5-SHAKE", "SHAKE", 29, 6, 5, 5, 2716, 48, 100398, 454, true},
};

size_t CeilHalf(size_t nibbles) { return (nibbles + 1) / 2; }

const SnovaParams *FinalizedParams(size_t index) {
  static SnovaParams finalized[sizeof(kSnovaParams) / sizeof(kSnovaParams[0])];
  static bool initialized[sizeof(kSnovaParams) / sizeof(kSnovaParams[0])] = {};
  if (initialized[index]) {
    return &finalized[index];
  }
  finalized[index] = kSnovaParams[index];
  SnovaParams &params = finalized[index];
  params.n_matrices = params.v + params.o;
  params.m_matrices = params.o;
  params.sq_rank = params.l * params.l;
  params.alpha_terms = params.sq_rank + params.l;
  // FIXED_ABQ=2 in the pinned build: l < 4 profiles use the fixed SNOVA ABQ block.
  params.fixed_abq = params.l < 4;
  params.signature_data_bytes = params.sig_max_len >= kSaltBytes ? params.sig_max_len - kSaltBytes : 0;
  params.public_seed_bytes = kPublicSeedBytes;
  params.private_seed_bytes = kPrivateSeedBytes;
  params.salt_bytes = kSaltBytes;
  params.hash_nibbles = params.m_matrices * params.sq_rank;
  params.hash_bytes = CeilHalf(params.hash_nibbles);
  params.u_off = 0;
  params.salt_off = params.signature_data_bytes;
  params.spublic_off = 0;
  params.p22_off = kPublicSeedBytes;
  params.p22_nibbles = params.m_matrices * params.o * params.o * params.sq_rank;
  params.seed_section_bytes = params.esk_len >= (kPublicSeedBytes + kPrivateSeedBytes)
                                  ? params.esk_len - (kPublicSeedBytes + kPrivateSeedBytes)
                                  : 0;
  const size_t m = params.m_matrices;
  const size_t v = params.v;
  const size_t o = params.o;
  const size_t lsq = params.sq_rank;
  const size_t alpha = params.alpha_terms;
  size_t cursor = 0;
  params.expand_p22_nibble_off = cursor;
  cursor += m * o * o * lsq;
  params.expand_p11_nibble_off = cursor;
  cursor += m * v * v * lsq;
  params.expand_p12_nibble_off = cursor;
  cursor += m * v * o * lsq;
  params.expand_p21_nibble_off = cursor;
  cursor += m * o * v * lsq;
  params.expand_a_nibble_off = cursor;
  cursor += m * alpha * lsq;
  params.expand_b_nibble_off = cursor;
  cursor += m * alpha * lsq;
  params.expand_q1_nibble_off = cursor;
  cursor += m * alpha * lsq;
  params.expand_q2_nibble_off = cursor;
  cursor += m * alpha * lsq;
  params.expanded_data_nibbles = cursor;
  params.expanded_pk_len = kPublicSeedBytes + CeilHalf(cursor);
  initialized[index] = true;
  return &params;
}

}  // namespace

bool GetSnovaParams(const std::string &algorithm, SnovaParams *params) {
  const size_t count = sizeof(kSnovaParams) / sizeof(kSnovaParams[0]);
  for (size_t index = 0; index < count; ++index) {
    const SnovaParams *candidate = FinalizedParams(index);
    if (std::strcmp(candidate->algorithm, algorithm.c_str()) == 0) {
      if (params != nullptr) {
        *params = *candidate;
      }
      return true;
    }
  }
  return false;
}

std::vector<MlKemRegion> SnovaSignatureRegions(const SnovaParams &params, size_t signature_len) {
  std::vector<MlKemRegion> regions;
  const size_t data_len = std::min(params.signature_data_bytes, signature_len);
  const size_t salt_len = signature_len > params.salt_off ? std::min(params.salt_bytes, signature_len - params.salt_off) : 0;
  regions.push_back({"signature.u", params.u_off, data_len});
  regions.push_back({"signature.salt", params.salt_off, salt_len});
  return regions;
}

std::vector<MlKemRegion> SnovaPublicKeyRegions(const SnovaParams &params) {
  std::vector<MlKemRegion> regions;
  regions.push_back({"public_key.spublic", params.spublic_off, params.public_seed_bytes});
  regions.push_back({"public_key.p22", params.p22_off, params.pk_len > params.p22_off ? params.pk_len - params.p22_off : 0});
  return regions;
}

size_t SnovaSignatureNibbleOffset(const SnovaParams &params, size_t nibble_index) {
  (void)params;
  return nibble_index / 2;
}

size_t SnovaMatrixNibbleIndex(const SnovaParams &params, size_t matrix, size_t row, size_t col) {
  return matrix * params.sq_rank + row * params.l + col;
}

bool SnovaDecodeSignatureNibble(const SnovaParams &params, const std::vector<uint8_t> &signature,
                                size_t nibble_index, uint8_t *value) {
  if (value == nullptr || nibble_index >= params.n_matrices * params.sq_rank) {
    return false;
  }
  const size_t offset = SnovaSignatureNibbleOffset(params, nibble_index);
  if (offset >= signature.size()) {
    return false;
  }
  const uint8_t byte = signature[offset];
  *value = (nibble_index % 2 == 0) ? static_cast<uint8_t>(byte & 0x0F) : static_cast<uint8_t>((byte >> 4) & 0x0F);
  return true;
}

bool SnovaEncodeSignatureNibble(const SnovaParams &params, std::vector<uint8_t> *signature,
                                size_t nibble_index, uint8_t value) {
  if (signature == nullptr || nibble_index >= params.n_matrices * params.sq_rank) {
    return false;
  }
  const size_t offset = SnovaSignatureNibbleOffset(params, nibble_index);
  if (offset >= signature->size()) {
    return false;
  }
  const uint8_t nibble = static_cast<uint8_t>(value & 0x0F);
  uint8_t &byte = (*signature)[offset];
  if (nibble_index % 2 == 0) {
    byte = static_cast<uint8_t>((byte & 0xF0) | nibble);
  } else {
    byte = static_cast<uint8_t>((byte & 0x0F) | (nibble << 4));
  }
  return true;
}

bool SnovaDecodeP22Nibble(const SnovaParams &params, const std::vector<uint8_t> &public_key,
                          size_t nibble_index, uint8_t *value) {
  if (value == nullptr || nibble_index >= params.p22_nibbles) {
    return false;
  }
  const size_t offset = params.p22_off + nibble_index / 2;
  if (offset >= public_key.size()) {
    return false;
  }
  const uint8_t byte = public_key[offset];
  *value = (nibble_index % 2 == 0) ? static_cast<uint8_t>(byte & 0x0F) : static_cast<uint8_t>((byte >> 4) & 0x0F);
  return true;
}

bool SnovaEncodeP22Nibble(const SnovaParams &params, std::vector<uint8_t> *public_key,
                          size_t nibble_index, uint8_t value) {
  if (public_key == nullptr || nibble_index >= params.p22_nibbles) {
    return false;
  }
  const size_t offset = params.p22_off + nibble_index / 2;
  if (offset >= public_key->size()) {
    return false;
  }
  const uint8_t nibble = static_cast<uint8_t>(value & 0x0F);
  uint8_t &byte = (*public_key)[offset];
  if (nibble_index % 2 == 0) {
    byte = static_cast<uint8_t>((byte & 0xF0) | nibble);
  } else {
    byte = static_cast<uint8_t>((byte & 0x0F) | (nibble << 4));
  }
  return true;
}

bool SnovaSignatureUsesPadding(const SnovaParams &params) {
  return (params.n_matrices * params.sq_rank) % 2 == 1;
}

size_t SnovaSignaturePaddingNibbleIndex(const SnovaParams &params) {
  const size_t nibbles = params.n_matrices * params.sq_rank;
  // The padding nibble is the high half of the final data byte, i.e. the
  // nibble immediately after the last GF16 element.
  return nibbles;
}

}  // namespace pqcfuzz

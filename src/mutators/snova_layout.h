#ifndef PQCFUZZ_MUTATORS_SNOVA_LAYOUT_H
#define PQCFUZZ_MUTATORS_SNOVA_LAYOUT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {

// One SNOVA round-2 parameter set/backend.  q=16, so every field element is a
// GF16 nibble.  The signature is U (n=v+o matrices) followed by a 16-byte salt;
// the public key is spublic[16] followed by P22 (m=o matrices).  The expanded
// secret key (ESK) uses the implementation's cut-in-half nibble packing and is
// much larger than the 48-byte seed secret key (SSK).
struct SnovaParams {
  const char *algorithm;
  const char *backend;  // "AES" or "SHAKE"
  size_t v;
  size_t o;
  size_t l;
  size_t category;
  size_t pk_len;
  size_t ssk_len;  // 48
  size_t esk_len;
  size_t sig_max_len;
  bool pk_expand_shake;
  bool fixed_abq = false;
  // Derived dimensions and offsets (filled by FinalizeSnovaParams).
  size_t n_matrices = 0;  // v + o
  size_t m_matrices = 0;  // o
  size_t sq_rank = 0;     // l*l
  size_t alpha_terms = 0; // l*l + l
  size_t signature_data_bytes = 0;
  size_t public_seed_bytes = 0;
  size_t private_seed_bytes = 0;
  size_t salt_bytes = 0;
  size_t hash_nibbles = 0;  // m*l*l
  size_t hash_bytes = 0;    // ceil(m*l*l/2)
  size_t u_off = 0;
  size_t salt_off = 0;
  size_t spublic_off = 0;
  size_t p22_off = 0;
  size_t p22_nibbles = 0;  // m*o*o*l*l
  size_t seed_section_bytes = 0;  // esk_len - 48
  // Packed expanded public key (seed || nibble stream of
  // P22,P11,P12,P21,A,B,Q1,Q2 in the pinned struct order).
  size_t expanded_pk_len = 0;
  size_t expanded_data_nibbles = 0;
  size_t expand_p22_nibble_off = 0;
  size_t expand_p11_nibble_off = 0;
  size_t expand_p12_nibble_off = 0;
  size_t expand_p21_nibble_off = 0;
  size_t expand_a_nibble_off = 0;
  size_t expand_b_nibble_off = 0;
  size_t expand_q1_nibble_off = 0;
  size_t expand_q2_nibble_off = 0;
};

bool GetSnovaParams(const std::string &algorithm, SnovaParams *params);

// Signature U is n matrices of l x l GF16 entries, row-major inside a matrix.
std::vector<MlKemRegion> SnovaSignatureRegions(const SnovaParams &params, size_t signature_len);
std::vector<MlKemRegion> SnovaPublicKeyRegions(const SnovaParams &params);

// Nibble codec for the signature U stream: low nibble first, odd final nibble
// stored in the low half of the last data byte.
size_t SnovaSignatureNibbleOffset(const SnovaParams &params, size_t nibble_index);
size_t SnovaMatrixNibbleIndex(const SnovaParams &params, size_t matrix, size_t row, size_t col);
bool SnovaDecodeSignatureNibble(const SnovaParams &params, const std::vector<uint8_t> &signature,
                                size_t nibble_index, uint8_t *value);
bool SnovaEncodeSignatureNibble(const SnovaParams &params, std::vector<uint8_t> *signature,
                                size_t nibble_index, uint8_t value);

// P22 nibble codec (same low-nibble-first convention).
bool SnovaDecodeP22Nibble(const SnovaParams &params, const std::vector<uint8_t> &public_key,
                          size_t nibble_index, uint8_t *value);
bool SnovaEncodeP22Nibble(const SnovaParams &params, std::vector<uint8_t> *public_key,
                          size_t nibble_index, uint8_t value);

// True when U has an odd nibble count and therefore a zero high-nibble pad.
bool SnovaSignatureUsesPadding(const SnovaParams &params);
size_t SnovaSignaturePaddingNibbleIndex(const SnovaParams &params);

}  // namespace pqcfuzz

#endif

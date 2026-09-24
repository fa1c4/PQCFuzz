#ifndef PQCFUZZ_MUTATORS_FALCON_LAYOUT_H
#define PQCFUZZ_MUTATORS_FALCON_LAYOUT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {

enum class FalconFormat {
  kCompressed = 0,
  kPadded = 1,
  kCt = 2,
};

// One Falcon parameter/format profile from src/config/scheme_profiles/falcon.json.
// Lengths are byte lengths; the compressed payload is a variable-length bit
// stream so only its capacity is fixed.
struct FalconParams {
  const char *algorithm = "";
  FalconFormat format = FalconFormat::kCompressed;
  int logn = 0;
  int n = 0;
  int q = 12289;
  size_t pk_len = 0;
  size_t sk_len = 0;
  size_t sig_max_len = 0;
  size_t padded_len = 0;
  size_t ct_len = 0;
  size_t salt_len = 40;
  int64_t norm_bound = 0;
  int compressed_coefficient_limit = 2047;
  int pk_header = 0;
  int sig_header = 0;
  int sk_header = 0;
  int ct_header = 0;
  int fg_bits = 0;
  // Derived layout constants.
  size_t header_len = 1;
  size_t pk_payload_off = 1;
  size_t pk_payload_len = 0;
  size_t sig_salt_off = 1;
  size_t sig_payload_off = 41;
  bool accepts_full_padded = false;
};

bool GetFalconParams(const std::string &algorithm, FalconParams *params);
const char *FalconFormatName(FalconFormat format);

std::vector<MlKemRegion> FalconSignatureRegions(const FalconParams &params, size_t signature_len);
std::vector<MlKemRegion> FalconPublicKeyRegions(const FalconParams &params);

size_t FalconPkPayloadLen(const FalconParams &params);
size_t FalconCtPayloadLen(const FalconParams &params);
uint8_t FalconCtHeader(const FalconParams &params);

bool FalconSignatureHeaderValid(const FalconParams &params, uint8_t header);
bool FalconPublicKeyHeaderValid(const FalconParams &params, uint8_t header);

// Bit codecs mirroring the pinned reference codec.c semantics.
bool DecodeFalconCompressedPayload(
    const uint8_t *payload,
    size_t payload_len,
    const FalconParams &params,
    std::vector<int16_t> *coefficients,
    size_t *consumed_bytes,
    std::string *error);

// Extended compressed decoder used by the format-aware mutator.  On success it
// can report the number of unused trailing bits in the last consumed byte and
// the bit offsets of every coefficient sign group and unary terminator.
bool DecodeFalconCompressedPayloadEx(
    const uint8_t *payload,
    size_t payload_len,
    const FalconParams &params,
    std::vector<int16_t> *coefficients,
    size_t *consumed_bytes,
    size_t *trailing_bits,
    std::vector<size_t> *coefficient_bit_offsets,
    std::vector<size_t> *terminator_bit_offsets,
    std::string *error);
bool EncodeFalconCompressedPayload(
    const std::vector<int16_t> &coefficients,
    const FalconParams &params,
    std::vector<uint8_t> *payload,
    std::string *error);
bool DecodeFalconCtPayload(
    const uint8_t *payload,
    size_t payload_len,
    const FalconParams &params,
    std::vector<int16_t> *coefficients,
    size_t *consumed_bytes,
    std::string *error);
bool EncodeFalconCtPayload(
    const std::vector<int16_t> &coefficients,
    const FalconParams &params,
    std::vector<uint8_t> *payload,
    std::string *error);
bool DecodeFalconPublicKeyCoefficients(
    const uint8_t *payload,
    size_t payload_len,
    const FalconParams &params,
    std::vector<uint16_t> *coefficients,
    size_t *consumed_bytes,
    std::string *error);
bool EncodeFalconPublicKeyCoefficients(
    const std::vector<uint16_t> &coefficients,
    const FalconParams &params,
    std::vector<uint8_t> *payload,
    std::string *error);

// Full signature view: header, salt, payload consumption and (for padded
// inputs) whether the trailing zero padding was complete and canonical.
struct FalconSignatureView {
  uint8_t header = 0;
  size_t salt_off = 0;
  size_t salt_len = 0;
  size_t payload_off = 0;
  size_t payload_len = 0;
  size_t consumed_bytes = 0;
  bool header_valid = false;
  bool is_ct = false;
  bool exact_length = false;
  bool full_padded = false;
  bool padding_all_zero = false;
  std::vector<int16_t> coefficients;
};

bool ParseFalconSignature(
    const FalconParams &params,
    const uint8_t *signature,
    size_t signature_len,
    FalconSignatureView *view,
    std::string *error);

// Long-term (secret) key header check used by the codec oracle.
bool FalconSecretKeyHeaderValid(const FalconParams &params, uint8_t header);

}  // namespace pqcfuzz

#endif

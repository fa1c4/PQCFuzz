#include "mutators/falcon_layout.h"

#include <algorithm>
#include <cstring>

namespace pqcfuzz {
namespace {

struct FalconProfile {
  const char *algorithm;
  FalconFormat format;
  int logn;
  int n;
  size_t pk_len;
  size_t sk_len;
  size_t sig_max_len;
  size_t padded_len;
  size_t ct_len;
  int64_t norm_bound;
  int fg_bits;
};

// Mirrors src/config/scheme_profiles/falcon.json.  The reference API macros
// FALCON_PUBKEY_SIZE/FALCON_PRIVKEY_SIZE/FALCON_SIG_*_SIZE are evaluated in
// tests against the pinned headers; this table is the runtime contract.
const FalconProfile kProfiles[] = {
    {"FALCON-512-COMPRESSED", FalconFormat::kCompressed, 9, 512, 897, 1281, 752, 666, 809, 34034726, 6},
    {"FALCON-1024-COMPRESSED", FalconFormat::kCompressed, 10, 1024, 1793, 2305, 1462, 1280, 1577, 70265242, 5},
    {"FALCON-512-PADDED", FalconFormat::kPadded, 9, 512, 897, 1281, 666, 666, 809, 34034726, 6},
    {"FALCON-1024-PADDED", FalconFormat::kPadded, 10, 1024, 1793, 2305, 1280, 1280, 1577, 70265242, 5},
    {"FALCON-512-CT", FalconFormat::kCt, 9, 512, 897, 1281, 809, 666, 809, 34034726, 6},
    {"FALCON-1024-CT", FalconFormat::kCt, 10, 1024, 1793, 2305, 1577, 1280, 1577, 70265242, 5},
};

constexpr size_t kCompressedLowBits = 7;
constexpr size_t kSaltOffset = 1;
constexpr size_t kPayloadOffset = 41;

size_t Packed14Len(int n) {
  return (static_cast<size_t>(n) * 14 + 7) / 8;
}

size_t Packed12Len(int n) {
  return (static_cast<size_t>(n) * 12 + 7) / 8;
}

bool Fail(std::string *error, const std::string &message) {
  if (error != nullptr) {
    *error = message;
  }
  return false;
}

}  // namespace

bool GetFalconParams(const std::string &algorithm, FalconParams *params) {
  if (params == nullptr) {
    return false;
  }
  for (const FalconProfile &profile : kProfiles) {
    if (algorithm != profile.algorithm) {
      continue;
    }
    FalconParams out;
    out.algorithm = profile.algorithm;
    out.format = profile.format;
    out.logn = profile.logn;
    out.n = profile.n;
    out.q = 12289;
    out.pk_len = profile.pk_len;
    out.sk_len = profile.sk_len;
    out.sig_max_len = profile.sig_max_len;
    out.padded_len = profile.padded_len;
    out.ct_len = profile.ct_len;
    out.salt_len = 40;
    out.norm_bound = profile.norm_bound;
    out.compressed_coefficient_limit = 2047;
    out.pk_header = 0x00 + profile.logn;
    out.sig_header = 0x30 + profile.logn;
    out.sk_header = 0x50 + profile.logn;
    out.ct_header = 0x50 + profile.logn;
    out.fg_bits = profile.fg_bits;
    out.header_len = 1;
    out.pk_payload_off = 1;
    out.pk_payload_len = Packed14Len(profile.n);
    out.sig_salt_off = kSaltOffset;
    out.sig_payload_off = kPayloadOffset;
    // The reference compressed verifier used through the header-inference path
    // accepts the full zero-padded form; the padded verifier requires the fixed
    // padded length and the CT verifier requires the exact CT length.
    out.accepts_full_padded = profile.format != FalconFormat::kCt;
    *params = out;
    return true;
  }
  return false;
}

const char *FalconFormatName(FalconFormat format) {
  switch (format) {
    case FalconFormat::kCompressed:
      return "compressed";
    case FalconFormat::kPadded:
      return "padded";
    case FalconFormat::kCt:
      return "ct";
  }
  return "unknown";
}

size_t FalconPkPayloadLen(const FalconParams &params) {
  return Packed14Len(params.n);
}

size_t FalconCtPayloadLen(const FalconParams &params) {
  return Packed12Len(params.n);
}

uint8_t FalconCtHeader(const FalconParams &params) {
  return static_cast<uint8_t>(0x50 + params.logn);
}

std::vector<MlKemRegion> FalconSignatureRegions(const FalconParams &params, size_t signature_len) {
  std::vector<MlKemRegion> regions;
  const auto clip = [signature_len](size_t offset, size_t length) {
    if (offset >= signature_len) {
      return std::make_pair(offset, static_cast<size_t>(0));
    }
    const size_t available = signature_len - offset;
    return std::make_pair(offset, std::min(length, available));
  };
  auto [header_off, header_len] = clip(0, params.header_len);
  regions.push_back({"signature.header", header_off, header_len});
  auto [salt_off, salt_len] = clip(params.sig_salt_off, params.salt_len);
  regions.push_back({"signature.salt", salt_off, salt_len});
  const size_t payload_len = signature_len > params.sig_payload_off ? signature_len - params.sig_payload_off : 0;
  regions.push_back({"signature.payload", params.sig_payload_off, payload_len});
  if (params.format == FalconFormat::kCt) {
    regions.push_back({"signature.ct_payload", params.sig_payload_off, payload_len});
  }
  return regions;
}

std::vector<MlKemRegion> FalconPublicKeyRegions(const FalconParams &params) {
  std::vector<MlKemRegion> regions;
  regions.push_back({"public_key.header", 0, params.header_len});
  regions.push_back({"public_key.coefficients", params.pk_payload_off, params.pk_payload_len});
  return regions;
}

bool FalconSignatureHeaderValid(const FalconParams &params, uint8_t header) {
  if (params.format == FalconFormat::kCt) {
    return header == static_cast<uint8_t>(0x50 + params.logn);
  }
  return header == static_cast<uint8_t>(0x30 + params.logn);
}

bool FalconPublicKeyHeaderValid(const FalconParams &params, uint8_t header) {
  return header == static_cast<uint8_t>(0x00 + params.logn);
}

bool FalconSecretKeyHeaderValid(const FalconParams &params, uint8_t header) {
  return header == static_cast<uint8_t>(0x50 + params.logn);
}

bool DecodeFalconCompressedPayload(
    const uint8_t *payload,
    size_t payload_len,
    const FalconParams &params,
    std::vector<int16_t> *coefficients,
    size_t *consumed_bytes,
    std::string *error) {
  return DecodeFalconCompressedPayloadEx(payload, payload_len, params, coefficients, consumed_bytes, nullptr, nullptr,
                                         nullptr, error);
}

bool DecodeFalconCompressedPayloadEx(
    const uint8_t *payload,
    size_t payload_len,
    const FalconParams &params,
    std::vector<int16_t> *coefficients,
    size_t *consumed_bytes,
    size_t *trailing_bits,
    std::vector<size_t> *coefficient_bit_offsets,
    std::vector<size_t> *terminator_bit_offsets,
    std::string *error) {
  if (payload == nullptr || coefficients == nullptr) {
    return Fail(error, "compressed payload decoder received a null buffer");
  }
  const size_t n = static_cast<size_t>(params.n);
  std::vector<int16_t> decoded(n, 0);
  std::vector<size_t> coeff_offsets(n, 0);
  std::vector<size_t> term_offsets(n, 0);
  // Literal transliteration of the pinned reference comp_decode() so the
  // unused-bit, "-0" and unary-terminator semantics cannot drift.
  uint32_t acc = 0;
  unsigned acc_len = 0;
  size_t v = 0;
  for (size_t u = 0; u < n; ++u) {
    if (v >= payload_len) {
      return Fail(error, "truncated compressed payload");
    }
    acc = (acc << 8) | static_cast<uint32_t>(payload[v++]);
    // Bit positions in `acc` map back to payload bits: a bit at acc position
    // p after v bytes were read belongs to byte v-1-(p>>3), bit p&7.
    const size_t sign_acc_pos = static_cast<size_t>(acc_len) + 7;
    coeff_offsets[u] = (v - 1 - (sign_acc_pos >> 3)) * 8 + (sign_acc_pos & 7);
    uint32_t b = acc >> acc_len;
    const uint32_t s = b & 128u;
    uint32_t m = b & 127u;
    for (;;) {
      if (acc_len == 0) {
        if (v >= payload_len) {
          return Fail(error, "unterminated compressed unary terminator");
        }
        acc = (acc << 8) | static_cast<uint32_t>(payload[v++]);
        acc_len = 8;
      }
      acc_len--;
      const size_t term_acc_pos = acc_len;
      if (((acc >> acc_len) & 1u) != 0) {
        term_offsets[u] = (v - 1 - (term_acc_pos >> 3)) * 8 + (term_acc_pos & 7);
        break;
      }
      m += 128u;
      if (m > static_cast<uint32_t>(params.compressed_coefficient_limit)) {
        return Fail(error, "compressed coefficient above the pinned limit");
      }
    }
    if (s != 0 && m == 0) {
      return Fail(error, "negative zero is forbidden by the compressed codec");
    }
    decoded[u] = s != 0 ? static_cast<int16_t>(-static_cast<int32_t>(m)) : static_cast<int16_t>(m);
  }
  if ((acc & ((1u << acc_len) - 1u)) != 0) {
    return Fail(error, "non-zero trailing bits in the last compressed payload byte");
  }
  *coefficients = std::move(decoded);
  if (consumed_bytes != nullptr) {
    *consumed_bytes = v;
  }
  if (trailing_bits != nullptr) {
    *trailing_bits = acc_len;
  }
  if (coefficient_bit_offsets != nullptr) {
    *coefficient_bit_offsets = std::move(coeff_offsets);
  }
  if (terminator_bit_offsets != nullptr) {
    *terminator_bit_offsets = std::move(term_offsets);
  }
  return true;
}

bool EncodeFalconCompressedPayload(
    const std::vector<int16_t> &coefficients,
    const FalconParams &params,
    std::vector<uint8_t> *payload,
    std::string *error) {
  if (payload == nullptr) {
    return Fail(error, "compressed payload encoder received a null output");
  }
  if (coefficients.size() != static_cast<size_t>(params.n)) {
    return Fail(error, "compressed payload encoder received the wrong coefficient count");
  }
  // Literal transliteration of the pinned reference comp_encode().
  std::vector<uint8_t> out;
  uint32_t acc = 0;
  unsigned acc_len = 0;
  for (int16_t value : coefficients) {
    int32_t t = value;
    if (t < -params.compressed_coefficient_limit || t > params.compressed_coefficient_limit) {
      return Fail(error, "compressed coefficient outside the pinned encoding limit");
    }
    acc <<= 1;
    if (t < 0) {
      t = -t;
      acc |= 1u;
    }
    const uint32_t w_low = static_cast<uint32_t>(t);
    acc <<= kCompressedLowBits;
    acc |= w_low & 127u;
    uint32_t w = w_low >> 7;
    acc_len += 8;
    acc <<= (w + 1);
    acc |= 1u;
    acc_len += w + 1;
    while (acc_len >= 8) {
      acc_len -= 8;
      out.push_back(static_cast<uint8_t>(acc >> acc_len));
    }
  }
  if (acc_len > 0) {
    out.push_back(static_cast<uint8_t>(acc << (8 - acc_len)));
  }
  *payload = std::move(out);
  return true;
}

bool DecodeFalconCtPayload(
    const uint8_t *payload,
    size_t payload_len,
    const FalconParams &params,
    std::vector<int16_t> *coefficients,
    size_t *consumed_bytes,
    std::string *error) {
  if (payload == nullptr || coefficients == nullptr) {
    return Fail(error, "CT payload decoder received a null buffer");
  }
  const size_t n = static_cast<size_t>(params.n);
  constexpr unsigned kBits = 12;
  const size_t in_len = Packed12Len(params.n);
  if (in_len > payload_len) {
    return Fail(error, "truncated CT payload");
  }
  std::vector<int16_t> decoded(n, 0);
  const uint32_t mask1 = (1u << kBits) - 1u;
  const uint32_t mask2 = 1u << (kBits - 1);
  uint32_t acc = 0;
  unsigned acc_len = 0;
  size_t v = 0;
  size_t u = 0;
  while (u < n) {
    acc = (acc << 8) | static_cast<uint32_t>(payload[v++]);
    acc_len += 8;
    while (acc_len >= kBits && u < n) {
      acc_len -= kBits;
      uint32_t w = (acc >> acc_len) & mask1;
      w |= static_cast<uint32_t>(-static_cast<int32_t>(w & mask2));
      if (w == static_cast<uint32_t>(-static_cast<int32_t>(mask2))) {
        return Fail(error, "the minimum negative CT coefficient is forbidden");
      }
      w |= static_cast<uint32_t>(-static_cast<int32_t>(w & mask2));
      decoded[u++] = static_cast<int16_t>(static_cast<int32_t>(w));
    }
  }
  if ((acc & ((1u << acc_len) - 1u)) != 0) {
    return Fail(error, "non-zero trailing bits in the last CT payload byte");
  }
  *coefficients = std::move(decoded);
  if (consumed_bytes != nullptr) {
    *consumed_bytes = v;
  }
  return true;
}

bool EncodeFalconCtPayload(
    const std::vector<int16_t> &coefficients,
    const FalconParams &params,
    std::vector<uint8_t> *payload,
    std::string *error) {
  if (payload == nullptr) {
    return Fail(error, "CT payload encoder received a null output");
  }
  if (coefficients.size() != static_cast<size_t>(params.n)) {
    return Fail(error, "CT payload encoder received the wrong coefficient count");
  }
  constexpr unsigned kBits = 12;
  const int maxv = (1 << (kBits - 1)) - 1;
  const int minv = -maxv;
  std::vector<uint8_t> out;
  uint32_t acc = 0;
  unsigned acc_len = 0;
  for (int16_t value : coefficients) {
    if (value < minv || value > maxv) {
      return Fail(error, "CT coefficient outside the signed 12-bit range");
    }
    acc = (acc << kBits) | (static_cast<uint16_t>(value) & ((1u << kBits) - 1u));
    acc_len += kBits;
    while (acc_len >= 8) {
      acc_len -= 8;
      out.push_back(static_cast<uint8_t>(acc >> acc_len));
    }
  }
  if (acc_len > 0) {
    out.push_back(static_cast<uint8_t>(acc << (8 - acc_len)));
  }
  *payload = std::move(out);
  return true;
}

bool DecodeFalconPublicKeyCoefficients(
    const uint8_t *payload,
    size_t payload_len,
    const FalconParams &params,
    std::vector<uint16_t> *coefficients,
    size_t *consumed_bytes,
    std::string *error) {
  if (payload == nullptr || coefficients == nullptr) {
    return Fail(error, "public key decoder received a null buffer");
  }
  const size_t n = static_cast<size_t>(params.n);
  const size_t in_len = Packed14Len(params.n);
  if (in_len > payload_len) {
    return Fail(error, "truncated public key payload");
  }
  std::vector<uint16_t> decoded(n, 0);
  uint32_t acc = 0;
  int acc_len = 0;
  size_t v = 0;
  size_t u = 0;
  while (u < n) {
    acc = (acc << 8) | static_cast<uint32_t>(payload[v++]);
    acc_len += 8;
    if (acc_len >= 14) {
      acc_len -= 14;
      const unsigned w = (acc >> acc_len) & 0x3FFFu;
      if (w >= static_cast<unsigned>(params.q)) {
        return Fail(error, "public key coefficient is not smaller than q");
      }
      decoded[u++] = static_cast<uint16_t>(w);
    }
  }
  if ((acc & ((1u << acc_len) - 1u)) != 0) {
    return Fail(error, "non-zero trailing bits in the last public key byte");
  }
  *coefficients = std::move(decoded);
  if (consumed_bytes != nullptr) {
    *consumed_bytes = v;
  }
  return true;
}

bool EncodeFalconPublicKeyCoefficients(
    const std::vector<uint16_t> &coefficients,
    const FalconParams &params,
    std::vector<uint8_t> *payload,
    std::string *error) {
  if (payload == nullptr) {
    return Fail(error, "public key encoder received a null output");
  }
  if (coefficients.size() != static_cast<size_t>(params.n)) {
    return Fail(error, "public key encoder received the wrong coefficient count");
  }
  for (uint16_t value : coefficients) {
    if (value >= static_cast<uint16_t>(params.q)) {
      return Fail(error, "public key coefficient is not smaller than q");
    }
  }
  std::vector<uint8_t> out;
  uint32_t acc = 0;
  int acc_len = 0;
  for (uint16_t value : coefficients) {
    acc = (acc << 14) | value;
    acc_len += 14;
    while (acc_len >= 8) {
      acc_len -= 8;
      out.push_back(static_cast<uint8_t>(acc >> acc_len));
    }
  }
  if (acc_len > 0) {
    out.push_back(static_cast<uint8_t>(acc << (8 - acc_len)));
  }
  *payload = std::move(out);
  return true;
}

bool ParseFalconSignature(
    const FalconParams &params,
    const uint8_t *signature,
    size_t signature_len,
    FalconSignatureView *view,
    std::string *error) {
  if (signature == nullptr || view == nullptr) {
    return Fail(error, "signature parser received a null buffer");
  }
  *view = FalconSignatureView{};
  if (signature_len < params.sig_payload_off) {
    return Fail(error, "signature shorter than header plus salt");
  }
  view->header = signature[0];
  view->salt_off = params.sig_salt_off;
  view->salt_len = params.salt_len;
  if (!FalconSignatureHeaderValid(params, signature[0])) {
    return Fail(error, "signature header does not match the profile");
  }
  view->header_valid = true;
  view->payload_off = params.sig_payload_off;
  view->payload_len = signature_len - params.sig_payload_off;

  if (params.format == FalconFormat::kPadded && signature_len != params.padded_len) {
    return Fail(error, "padded signature length is not the exact profile length");
  }

  if (params.format == FalconFormat::kCt) {
    if (signature_len != params.ct_len) {
      return Fail(error, "CT signature length is not the exact profile length");
    }
    std::string decode_error;
    if (!DecodeFalconCtPayload(signature + view->payload_off, view->payload_len, params,
                               &view->coefficients, &view->consumed_bytes, &decode_error)) {
      return Fail(error, decode_error);
    }
    view->is_ct = true;
    view->exact_length = true;
    return true;
  }

  std::string decode_error;
  if (!DecodeFalconCompressedPayload(signature + view->payload_off, view->payload_len, params,
                                     &view->coefficients, &view->consumed_bytes, &decode_error)) {
    return Fail(error, decode_error);
  }
  const size_t consumed_end = params.sig_payload_off + view->consumed_bytes;
  if (consumed_end == signature_len) {
    view->exact_length = true;
    return true;
  }
  if (!params.accepts_full_padded || signature_len != params.padded_len) {
    return Fail(error, "unconsumed trailing bytes are not a legal padded form for this profile");
  }
  view->full_padded = true;
  view->padding_all_zero = true;
  for (size_t i = consumed_end; i < signature_len; ++i) {
    if (signature[i] != 0) {
      view->padding_all_zero = false;
      return Fail(error, "non-zero byte inside the padded region");
    }
  }
  return true;
}

}  // namespace pqcfuzz

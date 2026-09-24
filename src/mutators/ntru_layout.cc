#include "mutators/ntru_layout.h"

#include <algorithm>
#include <cstring>

namespace pqcfuzz {
namespace {

struct NtruProfile {
  const char *algorithm;
  const char *variant;
  size_t n;
  size_t q;
  size_t logq;
  size_t b3;
  size_t bq;
  size_t pk_len;
  size_t sk_len;
  size_t ct_len;
  size_t weight;
  size_t pack_trinary_bytes;
  size_t tail_unused_bits;
  size_t sample_fg_bytes;
  size_t sample_rm_bytes;
};

// Mirrors src/config/scheme_profiles/ntru.json; the values are checked against
// each vendored params.h by scripts and tests.
const NtruProfile kProfiles[] = {
    {"NTRU-HPS-2048-509", "HPS", 509, 2048, 11, 102, 699, 699, 935, 699, 254, 102, 4, 2413, 2413},
    {"NTRU-HPS-2048-677", "HPS", 677, 2048, 11, 136, 930, 930, 1234, 930, 254, 136, 4, 3211, 3211},
    {"NTRU-HPS-4096-821", "HPS", 821, 4096, 12, 164, 1230, 1230, 1590, 1230, 510, 164, 0, 3895, 3895},
    {"NTRU-HRSS-701", "HRSS", 701, 8192, 13, 140, 1138, 1138, 1450, 1138, 0, 140, 4, 1400, 1400},
};

bool Fail(std::string *error, const std::string &message) {
  if (error != nullptr) {
    *error = message;
  }
  return false;
}

}  // namespace

bool GetNtruParams(const std::string &algorithm, NtruParams *params) {
  if (params == nullptr) {
    return false;
  }
  for (const NtruProfile &profile : kProfiles) {
    if (algorithm != profile.algorithm) {
      continue;
    }
    NtruParams out;
    out.algorithm = profile.algorithm;
    out.variant = profile.variant;
    out.n = profile.n;
    out.q = profile.q;
    out.logq = profile.logq;
    out.b3 = profile.b3;
    out.bq = profile.bq;
    out.pk_len = profile.pk_len;
    out.sk_len = profile.sk_len;
    out.ct_len = profile.ct_len;
    out.ss_len = 32;
    out.weight = profile.weight;
    out.pack_trinary_bytes = profile.pack_trinary_bytes;
    out.tail_unused_bits = profile.tail_unused_bits;
    out.sample_fg_bytes = profile.sample_fg_bytes;
    out.sample_rm_bytes = profile.sample_rm_bytes;
    out.prf_key_bytes = 32;
    out.sk_fp_off = profile.b3;
    out.sk_hq_off = 2 * profile.b3;
    out.sk_prf_off = 2 * profile.b3 + profile.bq;
    *params = out;
    return true;
  }
  return false;
}

std::vector<MlKemRegion> NtruPublicKeyRegions(const NtruParams &params) {
  return {{"public_key", 0, params.pk_len}};
}

std::vector<MlKemRegion> NtruCiphertextRegions(const NtruParams &params) {
  std::vector<MlKemRegion> regions = {{"ciphertext", 0, params.ct_len}};
  if (params.tail_unused_bits > 0 && params.ct_len > 0) {
    regions.push_back({"ciphertext.padding", params.ct_len - 1, 1});
  }
  return regions;
}

std::vector<MlKemRegion> NtruSecretKeyRegions(const NtruParams &params) {
  return {
      {"secret_key.f", 0, params.b3},
      {"secret_key.fp", params.sk_fp_off, params.b3},
      {"secret_key.hq", params.sk_hq_off, params.bq},
      {"secret_key.prf", params.sk_prf_off, params.prf_key_bytes},
  };
}

bool DecodeNtruS3(const uint8_t *payload, size_t payload_len, const NtruParams &params,
                  std::vector<uint8_t> *coefficients, std::string *error) {
  if (payload == nullptr || coefficients == nullptr) {
    return Fail(error, "S3 decoder received a null buffer");
  }
  if (payload_len < params.pack_trinary_bytes) {
    return Fail(error, "truncated S3 payload");
  }
  std::vector<uint8_t> decoded(params.n, 0);
  const size_t full_groups = (params.n - 1) / 5;
  size_t index = 0;
  for (size_t group = 0; group < full_groups; ++group) {
    unsigned value = payload[group];
    for (size_t j = 0; j < 5; ++j) {
      decoded[5 * group + j] = static_cast<uint8_t>(value % 3);
      value /= 3;
    }
    index = 5 * (group + 1);
  }
  if (index < params.n - 1) {
    unsigned value = payload[full_groups];
    while (index < params.n - 1) {
      decoded[index++] = static_cast<uint8_t>(value % 3);
      value /= 3;
    }
  }
  decoded[params.n - 1] = 0;
  *coefficients = std::move(decoded);
  return true;
}

bool EncodeNtruS3(const std::vector<uint8_t> &coefficients, const NtruParams &params,
                  std::vector<uint8_t> *payload, std::string *error) {
  if (payload == nullptr) {
    return Fail(error, "S3 encoder received a null output");
  }
  if (coefficients.size() != params.n) {
    return Fail(error, "S3 encoder received the wrong coefficient count");
  }
  for (size_t i = 0; i < params.n; ++i) {
    if (coefficients[i] > 2) {
      return Fail(error, "S3 coefficient outside {0,1,2}");
    }
  }
  std::vector<uint8_t> out(params.pack_trinary_bytes, 0);
  size_t group = 0;
  while (group * 5 < params.n - 1) {
    unsigned value = 0;
    unsigned place = 1;
    for (size_t j = 0; j < 5 && group * 5 + j < params.n - 1; ++j) {
      value += static_cast<unsigned>(coefficients[group * 5 + j]) * place;
      place *= 3;
    }
    out[group] = static_cast<uint8_t>(value & 0xFFu);
    ++group;
  }
  *payload = std::move(out);
  return true;
}

bool DecodeNtruRq0(const uint8_t *payload, size_t payload_len, const NtruParams &params,
                   std::vector<uint16_t> *coefficients, std::string *error) {
  if (payload == nullptr || coefficients == nullptr) {
    return Fail(error, "Rq0 decoder received a null buffer");
  }
  if (payload_len < params.bq) {
    return Fail(error, "truncated Rq0 payload");
  }
  std::vector<uint16_t> decoded(params.n, 0);
  uint64_t buffer = 0;
  size_t bits = 0;
  size_t byte_index = 0;
  const uint64_t mask = (params.logq >= 64) ? ~0ull : ((1ull << params.logq) - 1ull);
  uint64_t sum = 0;
  for (size_t i = 0; i + 1 < params.n; ++i) {
    while (bits < params.logq) {
      buffer |= static_cast<uint64_t>(payload[byte_index++]) << bits;
      bits += 8;
    }
    const uint16_t value = static_cast<uint16_t>(buffer & mask);
    buffer >>= params.logq;
    bits -= params.logq;
    decoded[i] = value;
    sum += value;
  }
  const uint64_t q = params.q;
  decoded[params.n - 1] = static_cast<uint16_t>((q - (sum % q)) % q);
  *coefficients = std::move(decoded);
  return true;
}

bool EncodeNtruRq0(const std::vector<uint16_t> &coefficients, const NtruParams &params,
                   std::vector<uint8_t> *payload, std::string *error) {
  if (payload == nullptr) {
    return Fail(error, "Rq0 encoder received a null output");
  }
  if (coefficients.size() != params.n) {
    return Fail(error, "Rq0 encoder received the wrong coefficient count");
  }
  std::vector<uint8_t> out(params.bq, 0);
  uint64_t buffer = 0;
  size_t bits = 0;
  size_t byte_index = 0;
  for (size_t i = 0; i + 1 < params.n; ++i) {
    if (coefficients[i] >= params.q) {
      return Fail(error, "Rq0 coefficient is not smaller than q");
    }
    buffer |= static_cast<uint64_t>(coefficients[i]) << bits;
    bits += params.logq;
    while (bits >= 8) {
      out[byte_index++] = static_cast<uint8_t>(buffer & 0xFFu);
      buffer >>= 8;
      bits -= 8;
    }
  }
  if (bits > 0) {
    out[byte_index++] = static_cast<uint8_t>(buffer & 0xFFu);
  }
  if (byte_index != params.bq) {
    return Fail(error, "Rq0 encoder produced an unexpected length");
  }
  *payload = std::move(out);
  return true;
}

bool NtruHasCiphertextPadding(const NtruParams &params) {
  return params.tail_unused_bits > 0;
}

bool NtruCiphertextPaddingValid(const uint8_t *ciphertext, size_t ciphertext_len, const NtruParams &params) {
  if (!NtruHasCiphertextPadding(params)) {
    return true;
  }
  if (ciphertext == nullptr || ciphertext_len < params.ct_len) {
    return false;
  }
  const uint8_t mask = static_cast<uint8_t>((1u << params.tail_unused_bits) - 1u) << (8 - params.tail_unused_bits);
  return (ciphertext[params.ct_len - 1] & mask) == 0;
}

}  // namespace pqcfuzz

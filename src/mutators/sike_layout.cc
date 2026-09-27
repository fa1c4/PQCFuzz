#include "mutators/sike_layout.h"

#include <cstring>
#include <limits>

namespace pqcfuzz {
namespace {

struct SikeTableEntry {
  const char *algorithm;
  size_t e2;
  size_t e3;
  size_t np;
  size_t nsk2;
  size_t nsk3;
  size_t msg_bytes;
  size_t pk_len;
  size_t sk_len;
  size_t ct_len;
  size_t ss_len;
};

// Locked from src/config/scheme_profiles/sike.json; the parameterized tests
// recompute pk/sk/ct/ss from e2/e3/Np and compare with this table.
const SikeTableEntry kSikeTable[] = {
    {"SIKE-p434", 216, 137, 55, 27, 28, 16, 330, 374, 346, 16},
    {"SIKE-p503", 250, 159, 63, 32, 32, 24, 378, 434, 402, 24},
    {"SIKE-p610", 305, 192, 77, 39, 38, 24, 462, 524, 486, 24},
    {"SIKE-p751", 372, 239, 94, 47, 48, 32, 564, 644, 596, 32},
};

struct SidhTableEntry {
  const char *algorithm;
  size_t e2;
  size_t e3;
  size_t np;
  size_t nsk2;
  size_t nsk3;
  size_t pk_len;
  size_t sk_a_len;
  size_t sk_b_len;
  size_t shared_len;
};

const SidhTableEntry kSidhTable[] = {
    {"SIDH-p434", 216, 137, 55, 27, 28, 330, 27, 28, 110},
    {"SIDH-p503", 250, 159, 63, 32, 32, 378, 32, 32, 126},
    {"SIDH-p610", 305, 192, 77, 39, 38, 462, 39, 38, 154},
    {"SIDH-p751", 372, 239, 94, 47, 48, 564, 47, 48, 188},
};

void SetRegion(std::vector<MlKemRegion> *regions, const std::string &name, size_t offset, size_t length) {
  if (length == 0) {
    return;
  }
  regions->push_back({name, offset, length});
}

}  // namespace

bool GetSikeParams(const std::string &algorithm, SikeParams *params) {
  if (params == nullptr) {
    return false;
  }
  for (const SikeTableEntry &entry : kSikeTable) {
    if (algorithm == entry.algorithm) {
      params->algorithm = entry.algorithm;
      params->e2 = entry.e2;
      params->e3 = entry.e3;
      params->np = entry.np;
      params->nsk2 = entry.nsk2;
      params->nsk3 = entry.nsk3;
      params->msg_bytes = entry.msg_bytes;
      params->pk_len = entry.pk_len;
      params->sk_len = entry.sk_len;
      params->ct_len = entry.ct_len;
      params->ss_len = entry.ss_len;
      params->sk_s_off = 0;
      params->sk_sk3_off = entry.msg_bytes;
      params->sk_pk_off = entry.msg_bytes + entry.nsk3;
      params->c0_len = 6 * entry.np;
      params->c1_off = params->c0_len;
      return true;
    }
  }
  return false;
}

bool GetSidhParams(const std::string &algorithm, SidhParams *params) {
  if (params == nullptr) {
    return false;
  }
  for (const SidhTableEntry &entry : kSidhTable) {
    if (algorithm == entry.algorithm) {
      params->algorithm = entry.algorithm;
      params->e2 = entry.e2;
      params->e3 = entry.e3;
      params->np = entry.np;
      params->nsk2 = entry.nsk2;
      params->nsk3 = entry.nsk3;
      params->pk_len = entry.pk_len;
      params->sk_a_len = entry.sk_a_len;
      params->sk_b_len = entry.sk_b_len;
      params->shared_len = entry.shared_len;
      return true;
    }
  }
  return false;
}

bool SikeBigToU64(const SikeBig &value, uint64_t *out) {
  if (out == nullptr) {
    return false;
  }
  for (size_t i = 1; i < SikeBig::kLimbs; ++i) {
    if (value.limb[i] != 0) {
      return false;
    }
  }
  *out = value.limb[0];
  return true;
}

int SikeBigCompare(const SikeBig &a, const SikeBig &b) {
  for (size_t i = SikeBig::kLimbs; i-- > 0;) {
    if (a.limb[i] != b.limb[i]) {
      return a.limb[i] < b.limb[i] ? -1 : 1;
    }
  }
  return 0;
}

namespace {

void SikeBigFromU64(uint64_t value, SikeBig *out) {
  out->limb[0] = value;
}

void SikeBigMulSmall(uint64_t factor, SikeBig *value) {
  unsigned __int128 carry = 0;
  for (size_t i = 0; i < SikeBig::kLimbs; ++i) {
    unsigned __int128 product = static_cast<unsigned __int128>(value->limb[i]) * factor + carry;
    value->limb[i] = static_cast<uint64_t>(product);
    carry = product >> 64;
  }
}

void SikeBigShl(size_t bits, SikeBig *value) {
  const size_t words = bits / 64;
  const size_t shift = bits % 64;
  if (words > 0) {
    for (size_t i = SikeBig::kLimbs; i-- > 0;) {
      value->limb[i] = i >= words ? value->limb[i - words] : 0;
    }
  }
  if (shift != 0) {
    for (size_t i = SikeBig::kLimbs; i-- > 1;) {
      value->limb[i] = (value->limb[i] << shift) | (value->limb[i - 1] >> (64 - shift));
    }
    value->limb[0] <<= shift;
  }
}

void SikeBigSubOne(SikeBig *value) {
  for (size_t i = 0; i < SikeBig::kLimbs; ++i) {
    if (value->limb[i] != 0) {
      value->limb[i] -= 1;
      break;
    }
    value->limb[i] = ~static_cast<uint64_t>(0);
  }
}

size_t SikeBigBitLength(const SikeBig &value) {
  for (size_t i = SikeBig::kLimbs; i-- > 0;) {
    if (value.limb[i] != 0) {
      size_t bits = 64 * i;
      uint64_t word = value.limb[i];
      while (word != 0) {
        ++bits;
        word >>= 1;
      }
      return bits;
    }
  }
  return 0;
}

}  // namespace

bool ComputeSikeFieldPrime(size_t e2, size_t e3, SikeBig *p) {
  if (p == nullptr || e3 == 0) {
    return false;
  }
  SikeBig value;
  SikeBigFromU64(1, &value);
  for (size_t i = 0; i < e3; ++i) {
    SikeBigMulSmall(3, &value);
  }
  SikeBigShl(e2, &value);
  SikeBigSubOne(&value);
  *p = value;
  return true;
}

bool ComputeSikeBobScalarBits(size_t e3, size_t *sbits) {
  if (sbits == nullptr || e3 == 0) {
    return false;
  }
  SikeBig value;
  SikeBigFromU64(1, &value);
  for (size_t i = 0; i < e3; ++i) {
    SikeBigMulSmall(3, &value);
  }
  const size_t bits = SikeBigBitLength(value);
  if (bits == 0) {
    return false;
  }
  *sbits = bits - 1;
  return true;
}

bool SikeBigFromLeBytes(const uint8_t *bytes, size_t len, SikeBig *out) {
  if (bytes == nullptr || out == nullptr || len > SikeBig::kLimbs * 8) {
    return false;
  }
  *out = SikeBig{};
  for (size_t i = 0; i < len; ++i) {
    out->limb[i / 8] |= static_cast<uint64_t>(bytes[i]) << (8 * (i % 8));
  }
  return true;
}

void SikeBigToLeBytes(const SikeBig &value, uint8_t *out, size_t len) {
  if (out == nullptr) {
    return;
  }
  for (size_t i = 0; i < len; ++i) {
    const size_t word = i / 8;
    out[i] = word < SikeBig::kLimbs ? static_cast<uint8_t>((value.limb[word] >> (8 * (i % 8))) & 0xFFu) : 0;
  }
}

bool SikeFpCanonical(const uint8_t *bytes, size_t len, const SikeBig &p) {
  SikeBig value;
  if (!SikeBigFromLeBytes(bytes, len, &value)) {
    return false;
  }
  return SikeBigCompare(value, p) < 0;
}

size_t SikePublicKeyCoordinateCount() {
  return 3;
}

size_t SikeCiphertextCoordinateCount() {
  return 3;
}

size_t SikeCoordinateOffset(size_t base, size_t coordinate, size_t np) {
  if (np == 0 || coordinate > (std::numeric_limits<size_t>::max() - base) / (2 * np)) {
    return std::numeric_limits<size_t>::max();
  }
  return base + coordinate * 2 * np;
}

std::vector<MlKemRegion> SikePublicKeyRegions(const SikeParams &params) {
  std::vector<MlKemRegion> regions;
  for (size_t coordinate = 0; coordinate < SikePublicKeyCoordinateCount(); ++coordinate) {
    const size_t offset = SikeCoordinateOffset(0, coordinate, params.np);
    SetRegion(&regions, "pk.fp2." + std::to_string(coordinate), offset, params.np);
    SetRegion(&regions, "pk.fp2." + std::to_string(coordinate) + ".imag", offset + params.np, params.np);
  }
  return regions;
}

std::vector<MlKemRegion> SikeCiphertextRegions(const SikeParams &params) {
  std::vector<MlKemRegion> regions;
  for (size_t coordinate = 0; coordinate < SikeCiphertextCoordinateCount(); ++coordinate) {
    const size_t offset = SikeCoordinateOffset(0, coordinate, params.np);
    SetRegion(&regions, "ct.c0." + std::to_string(coordinate), offset, params.np);
    SetRegion(&regions, "ct.c0." + std::to_string(coordinate) + ".imag", offset + params.np, params.np);
  }
  SetRegion(&regions, "ct.c1", params.c1_off, params.msg_bytes);
  return regions;
}

std::vector<MlKemRegion> SikeSecretKeyRegions(const SikeParams &params) {
  std::vector<MlKemRegion> regions;
  SetRegion(&regions, "sk.s", params.sk_s_off, params.msg_bytes);
  SetRegion(&regions, "sk.sk3", params.sk_sk3_off, params.nsk3);
  SetRegion(&regions, "sk.pk3", params.sk_pk_off, params.pk_len);
  return regions;
}

std::vector<MlKemRegion> SidhPublicKeyRegions(const SidhParams &params) {
  std::vector<MlKemRegion> regions;
  for (size_t coordinate = 0; coordinate < 3; ++coordinate) {
    const size_t offset = SikeCoordinateOffset(0, coordinate, params.np);
    SetRegion(&regions, "pk.fp2." + std::to_string(coordinate), offset, params.np);
    SetRegion(&regions, "pk.fp2." + std::to_string(coordinate) + ".imag", offset + params.np, params.np);
  }
  return regions;
}

}  // namespace pqcfuzz

#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {
namespace {

constexpr MlKemParams kMlKemParams[] = {
    // z_offset = 768*k + 64: dkPKE(384k) || ek(384k+32) || H(ek)(32) || z(32).
    {"ML-KEM-512", 800, 1632, 768, 32, 2, 10, 4, 1600, 32},
    {"ML-KEM-768", 1184, 2400, 1088, 32, 3, 10, 4, 2368, 32},
    {"ML-KEM-1024", 1568, 3168, 1568, 32, 4, 11, 5, 3136, 32},
};

}  // namespace

bool GetMlKemParams(const std::string &algorithm, MlKemParams *params) {
  for (const auto &candidate : kMlKemParams) {
    if (algorithm == candidate.algorithm) {
      if (params != nullptr) {
        *params = candidate;
      }
      return true;
    }
  }
  return false;
}

std::vector<MlKemRegion> PublicKeyRegions(const MlKemParams &params) {
  const size_t rho_len = 32;
  const size_t t_len = params.pk_len - rho_len;
  return {
      {"public_key.t", 0, t_len},
      {"public_key.rho", t_len, rho_len},
  };
}

std::vector<MlKemRegion> CiphertextRegions(const MlKemParams &params) {
  const size_t u_len = 32 * params.du * params.k;
  const size_t v_len = 32 * params.dv;
  return {
      {"ciphertext.u", 0, u_len},
      {"ciphertext.v", u_len, v_len},
  };
}

bool DecodeMlKemCoefficient12(const std::vector<uint8_t> &public_key, size_t coefficient_index, uint16_t *value) {
  if (value == nullptr) {
    return false;
  }
  const size_t byte_offset = (coefficient_index / 2) * 3;
  if (byte_offset + 3 > public_key.size()) {
    return false;
  }
  const uint8_t b0 = public_key[byte_offset];
  const uint8_t b1 = public_key[byte_offset + 1];
  const uint8_t b2 = public_key[byte_offset + 2];
  *value = (coefficient_index % 2 == 0)
      ? static_cast<uint16_t>(b0 | ((b1 & 0x0Fu) << 8))
      : static_cast<uint16_t>((b1 >> 4) | (static_cast<uint16_t>(b2) << 4));
  return true;
}

bool EncodeMlKemCoefficient12(std::vector<uint8_t> *public_key, size_t coefficient_index, uint16_t value) {
  if (public_key == nullptr || value > 0x0FFFu) {
    return false;
  }
  const size_t byte_offset = (coefficient_index / 2) * 3;
  if (byte_offset + 3 > public_key->size()) {
    return false;
  }
  uint8_t &b0 = (*public_key)[byte_offset];
  uint8_t &b1 = (*public_key)[byte_offset + 1];
  uint8_t &b2 = (*public_key)[byte_offset + 2];
  if (coefficient_index % 2 == 0) {
    b0 = static_cast<uint8_t>(value & 0xFFu);
    b1 = static_cast<uint8_t>((b1 & 0xF0u) | ((value >> 8) & 0x0Fu));
  } else {
    b1 = static_cast<uint8_t>((b1 & 0x0Fu) | ((value & 0x0Fu) << 4));
    b2 = static_cast<uint8_t>((value >> 4) & 0xFFu);
  }
  return true;
}

}  // namespace pqcfuzz

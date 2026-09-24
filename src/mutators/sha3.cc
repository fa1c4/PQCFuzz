#include "mutators/sha3.h"

#include <array>
#include <cstdio>

namespace pqcfuzz {
namespace {

constexpr size_t kRate = 136;  // SHA3-256 rate in bytes (1088 bits)
constexpr size_t kStateLanes = 25;

constexpr uint64_t kRoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

// rho offsets indexed as lane = x + 5*y.
constexpr unsigned kRotation[25] = {
    0,  1,  62, 28, 27, 36, 44, 6,  55, 20, 3,  10, 43,
    25, 39, 41, 45, 15, 21, 8,  18, 2,  61, 56, 14,
};

inline uint64_t Rotl(uint64_t value, unsigned shift) {
  if (shift == 0) {
    return value;
  }
  return (value << shift) | (value >> (64 - shift));
}

void KeccakF1600(uint64_t state[kStateLanes]) {
  for (int round = 0; round < 24; ++round) {
    uint64_t c[5];
    for (int x = 0; x < 5; ++x) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    uint64_t d[5];
    for (int x = 0; x < 5; ++x) {
      d[x] = c[(x + 4) % 5] ^ Rotl(c[(x + 1) % 5], 1);
    }
    for (int y = 0; y < 5; ++y) {
      for (int x = 0; x < 5; ++x) {
        state[x + 5 * y] ^= d[x];
      }
    }
    uint64_t b[kStateLanes];
    for (int y = 0; y < 5; ++y) {
      for (int x = 0; x < 5; ++x) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = Rotl(state[x + 5 * y], kRotation[x + 5 * y]);
      }
    }
    for (int y = 0; y < 5; ++y) {
      for (int x = 0; x < 5; ++x) {
        state[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
      }
    }
    state[0] ^= kRoundConstants[round];
  }
}

void AbsorbBlock(uint64_t state[kStateLanes], const uint8_t *block) {
  for (size_t i = 0; i < kRate / 8; ++i) {
    uint64_t lane = 0;
    for (int j = 0; j < 8; ++j) {
      lane |= static_cast<uint64_t>(block[i * 8 + j]) << (8 * j);
    }
    state[i] ^= lane;
  }
  KeccakF1600(state);
}

}  // namespace

std::vector<uint8_t> Sha3_256(const uint8_t *data, size_t size) {
  uint64_t state[kStateLanes] = {};
  size_t offset = 0;
  while (offset + kRate <= size) {
    AbsorbBlock(state, data + offset);
    offset += kRate;
  }
  uint8_t tail[kRate] = {};
  const size_t remaining = size - offset;
  for (size_t i = 0; i < remaining; ++i) {
    tail[i] = data[offset + i];
  }
  tail[remaining] = 0x06;            // SHA3 domain separation
  tail[kRate - 1] |= static_cast<uint8_t>(0x80);
  AbsorbBlock(state, tail);

  std::vector<uint8_t> digest(32);
  for (size_t i = 0; i < digest.size(); ++i) {
    digest[i] = static_cast<uint8_t>((state[i / 8] >> (8 * (i % 8))) & 0xFFu);
  }
  return digest;
}

std::vector<uint8_t> Sha3_256(const std::vector<uint8_t> &data) {
  return Sha3_256(data.data(), data.size());
}

std::string Sha3_256Hex(const uint8_t *data, size_t size) {
  const std::vector<uint8_t> digest = Sha3_256(data, size);
  std::string out;
  char buffer[3];
  for (uint8_t byte : digest) {
    std::snprintf(buffer, sizeof(buffer), "%02x", byte);
    out += buffer;
  }
  return out;
}

std::string Sha3_256Hex(const std::vector<uint8_t> &data) {
  return Sha3_256Hex(data.data(), data.size());
}

}  // namespace pqcfuzz

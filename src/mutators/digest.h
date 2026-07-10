#ifndef PQCFUZZ_MUTATORS_DIGEST_H
#define PQCFUZZ_MUTATORS_DIGEST_H

#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <vector>

namespace pqcfuzz {
namespace detail {

inline uint32_t DigestRotR(uint32_t value, uint32_t bits) {
  return (value >> bits) | (value << (32 - bits));
}

inline uint32_t DigestLoad32(const uint8_t *data) {
  return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);
}

inline void DigestStore32(uint32_t value, uint8_t *out) {
  out[0] = static_cast<uint8_t>(value >> 24);
  out[1] = static_cast<uint8_t>(value >> 16);
  out[2] = static_cast<uint8_t>(value >> 8);
  out[3] = static_cast<uint8_t>(value);
}

inline std::array<uint8_t, 32> MutationSha256(const std::vector<uint8_t> &input) {
  static constexpr uint32_t k[64] = {
      0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
      0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
      0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
      0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
      0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
      0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
      0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
      0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,
      0xbef9a3f7u,0xc67178f2u,
  };
  uint32_t h[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
  std::vector<uint8_t> data = input;
  const uint64_t bit_len = static_cast<uint64_t>(data.size()) * 8u;
  data.push_back(0x80);
  while (data.size() % 64 != 56) data.push_back(0);
  for (int i = 7; i >= 0; --i) data.push_back(static_cast<uint8_t>(bit_len >> (i * 8)));
  for (size_t block = 0; block < data.size(); block += 64) {
    uint32_t w[64] = {};
    for (int i = 0; i < 16; ++i) w[i] = DigestLoad32(data.data() + block + static_cast<size_t>(i) * 4);
    for (int i = 16; i < 64; ++i) {
      const uint32_t s0 = DigestRotR(w[i - 15], 7) ^ DigestRotR(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const uint32_t s1 = DigestRotR(w[i - 2], 17) ^ DigestRotR(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; ++i) {
      const uint32_t s1 = DigestRotR(e,6)^DigestRotR(e,11)^DigestRotR(e,25);
      const uint32_t ch = (e&f)^((~e)&g);
      const uint32_t t1 = hh+s1+ch+k[i]+w[i];
      const uint32_t s0 = DigestRotR(a,2)^DigestRotR(a,13)^DigestRotR(a,22);
      const uint32_t maj = (a&b)^(a&c)^(b&c);
      const uint32_t t2 = s0+maj;
      hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
  }
  std::array<uint8_t,32> result{};
  for (int i = 0; i < 8; ++i) DigestStore32(h[i], result.data() + static_cast<size_t>(i) * 4);
  return result;
}

}  // namespace detail

inline std::string MutationSha256Hex(const std::vector<uint8_t> &bytes) {
  const auto digest = detail::MutationSha256(bytes);
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (uint8_t byte : digest) out << std::setw(2) << static_cast<unsigned>(byte);
  return out.str();
}

}  // namespace pqcfuzz

#endif

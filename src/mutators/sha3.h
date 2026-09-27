#ifndef PQCFUZZ_MUTATORS_SHA3_H
#define PQCFUZZ_MUTATORS_SHA3_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pqcfuzz {

// Small independent SHA3-256/SHAKE256 used by the NTRU and SIKE/SIDH oracles.
// It is deliberately not the target's fips202.c so a shared bug in the target
// hash cannot validate itself.  Tests pin it against known vectors.
std::vector<uint8_t> Sha3_256(const uint8_t *data, size_t size);
std::vector<uint8_t> Sha3_256(const std::vector<uint8_t> &data);
std::string Sha3_256Hex(const uint8_t *data, size_t size);
std::string Sha3_256Hex(const std::vector<uint8_t> &data);

// SHAKE256 with an arbitrary byte output length (the SIKE profile computes
// SHAKE256 at e2/k bit lengths, which are masked after byte extraction).
std::vector<uint8_t> Shake256(const uint8_t *data, size_t size, size_t out_len);
std::vector<uint8_t> Shake256(const std::vector<uint8_t> &data, size_t out_len);

}  // namespace pqcfuzz

#endif

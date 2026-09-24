#ifndef PQCFUZZ_MUTATORS_SHA3_H
#define PQCFUZZ_MUTATORS_SHA3_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pqcfuzz {

// Small independent SHA3-256 used by the NTRU implicit-rejection oracles.  It
// is deliberately not the target's fips202.c so a shared bug in the target
// hash cannot validate itself.  Tests pin it against known SHA3-256 vectors.
std::vector<uint8_t> Sha3_256(const uint8_t *data, size_t size);
std::vector<uint8_t> Sha3_256(const std::vector<uint8_t> &data);
std::string Sha3_256Hex(const uint8_t *data, size_t size);
std::string Sha3_256Hex(const std::vector<uint8_t> &data);

}  // namespace pqcfuzz

#endif

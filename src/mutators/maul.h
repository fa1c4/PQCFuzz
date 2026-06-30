#ifndef PQCFUZZ_MUTATORS_MAUL_H
#define PQCFUZZ_MUTATORS_MAUL_H

#include <cstdint>
#include <string>
#include <vector>

#include "mutators/ml_kem_mutator.h"

namespace pqcfuzz {

struct MaulResult {
  std::vector<uint8_t> mutated;
  MutationRecord record;
};

MaulResult MaulBytes(
    const std::vector<uint8_t> &input,
    const std::vector<uint8_t> &mutation,
    const std::string &field_name);

}  // namespace pqcfuzz

#endif

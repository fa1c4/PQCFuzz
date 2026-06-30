#ifndef PQCFUZZ_ORACLES_METAMORPHIC_SPEC_H
#define PQCFUZZ_ORACLES_METAMORPHIC_SPEC_H

#include <string>
#include <vector>

namespace pqcfuzz {

struct MetamorphicSpec {
  std::string oracle_id;
  std::string primitive_type;
  std::string field;
  std::string expected_relation;
  std::string finding_subclass;
  bool uses_rng = false;
};

const MetamorphicSpec *FindMetamorphicSpec(const std::string &oracle_id);
std::vector<std::string> DefaultMetamorphicKemOracles();
std::vector<std::string> DefaultMetamorphicSigOracles();

}  // namespace pqcfuzz

#endif

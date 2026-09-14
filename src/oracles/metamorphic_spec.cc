#include "oracles/metamorphic_spec.h"

namespace pqcfuzz {
namespace {

#include "oracles/generated_metamorphic_specs.inc"

std::vector<std::string> OracleIdsForPrimitive(const std::string &primitive_type) {
  std::vector<std::string> ids;
  for (const auto &spec : AllMetamorphicSpecs()) {
    if (spec.primitive_type == primitive_type) {
      ids.push_back(spec.oracle_id);
    }
  }
  return ids;
}

}  // namespace

const std::vector<MetamorphicSpec> &AllMetamorphicSpecs() {
  static const std::vector<MetamorphicSpec> specs = GeneratedMetamorphicOracleSpecs();
  return specs;
}

const MetamorphicSpec *FindMetamorphicSpec(const std::string &oracle_id) {
  for (const auto &spec : AllMetamorphicSpecs()) {
    if (spec.oracle_id == oracle_id) {
      return &spec;
    }
  }
  return nullptr;
}

std::vector<std::string> DefaultMetamorphicKemOracles() {
  return OracleIdsForPrimitive("kem");
}

std::vector<std::string> DefaultMetamorphicSigOracles() {
  return OracleIdsForPrimitive("sig");
}

}  // namespace pqcfuzz

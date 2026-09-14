#include "oracles/oracle_spec.h"

#include <algorithm>

#include "oracles/metamorphic_spec.h"

namespace pqcfuzz {
namespace {

#include "oracles/generated_fips_specs.inc"

std::vector<OracleSpec> SpecsForFamily(const std::string &family) {
  std::vector<OracleSpec> specs;
  for (const auto &spec : AllFipsOracleSpecs()) {
    if (spec.algorithm_family == family) {
      specs.push_back(spec);
    }
  }
  return specs;
}

}  // namespace

const std::vector<OracleSpec> &AllFipsOracleSpecs() {
  static const std::vector<OracleSpec> specs = GeneratedFipsOracleSpecs();
  return specs;
}

std::vector<OracleSpec> DefaultMlKemOracleSpecs() {
  return SpecsForFamily("ML-KEM");
}

std::vector<OracleSpec> DefaultMlDsaOracleSpecs() {
  return SpecsForFamily("ML-DSA");
}

std::vector<OracleSpec> DefaultSlhDsaOracleSpecs() {
  return SpecsForFamily("SLH-DSA");
}

std::vector<OracleSpec> DefaultAigisEncOracleSpecs() {
  return SpecsForFamily("AIGIS-ENC");
}

std::vector<OracleSpec> DefaultAigisSigOracleSpecs() {
  return SpecsForFamily("AIGIS-SIG");
}

const OracleSpec *FindOracleSpec(const std::vector<OracleSpec> &specs, const std::string &oracle_id) {
  for (const auto &spec : specs) {
    if (spec.oracle_id == oracle_id) {
      return &spec;
    }
  }
  return nullptr;
}

const OracleSpec *FindAnyOracleSpec(const std::string &oracle_id) {
  return FindOracleSpec(AllFipsOracleSpecs(), oracle_id);
}

const OracleMetadata *FindOracleMetadata(const std::string &oracle_id) {
  if (const OracleSpec *spec = FindAnyOracleSpec(oracle_id)) {
    return &spec->metadata;
  }
  if (const MetamorphicSpec *spec = FindMetamorphicSpec(oracle_id)) {
    return &spec->metadata;
  }
  return nullptr;
}

}  // namespace pqcfuzz

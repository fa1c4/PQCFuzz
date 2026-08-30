#ifndef PQCFUZZ_ORACLES_ORACLE_SPEC_H
#define PQCFUZZ_ORACLES_ORACLE_SPEC_H

#include <string>
#include <vector>

#include "oracles/expected_relation.h"

namespace pqcfuzz {

struct OracleSpec {
  std::string oracle_id;
  std::string algorithm_family;
  std::string primitive_type;
  std::vector<std::string> api_surface;
  std::string mutation_type;
  std::vector<std::string> mutation_targets;
  ExpectedRelation expected_relation = ExpectedRelation::kUnknown;
  std::string comparator;
  std::string triage_policy;
};

std::vector<OracleSpec> DefaultMlKemOracleSpecs();
std::vector<OracleSpec> DefaultMlDsaOracleSpecs();
std::vector<OracleSpec> DefaultSlhDsaOracleSpecs();
std::vector<OracleSpec> DefaultAigisEncOracleSpecs();
std::vector<OracleSpec> DefaultAigisSigOracleSpecs();
const OracleSpec *FindOracleSpec(const std::vector<OracleSpec> &specs, const std::string &oracle_id);

}  // namespace pqcfuzz

#endif

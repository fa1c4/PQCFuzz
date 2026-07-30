#ifndef PQCFUZZ_ORACLES_ORACLE_REGISTRY_H
#define PQCFUZZ_ORACLES_ORACLE_REGISTRY_H

#include <string>
#include <vector>

namespace pqcfuzz {

enum class EvidenceTier {
  kSecurity,
  kExperimental,
  kDiagnostic,
};

enum class RngPolicy {
  kSameStream,
  kDistinctStreams,
  kNoOverride,
};

struct OracleDescriptor {
  std::string oracle_id;
  std::string primitive;
  std::string field;
  EvidenceTier evidence_tier = EvidenceTier::kDiagnostic;
  RngPolicy rng_policy = RngPolicy::kNoOverride;
  std::string promotion_policy;
};

const std::vector<OracleDescriptor> &OracleRegistry();
const OracleDescriptor *FindOracleDescriptor(const std::string &oracle_id);
const char *EvidenceTierName(EvidenceTier tier);
const char *RngPolicyName(RngPolicy policy);

}  // namespace pqcfuzz

#endif

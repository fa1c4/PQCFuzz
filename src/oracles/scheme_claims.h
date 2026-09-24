#ifndef PQCFUZZ_ORACLES_SCHEME_CLAIMS_H
#define PQCFUZZ_ORACLES_SCHEME_CLAIMS_H

#include <string>
#include <utility>
#include <vector>

#include "oracles/oracle_record.h"

namespace pqcfuzz {

// A claim variant is selected when every condition matches the resolved
// (oracle_id, profile_id, subtest_id) context.  Conditions are deliberately
// explicit strings so a JSON spec cannot silently fall back to the highest
// evidence class.
struct ClaimCondition {
  std::string key;
  std::string value;
};

struct ClaimVariant {
  std::string claim_id;
  std::vector<ClaimCondition> conditions;
  OracleMetadata metadata;
};

struct ResolvedClaim {
  std::string claim_id;
  OracleMetadata metadata;
  bool resolved_by_variant = false;
};

// Condition keys understood by the shared resolver:
//   profile_id, algorithm, subtest_id, format
// Anything else is a harness error, not a silent non-match.
bool ClaimConditionKeyKnown(const std::string &key);

bool ClaimConditionsMatch(
    const std::vector<ClaimCondition> &conditions,
    const std::string &profile_id,
    const std::string &subtest_id,
    const std::vector<std::pair<std::string, std::string>> &extra_attributes);

// Oracles without claim_variants keep the legacy profile-independent
// metadata.  Oracles that declare variants must match exactly one; zero or
// multiple matches are not evaluable and return false.
bool ResolveSchemeClaim(
    const std::string &oracle_id,
    const std::string &profile_id,
    const std::string &subtest_id,
    const std::vector<std::pair<std::string, std::string>> &extra_attributes,
    ResolvedClaim *out,
    std::string *error);

bool ResolveSchemeClaim(
    const std::string &oracle_id,
    const std::string &profile_id,
    const std::string &subtest_id,
    ResolvedClaim *out,
    std::string *error);

}  // namespace pqcfuzz

#endif

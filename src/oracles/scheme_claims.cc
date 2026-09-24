#include "oracles/scheme_claims.h"

#include "oracles/oracle_spec.h"

namespace pqcfuzz {
namespace {

const OracleSpec *FindSpecForOracle(const std::string &oracle_id) {
  for (const OracleSpec &spec : AllFipsOracleSpecs()) {
    if (spec.oracle_id == oracle_id) {
      return &spec;
    }
  }
  return nullptr;
}

bool LookupAttribute(
    const std::string &key,
    const std::string &profile_id,
    const std::string &subtest_id,
    const std::vector<std::pair<std::string, std::string>> &extra_attributes,
    std::string *value) {
  if (key == "profile_id" || key == "algorithm") {
    *value = profile_id;
    return true;
  }
  if (key == "subtest_id") {
    *value = subtest_id;
    return true;
  }
  for (const auto &attribute : extra_attributes) {
    if (attribute.first == key) {
      *value = attribute.second;
      return true;
    }
  }
  // A known key that the caller did not supply can never match a condition.
  if (ClaimConditionKeyKnown(key)) {
    value->clear();
    return true;
  }
  return false;
}

}  // namespace

bool ClaimConditionKeyKnown(const std::string &key) {
  return key == "profile_id" || key == "algorithm" || key == "subtest_id" || key == "format" || key == "variant";
}

bool ClaimConditionsMatch(
    const std::vector<ClaimCondition> &conditions,
    const std::string &profile_id,
    const std::string &subtest_id,
    const std::vector<std::pair<std::string, std::string>> &extra_attributes) {
  for (const ClaimCondition &condition : conditions) {
    std::string value;
    if (!LookupAttribute(condition.key, profile_id, subtest_id, extra_attributes, &value)) {
      return false;
    }
    if (value != condition.value) {
      return false;
    }
  }
  return true;
}

bool ResolveSchemeClaim(
    const std::string &oracle_id,
    const std::string &profile_id,
    const std::string &subtest_id,
    const std::vector<std::pair<std::string, std::string>> &extra_attributes,
    ResolvedClaim *out,
    std::string *error) {
  if (out == nullptr) {
    if (error != nullptr) {
      *error = "scheme claim output pointer is null";
    }
    return false;
  }
  const OracleSpec *spec = FindSpecForOracle(oracle_id);
  if (spec == nullptr) {
    if (error != nullptr) {
      *error = "oracle_id has no generated spec record";
    }
    return false;
  }
  for (const ClaimVariant &variant : spec->claim_variants) {
    for (const ClaimCondition &condition : variant.conditions) {
      if (!ClaimConditionKeyKnown(condition.key)) {
        if (error != nullptr) {
          *error = "claim variant uses an unknown condition key";
        }
        return false;
      }
    }
  }
  if (spec->claim_variants.empty()) {
    out->claim_id = oracle_id;
    out->metadata = spec->metadata;
    out->resolved_by_variant = false;
    return true;
  }
  const ClaimVariant *match = nullptr;
  size_t matches = 0;
  for (const ClaimVariant &variant : spec->claim_variants) {
    if (ClaimConditionsMatch(variant.conditions, profile_id, subtest_id, extra_attributes)) {
      match = &variant;
      ++matches;
    }
  }
  if (matches == 0) {
    if (error != nullptr) {
      *error = "no claim variant matches the profile/subtest context";
    }
    return false;
  }
  if (matches > 1) {
    if (error != nullptr) {
      *error = "conflicting claim variants match the profile/subtest context";
    }
    return false;
  }
  out->claim_id = match->claim_id;
  out->metadata = match->metadata;
  out->resolved_by_variant = true;
  return true;
}

bool ResolveSchemeClaim(
    const std::string &oracle_id,
    const std::string &profile_id,
    const std::string &subtest_id,
    ResolvedClaim *out,
    std::string *error) {
  return ResolveSchemeClaim(oracle_id, profile_id, subtest_id, {}, out, error);
}

}  // namespace pqcfuzz

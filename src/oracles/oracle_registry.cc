#include "oracles/oracle_registry.h"

namespace pqcfuzz {
namespace {

const std::vector<OracleDescriptor> kRegistry = {
    {"kem_decaps_c", "kem", "ciphertext", EvidenceTier::kSecurity, RngPolicy::kSameStream, "requires_v4_replay"},
    {"kem_decaps_sk", "kem", "secret_key", EvidenceTier::kExperimental, RngPolicy::kSameStream, "raw_experimental"},
    {"kem_encaps_badrng", "kem", "rng", EvidenceTier::kDiagnostic, RngPolicy::kDistinctStreams, "diagnostic_rng_contract"},
    {"kem_encaps_pk_0", "kem", "public_key", EvidenceTier::kDiagnostic, RngPolicy::kSameStream, "robustness_diagnostic"},
    {"kem_encaps_pk", "kem", "public_key", EvidenceTier::kExperimental, RngPolicy::kSameStream, "raw_experimental"},
    {"kem_keygen_badrng", "kem", "rng", EvidenceTier::kDiagnostic, RngPolicy::kDistinctStreams, "diagnostic_rng_contract"},
    {"sig_keygen_badrng", "sig", "rng", EvidenceTier::kDiagnostic, RngPolicy::kDistinctStreams, "diagnostic_rng_contract"},
    {"sig_sign_badrng", "sig", "rng", EvidenceTier::kDiagnostic, RngPolicy::kDistinctStreams, "diagnostic_rng_contract"},
    {"sig_sign_m", "sig", "message", EvidenceTier::kExperimental, RngPolicy::kSameStream, "raw_experimental"},
    {"sig_sign_sk", "sig", "secret_key", EvidenceTier::kExperimental, RngPolicy::kSameStream, "raw_experimental"},
    {"sig_verify_m", "sig", "message", EvidenceTier::kSecurity, RngPolicy::kSameStream, "requires_v4_replay"},
    {"sig_verify_sig", "sig", "signature", EvidenceTier::kSecurity, RngPolicy::kSameStream, "requires_v4_replay"},
    {"sig_verify_pk", "sig", "public_key", EvidenceTier::kSecurity, RngPolicy::kSameStream, "requires_valid_alternate_key_replay"},
};

}  // namespace

const std::vector<OracleDescriptor> &OracleRegistry() {
  return kRegistry;
}

const OracleDescriptor *FindOracleDescriptor(const std::string &oracle_id) {
  for (const auto &descriptor : kRegistry) {
    if (descriptor.oracle_id == oracle_id) {
      return &descriptor;
    }
  }
  return nullptr;
}

const char *EvidenceTierName(EvidenceTier tier) {
  switch (tier) {
    case EvidenceTier::kSecurity:
      return "security";
    case EvidenceTier::kExperimental:
      return "experimental";
    case EvidenceTier::kDiagnostic:
      return "diagnostic";
  }
  return "diagnostic";
}

const char *RngPolicyName(RngPolicy policy) {
  switch (policy) {
    case RngPolicy::kSameStream:
      return "same_stream";
    case RngPolicy::kDistinctStreams:
      return "distinct_streams";
    case RngPolicy::kNoOverride:
      return "no_override";
  }
  return "no_override";
}

}  // namespace pqcfuzz

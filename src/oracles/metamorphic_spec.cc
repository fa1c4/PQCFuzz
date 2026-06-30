#include "oracles/metamorphic_spec.h"

#include <array>

namespace pqcfuzz {
namespace {

const std::array<MetamorphicSpec, 13> kSpecs = {{
    {"kem_decaps_c", "kem", "ciphertext", "EXPECT_DIFFERENT", "ciphertext_malleability", false},
    {"kem_decaps_sk", "kem", "secret_key", "EXPECT_DIFFERENT", "secret_key_malleability", false},
    {"kem_encaps_badrng", "kem", "rng", "EXPECT_DIFFERENT", "encaps_rng_ignored", true},
    {"kem_encaps_pk_0", "kem", "public_key", "EXPECT_DIFFERENT", "zero_public_key_equivalence", false},
    {"kem_encaps_pk", "kem", "public_key", "EXPECT_DIFFERENT", "public_key_ignored_or_malleable", false},
    {"kem_keygen_badrng", "kem", "rng", "EXPECT_DIFFERENT", "keygen_rng_ignored", true},
    {"sig_keygen_badrng", "sig", "rng", "EXPECT_DIFFERENT", "keygen_rng_ignored", true},
    {"sig_sign_badrng", "sig", "rng", "EXPECT_DIFFERENT", "sign_rng_ignored", true},
    {"sig_sign_m", "sig", "message", "EXPECT_DIFFERENT", "message_not_bound_in_signature_generation", false},
    {"sig_sign_sk", "sig", "secret_key", "EXPECT_DIFFERENT", "secret_key_ignored_or_malleable", false},
    {"sig_verify_m", "sig", "message", "EXPECT_DIFFERENT", "message_binding_failure", false},
    {"sig_verify_sig", "sig", "signature", "EXPECT_DIFFERENT", "signature_malleability", false},
    {"sig_verify_pk", "sig", "public_key", "EXPECT_DIFFERENT", "public_key_binding_failure", false},
}};

}  // namespace

const MetamorphicSpec *FindMetamorphicSpec(const std::string &oracle_id) {
  for (const auto &spec : kSpecs) {
    if (spec.oracle_id == oracle_id) {
      return &spec;
    }
  }
  return nullptr;
}

std::vector<std::string> DefaultMetamorphicKemOracles() {
  return {
      "kem_decaps_c",
      "kem_decaps_sk",
      "kem_encaps_badrng",
      "kem_encaps_pk_0",
      "kem_encaps_pk",
      "kem_keygen_badrng",
  };
}

std::vector<std::string> DefaultMetamorphicSigOracles() {
  return {
      "sig_keygen_badrng",
      "sig_sign_badrng",
      "sig_sign_m",
      "sig_sign_sk",
      "sig_verify_m",
      "sig_verify_sig",
      "sig_verify_pk",
  };
}

}  // namespace pqcfuzz

// SNOVA executor test driver: runs ExecuteSnovaOracle with adapters looked up
// by id and prints a deterministic summary line per oracle/subtest.  The test
// harness runs it with the real reference adapter and with a deliberately
// broken fake adapter.
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "adapters/snova/sig_adapter.h"
#include "mutators/snova_layout.h"
#include "oracles/oracle_result.h"
#include "oracles/snova_executor.h"

namespace {

const char *StatusName(pqcfuzz::OracleDisposition disposition) {
  using pqcfuzz::OracleDisposition;
  switch (disposition) {
    case OracleDisposition::kPass:
      return "pass";
    case OracleDisposition::kDiagnostic:
      return "diagnostic";
    case OracleDisposition::kNotEvaluable:
      return "not_evaluable";
    case OracleDisposition::kNotApplicable:
      return "not_applicable";
    case OracleDisposition::kRawCandidate:
      return "raw_candidate";
    case OracleDisposition::kSanitizerEvidence:
      return "sanitizer";
    case OracleDisposition::kProcessEvidence:
      return "process";
    case OracleDisposition::kHarnessError:
      return "harness_error";
  }
  return "unknown";
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 4) {
    std::cerr << "usage: snova_executor_main <algorithm> <left_impl> <right_impl> [oracle...]\n";
    return 2;
  }
  const std::string algorithm = argv[1];
  const std::string left_impl = argv[2];
  const std::string right_impl = argv[3];
  pqcfuzz::SnovaParams params{};
  if (!pqcfuzz::GetSnovaParams(algorithm, &params)) {
    std::cerr << "unknown SNOVA algorithm: " << algorithm << "\n";
    return 2;
  }
  const pqcfuzz_sig_adapter *left = pqcfuzz_get_snova_sig_adapter(left_impl.c_str());
  const pqcfuzz_sig_adapter *right = pqcfuzz_get_snova_sig_adapter(right_impl.c_str());
  const pqcfuzz_snova_api *left_api = pqcfuzz_get_snova_api(left_impl.c_str());
  const pqcfuzz_snova_api *right_api = pqcfuzz_get_snova_api(right_impl.c_str());
  if (left == nullptr || left_api == nullptr) {
    std::cout << "UNAVAILABLE\n";
    return 0;
  }

  std::vector<std::string> oracles;
  for (int i = 4; i < argc; ++i) {
    oracles.emplace_back(argv[i]);
  }
  if (oracles.empty()) {
    oracles = {"snova_kat",
               "snova_local_sign_verify",
               "snova_cross_verify",
               "snova_message_salt_binding",
               "snova_public_seed_binding",
               "snova_exact_lengths",
               "snova_nibble_encoding",
               "snova_public_map",
               "snova_fixed_abq",
               "snova_ssk_esk_equivalence",
               "snova_rng_replay",
               "snova_malformed_key_state",
               "snova_backend_profile_gate"};
  }
  std::vector<uint8_t> seed(48);
  for (size_t i = 0; i < seed.size(); ++i) {
    seed[i] = static_cast<uint8_t>(i * 2 + 1);
  }
  const std::vector<uint8_t> message = {'P', 'Q', 'C', 'F', 'u', 'z', 'z', ' ', 'S', 'N', 'O', 'V', 'A'};
  for (const auto &oracle_id : oracles) {
    pqcfuzz::SnovaOracleConfig config;
    config.job_id = "snova_executor_main";
    config.pair_id = "snova_executor_main_pair";
    config.algorithm = algorithm;
    config.oracle_id = oracle_id;
    config.params = params;
    config.left = left;
    config.left_api = left_api;
    config.right = right;
    config.right_api = right_api;
    config.public_key_exchange = true;
    config.signature_exchange = true;
    config.seed = seed;
    config.message = message;
    pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteSnovaOracle(config);
    std::cout << "ORACLE " << oracle_id << " findings=" << trace.findings.size()
              << " relation_evaluable=" << (trace.relation_evaluable ? 1 : 0)
              << " not_applicable=" << (trace.relation_not_applicable ? 1 : 0)
              << " disposition=" << StatusName(pqcfuzz::FinalizeDisposition(trace)) << "\n";
    for (const auto &subtest : trace.subtests) {
      std::cout << "SUBTEST " << oracle_id << " " << subtest.subtest_id << " passed=" << (subtest.passed ? 1 : 0)
                << " na=" << (subtest.not_applicable ? 1 : 0) << " note=" << (subtest.note.empty() ? "-" : subtest.note)
                << "\n";
    }
    for (const auto &finding : trace.findings) {
      std::cout << "FINDING " << oracle_id << " " << finding.finding_class << " " << finding.finding_subclass
                << " verdict=" << static_cast<int>(finding.verdict) << "\n";
    }
  }
  return 0;
}

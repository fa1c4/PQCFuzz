#include <cstdlib>
#include <cctype>
#include <cstring>
#include <iostream>
#include <string>

#include "oracles/kat_executor.h"
#include "runtime/adapter_registry.h"
#include "triage/finding_writer.h"
#include "triage/oracle_coverage.h"

namespace {

std::string ReferenceImplementationFor(const std::string &algorithm) {
  if (algorithm == "ML-KEM-512") return "pqclean_ref_mlkem512";
  if (algorithm == "ML-KEM-768") return "pqclean_ref_mlkem768";
  if (algorithm == "ML-KEM-1024") return "pqclean_ref_mlkem1024";
  if (algorithm.rfind("SLH-DSA-", 0) == 0) {
    std::string token = algorithm.substr(std::string("SLH-DSA-").size());
    std::string normalized = "pqclean_ref_slhdsa_";
    for (char ch : token) {
      normalized.push_back(ch == '-' ? '_' : static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return normalized;
  }
  return "";
}

void PrintUsage() {
  std::cerr << "usage: kat_oracle --result-dir DIR --algorithm ALG --oracle-id ID"
               " [--job-id ID] [--pair-id ID]\n";
}

}  // namespace

int main(int argc, char **argv) {
  std::string result_dir;
  std::string algorithm;
  std::string oracle_id;
  std::string job_id = "kat_reference";
  std::string pair_id = "pqclean_reference_kat";
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    if (i + 1 >= argc) {
      PrintUsage();
      return 2;
    }
    const std::string value = argv[++i];
    if (flag == "--result-dir") {
      result_dir = value;
    } else if (flag == "--algorithm") {
      algorithm = value;
    } else if (flag == "--oracle-id") {
      oracle_id = value;
    } else if (flag == "--job-id") {
      job_id = value;
    } else if (flag == "--pair-id") {
      pair_id = value;
    } else {
      PrintUsage();
      return 2;
    }
  }
  if (result_dir.empty() || algorithm.empty() || oracle_id.empty()) {
    PrintUsage();
    return 2;
  }

  const std::string implementation_id = ReferenceImplementationFor(algorithm);
  const pqcfuzz_kem_adapter *kem = pqcfuzz::GetKemAdapterByProjectAndId("pqclean_reference", implementation_id);
  const pqcfuzz_sig_adapter *sig = pqcfuzz::GetSigAdapterByProjectAndId("pqclean_reference", implementation_id);

  pqcfuzz::KATOracleConfig config;
  config.job_id = job_id;
  config.pair_id = pair_id;
  config.algorithm = algorithm;
  config.oracle_id = oracle_id;
  config.kem = kem;
  config.sig = sig;

  const pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteKATOracle(config);
  pqcfuzz::RecordOracleTrace(result_dir, trace);

  size_t failed = 0;
  for (const auto &subtest : trace.subtests) {
    if (!subtest.passed) {
      ++failed;
    }
  }
  if (pqcfuzz::IsPersistableRawEvidence(trace)) {
    pqcfuzz::FindingArtifactInput artifacts;
    artifacts.job_id = job_id;
    artifacts.pair_id = pair_id;
    artifacts.algorithm = algorithm;
    artifacts.primitive = "kem";
    artifacts.oracle_id = oracle_id;
    artifacts.result_dir = result_dir;
    artifacts.generated_config_json = "{}\n";
    artifacts.trace = trace;
    std::string artifact_dir;
    std::string error;
    if (!pqcfuzz::WriteFindingArtifacts(artifacts, &artifact_dir, &error)) {
      std::cerr << "finding artifact write failed: " << error << "\n";
      return 1;
    }
  }

  std::cout << "oracle=" << oracle_id << " algorithm=" << algorithm
            << " subtests=" << trace.subtests.size() << " failed=" << failed << "\n";
  return failed == 0 ? 0 : 1;
}

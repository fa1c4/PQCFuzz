#include <iostream>
#include <string>

#include "oracles/alloc_failure_oracle.h"
#include "runtime/adapter_registry.h"
#include "triage/finding_writer.h"
#include "triage/oracle_coverage.h"

namespace {

void PrintUsage() {
  std::cerr << "usage: alloc_probe --result-dir DIR --algorithm ALG --project-id ID"
               " --implementation-id ID [--max-sites N] [--job-id ID] [--pair-id ID]\n";
}

}  // namespace

int main(int argc, char **argv) {
  std::string result_dir;
  std::string algorithm;
  std::string project_id;
  std::string implementation_id;
  std::string job_id = "alloc_fault_probe";
  std::string pair_id = "alloc_fault_probe_pair";
  size_t max_sites = 8;

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
    } else if (flag == "--project-id") {
      project_id = value;
    } else if (flag == "--implementation-id") {
      implementation_id = value;
    } else if (flag == "--job-id") {
      job_id = value;
    } else if (flag == "--pair-id") {
      pair_id = value;
    } else if (flag == "--max-sites") {
      max_sites = static_cast<size_t>(std::stoul(value));
    } else {
      PrintUsage();
      return 2;
    }
  }
  if (result_dir.empty() || algorithm.empty() || project_id.empty() || implementation_id.empty()) {
    PrintUsage();
    return 2;
  }

  const pqcfuzz_kem_adapter *adapter = pqcfuzz::GetKemAdapterByProjectAndId(project_id, implementation_id);
  if (adapter == nullptr) {
    std::cerr << "unknown adapter: " << project_id << "/" << implementation_id << "\n";
    return 2;
  }

  pqcfuzz::AllocFailureProbeConfig config;
  config.job_id = job_id;
  config.pair_id = pair_id;
  config.algorithm = algorithm;
  config.kem = adapter;
  config.max_sites = max_sites;

  const pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteAllocFailureProbe(config);
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
    artifacts.oracle_id = config.oracle_id;
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

  std::cout << "oracle=" << config.oracle_id << " algorithm=" << algorithm
            << " subtests=" << trace.subtests.size() << " failed=" << failed << "\n";
  return failed == 0 ? 0 : 1;
}

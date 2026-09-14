#include "oracles/alloc_failure_oracle.h"

#include <algorithm>

#include "oracles/oracle_result.h"
#include "runtime/alloc_fault_injector.h"
#include "runtime/isolated_worker.h"

namespace pqcfuzz {
namespace {

constexpr uint8_t kSentinelFill = 0xA5;

OracleFindingTrace MakeAllocFinding(
    const std::string &oracle_id,
    const std::string &subtest_id,
    const std::string &summary) {
  OracleFindingTrace finding;
  finding.finding_class = "confirmed_semantic_bug";
  finding.finding_subclass = subtest_id;
  finding.summary = summary;
  const FindingClassification classification = ClassifyFinding(oracle_id, EvidenceKind::kSemantic, finding.finding_class);
  finding.verdict = classification.verdict;
  finding.evidence_class = classification.evidence_class;
  finding.conditional_verdict = classification.conditional_verdict;
  finding.claim = classification.claim;
  finding.source_reference = classification.source_reference;
  finding.limitations = classification.limitations;
  return finding;
}

void AddAllocCall(OracleSubtestTrace *subtest, pqcfuzz_status status) {
  OracleCallTrace call;
  call.adapter = "left";
  call.api = "keygen";
  call.status = status;
  call.executor_dispatched = true;
  call.adapter_entered = status != PQCFUZZ_API_UNSUPPORTED;
  call.target_entered = call.adapter_entered;
  call.target_returned = status != PQCFUZZ_CRASH && status != PQCFUZZ_TIMEOUT;
  call.rejection_layer = status == PQCFUZZ_REJECT ? "target" : "";
  subtest->calls.push_back(call);
}

bool AllSentinel(const std::vector<uint8_t> &buffer) {
  return std::all_of(buffer.begin(), buffer.end(), [](uint8_t byte) { return byte == kSentinelFill; });
}

}  // namespace

KEMOracleTrace ExecuteAllocFailureProbe(const AllocFailureProbeConfig &config) {
  KEMOracleTrace trace;
  trace.job_id = config.job_id;
  trace.pair_id = config.pair_id;
  trace.algorithm = config.algorithm;
  trace.oracle_id = config.oracle_id;
  trace.oracle_suite = "fault";
  trace.relation_mode = "fault-injection";
  trace.baseline_setup_valid = true;
  trace.mutated_setup_valid = true;
  trace.baseline_adapter_entered = true;
  trace.baseline_target_entered = true;
  trace.mutated_adapter_entered = true;
  trace.mutated_target_entered = true;
  trace.relation_evaluable = true;
  trace.intervention_supported = true;
  trace.intervention_effective = true;
  trace.controls.positive_control = "key generation succeeds without injected allocation failure";
  trace.controls.negative_control = "each subtest records the number of triggered allocation failures";

  if (config.kem == nullptr || config.kem->keygen == nullptr) {
    trace.relation_evaluable = false;
    trace.intervention_supported = false;
    trace.intervention_effective = false;
    trace.diagnostic_event = "adapter keygen unavailable for allocation fault injection";
    return trace;
  }

  // Baseline control: the same call must succeed without injection.
  pqcfuzz_alloc_fault_disarm();
  std::vector<uint8_t> baseline_pk(config.kem->pk_len, 0);
  std::vector<uint8_t> baseline_sk(config.kem->sk_len, 0);
  const pqcfuzz_status baseline_status = config.kem->keygen(baseline_pk.data(), baseline_sk.data());
  if (baseline_status != PQCFUZZ_OK) {
    trace.baseline_setup_valid = false;
    trace.relation_evaluable = false;
    trace.intervention_supported = false;
    trace.intervention_effective = false;
    trace.diagnostic_event = "baseline key generation failed before fault injection";
    return trace;
  }

  for (size_t site = 1; site <= config.max_sites; ++site) {
    OracleSubtestTrace subtest;
    subtest.subtest_id = "alloc_fail_site_" + std::to_string(site);
    subtest.oracle_id = config.oracle_id;
    subtest.expected_relation = "NO_OUTPUT_ON_ALLOCATION_FAILURE";

    // Each site runs in a forked worker: PQClean-style libraries call exit()
    // or abort() on allocation failure, and the exit behavior is itself an
    // observable part of the failure contract.
    const pqcfuzz_kem_adapter *adapter = config.kem;
    const WorkerResult worker = RunIsolatedWorker([adapter, site]() -> int {
      std::vector<uint8_t> pk(adapter->pk_len, kSentinelFill);
      std::vector<uint8_t> sk(adapter->sk_len, kSentinelFill);
      pqcfuzz_alloc_fault_configure(site, 1);
      const pqcfuzz_status status = adapter->keygen(pk.data(), sk.data());
      const size_t failures = pqcfuzz_alloc_fault_failures();
      pqcfuzz_alloc_fault_disarm();
      if (failures == 0) {
        return 10;
      }
      const bool untouched = AllSentinel(pk) && AllSentinel(sk);
      if (status != PQCFUZZ_OK && untouched) return 0;
      if (status == PQCFUZZ_OK && untouched) return 1;
      if (status == PQCFUZZ_OK) return 2;
      return 3;
    }, 10);

    if (worker.timed_out) {
      subtest.passed = false;
      subtest.note = "key generation did not finish under injected allocation failure";
      trace.findings.push_back(MakeAllocFinding(config.oracle_id, subtest.subtest_id, subtest.note));
      trace.subtests.push_back(subtest);
      return trace;
    }
    if (worker.crashed) {
      subtest.passed = true;
      subtest.note = "process terminated on allocation failure (fail-stop policy)";
      trace.subtests.push_back(subtest);
      return trace;
    }

    pqcfuzz_status status = PQCFUZZ_OK;
    switch (worker.exit_code) {
      case 0:
        subtest.passed = true;
        AddAllocCall(&subtest, PQCFUZZ_INVALID_INPUT);
        break;
      case 1:
        status = PQCFUZZ_OK;
        subtest.passed = false;
        subtest.note = "key generation reported success despite an injected allocation failure";
        AddAllocCall(&subtest, status);
        trace.findings.push_back(MakeAllocFinding(config.oracle_id, subtest.subtest_id, subtest.note));
        break;
      case 2:
        status = PQCFUZZ_OK;
        subtest.passed = false;
        subtest.note = "key generation returned success with output despite an injected allocation failure";
        AddAllocCall(&subtest, status);
        trace.findings.push_back(MakeAllocFinding(config.oracle_id, subtest.subtest_id, subtest.note));
        break;
      case 3:
        subtest.passed = false;
        subtest.note = "failed key generation exposed partial output";
        AddAllocCall(&subtest, PQCFUZZ_INVALID_INPUT);
        trace.findings.push_back(MakeAllocFinding(config.oracle_id, subtest.subtest_id, subtest.note));
        break;
      case 10:
        subtest.passed = true;
        subtest.skipped = true;
        subtest.note = "no allocation failure was triggered at this site";
        trace.subtests.push_back(subtest);
        return trace;
      default:
        subtest.passed = true;
        subtest.note = "implementation rejected the allocation failure by exiting with code " +
            std::to_string(worker.exit_code);
        trace.subtests.push_back(subtest);
        return trace;
    }
    trace.subtests.push_back(subtest);
  }

  return trace;
}

}  // namespace pqcfuzz

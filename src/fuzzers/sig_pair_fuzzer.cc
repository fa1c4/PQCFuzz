#include <cstddef>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "mutators/envelope.h"
#include "mutators/ml_dsa_layout.h"
#include "mutators/slh_dsa_layout.h"
#include "oracles/metamorphic_executor.h"
#include "oracles/oracle_executor.h"
#include "runtime/adapter_registry.h"
#include "triage/finding_writer.h"

#ifndef PQCFUZZ_JOB_ID
#define PQCFUZZ_JOB_ID "adhoc_pqcfuzz_sig_job"
#endif

#ifndef PQCFUZZ_PAIR_ID
#define PQCFUZZ_PAIR_ID "adhoc_liboqs_vs_pqclean_sig"
#endif

#ifndef PQCFUZZ_RESULT_DIR
#define PQCFUZZ_RESULT_DIR "workspace/results/adhoc_pqcfuzz_sig_job"
#endif

#ifndef PQCFUZZ_GENERATED_CONFIG_PATH
#define PQCFUZZ_GENERATED_CONFIG_PATH ""
#endif

#ifndef PQCFUZZ_LEFT_PROJECT_ID
#define PQCFUZZ_LEFT_PROJECT_ID "liboqs"
#endif

#ifndef PQCFUZZ_LEFT_IMPLEMENTATION_ID
#define PQCFUZZ_LEFT_IMPLEMENTATION_ID ""
#endif

#ifndef PQCFUZZ_EXPECTED_ALGORITHM
#define PQCFUZZ_EXPECTED_ALGORITHM "ML-DSA-44"
#endif

#ifndef PQCFUZZ_EXPECTED_IMPLEMENTATION_ID
#define PQCFUZZ_EXPECTED_IMPLEMENTATION_ID PQCFUZZ_LEFT_IMPLEMENTATION_ID
#endif

#ifndef PQCFUZZ_RIGHT_PROJECT_ID
#define PQCFUZZ_RIGHT_PROJECT_ID "pqclean"
#endif

#ifndef PQCFUZZ_RIGHT_IMPLEMENTATION_ID
#define PQCFUZZ_RIGHT_IMPLEMENTATION_ID ""
#endif

#ifndef PQCFUZZ_RELATION_MODE
#define PQCFUZZ_RELATION_MODE "cross-implementation"
#endif

#ifndef PQCFUZZ_ORACLE_SUITE
#define PQCFUZZ_ORACLE_SUITE "fips"
#endif

#ifndef PQCFUZZ_PUBLIC_KEY_EXCHANGE
#define PQCFUZZ_PUBLIC_KEY_EXCHANGE 1
#endif

#ifndef PQCFUZZ_SIGNATURE_EXCHANGE
#define PQCFUZZ_SIGNATURE_EXCHANGE 1
#endif

namespace {

std::string ReadConfigText() {
  if (std::string(PQCFUZZ_GENERATED_CONFIG_PATH).empty()) {
    return "{}\n";
  }
  std::ifstream in(PQCFUZZ_GENERATED_CONFIG_PATH);
  if (!in) {
    return "{}\n";
  }
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pqcfuzz::Envelope envelope;
  std::string error;
  if (!pqcfuzz::ParseEnvelope(data, size, &envelope, &error)) {
    return 0;
  }

  const std::string algorithm = pqcfuzz::AlgorithmName(envelope.algorithm);
  const std::string expected_algorithm = PQCFUZZ_EXPECTED_ALGORITHM;
  if (algorithm != expected_algorithm) {
    return 0;
  }
  pqcfuzz::MlDsaParams params{};
  if (!pqcfuzz::GetMlDsaParams(expected_algorithm, &params)) {
    return 0;
  }
  static const pqcfuzz_sig_adapter *const target =
      pqcfuzz::GetSigAdapterByProjectAndId(PQCFUZZ_LEFT_PROJECT_ID, PQCFUZZ_EXPECTED_IMPLEMENTATION_ID);
  std::string routing_error;
  const pqcfuzz::AdapterRoutingExpectation expected_routing{
      PQCFUZZ_LEFT_PROJECT_ID, PQCFUZZ_EXPECTED_IMPLEMENTATION_ID, expected_algorithm,
      params.pk_len, params.sk_len, 0, 0, params.sig_max_len};
  if (!pqcfuzz::ValidateSigAdapterRouting(target, expected_routing, &routing_error)) {
    return 0;
  }

  pqcfuzz::KEMOracleTrace trace;
  if (std::string(PQCFUZZ_ORACLE_SUITE) == "metamorphic") {
    pqcfuzz::MetamorphicSigConfig config;
    config.job_id = PQCFUZZ_JOB_ID;
    config.pair_id = PQCFUZZ_PAIR_ID;
    config.algorithm = expected_algorithm;
    config.oracle_id = pqcfuzz::OracleName(envelope.oracle_id);
    config.params = params;
    config.target = target;
    config.seed = envelope.seed;
    config.message = envelope.msg.empty() ? std::vector<uint8_t>{'P', 'Q', 'C', 'F', 'u', 'z', 'z'} : envelope.msg;
    config.context = envelope.extra.size() > 255 ? std::vector<uint8_t>(envelope.extra.begin(), envelope.extra.begin() + 255) : envelope.extra;
    config.mutation = envelope.mutation;
    trace = pqcfuzz::ExecuteMetamorphicSigOracle(config);
  } else {
    pqcfuzz::SigOracleExecutorConfig config;
    config.job_id = PQCFUZZ_JOB_ID;
    config.pair_id = PQCFUZZ_PAIR_ID;
    config.algorithm = expected_algorithm;
    config.oracle_id = pqcfuzz::OracleName(envelope.oracle_id);
    config.params = params;
    config.left = target;
    config.right = pqcfuzz::GetSigAdapterByProjectAndId(PQCFUZZ_RIGHT_PROJECT_ID, PQCFUZZ_RIGHT_IMPLEMENTATION_ID);
    config.exchange_contract.public_key_exchange = PQCFUZZ_PUBLIC_KEY_EXCHANGE != 0;
    config.exchange_contract.signature_exchange = PQCFUZZ_SIGNATURE_EXCHANGE != 0;
    config.seed = envelope.seed;
    config.message = envelope.msg.empty() ? std::vector<uint8_t>{'P', 'Q', 'C', 'F', 'u', 'z', 'z'} : envelope.msg;
    config.context = envelope.extra.size() > 255 ? std::vector<uint8_t>(envelope.extra.begin(), envelope.extra.begin() + 255) : envelope.extra;
    config.mutation = envelope.mutation;
    trace = pqcfuzz::ExecuteSigOracle(config);
  }
  trace.oracle_suite = PQCFUZZ_ORACLE_SUITE;
  trace.relation_mode = PQCFUZZ_RELATION_MODE;
  trace.configured_algorithm = expected_algorithm;
  trace.adapter_algorithm = target->algorithm;
  trace.project_id = target->project_id;
  trace.implementation_id = target->implementation_id;
  trace.adapter_pk_len = target->pk_len;
  trace.adapter_sk_len = target->sk_len;
  trace.adapter_sig_max_len = target->sig_max_len;
  if (!trace.findings.empty()) {
    pqcfuzz::FindingArtifactInput artifacts;
    artifacts.job_id = PQCFUZZ_JOB_ID;
    artifacts.pair_id = PQCFUZZ_PAIR_ID;
    artifacts.algorithm = algorithm;
    artifacts.primitive = "sig";
    artifacts.oracle_id = trace.oracle_id;
    artifacts.result_dir = PQCFUZZ_RESULT_DIR;
    artifacts.generated_config_json = ReadConfigText();
    artifacts.structured_input.assign(data, data + size);
    artifacts.trace = trace;
    std::string artifact_dir;
    pqcfuzz::WriteFindingArtifacts(artifacts, &artifact_dir, nullptr);
  }
  return 0;
}

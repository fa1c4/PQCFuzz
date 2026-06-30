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
  pqcfuzz::MlDsaParams params{};
  pqcfuzz::SlhDsaParams slh_params{};
  const bool is_mldsa = pqcfuzz::GetMlDsaParams(algorithm, &params);
  const bool is_slhdsa = pqcfuzz::GetSlhDsaParams(algorithm, &slh_params);
  if (!is_mldsa && !is_slhdsa) {
    return 0;
  }

  pqcfuzz::KEMOracleTrace trace;
  if (std::string(PQCFUZZ_ORACLE_SUITE) == "metamorphic") {
    pqcfuzz::MetamorphicSigConfig config;
    config.job_id = PQCFUZZ_JOB_ID;
    config.pair_id = PQCFUZZ_PAIR_ID;
    config.algorithm = algorithm;
    config.oracle_id = pqcfuzz::OracleName(envelope.oracle_id);
    config.params = params;
    config.slh_params = slh_params;
    config.is_slh_dsa = is_slhdsa;
    config.target = pqcfuzz::GetSigAdapterByProjectAndId(PQCFUZZ_LEFT_PROJECT_ID, PQCFUZZ_LEFT_IMPLEMENTATION_ID);
    config.seed = envelope.seed;
    config.message = envelope.msg.empty() ? std::vector<uint8_t>{'P', 'Q', 'C', 'F', 'u', 'z', 'z'} : envelope.msg;
    config.context = envelope.extra.size() > 255 ? std::vector<uint8_t>(envelope.extra.begin(), envelope.extra.begin() + 255) : envelope.extra;
    config.mutation = envelope.mutation;
    trace = pqcfuzz::ExecuteMetamorphicSigOracle(config);
  } else {
    pqcfuzz::SigOracleExecutorConfig config;
    config.job_id = PQCFUZZ_JOB_ID;
    config.pair_id = PQCFUZZ_PAIR_ID;
    config.algorithm = algorithm;
    config.oracle_id = pqcfuzz::OracleName(envelope.oracle_id);
    config.params = params;
    config.slh_params = slh_params;
    config.is_slh_dsa = is_slhdsa;
    config.left = pqcfuzz::GetSigAdapterByProjectAndId(PQCFUZZ_LEFT_PROJECT_ID, PQCFUZZ_LEFT_IMPLEMENTATION_ID);
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
  if (!trace.findings.empty()) {
    pqcfuzz::FindingArtifactInput artifacts;
    artifacts.job_id = PQCFUZZ_JOB_ID;
    artifacts.pair_id = PQCFUZZ_PAIR_ID;
    artifacts.algorithm = algorithm;
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

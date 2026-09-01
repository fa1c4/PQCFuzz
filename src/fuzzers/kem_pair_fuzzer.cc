#include <cstddef>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "mutators/aigis_enc_layout.h"
#include "mutators/envelope.h"
#include "mutators/ml_kem_layout.h"
#include "oracles/metamorphic_executor.h"
#include "oracles/oracle_executor.h"
#include "runtime/adapter_registry.h"
#include "triage/finding_writer.h"
#include "triage/oracle_coverage.h"

#ifndef PQCFUZZ_JOB_ID
#define PQCFUZZ_JOB_ID "adhoc_pqcfuzz_kem_job"
#endif

#ifndef PQCFUZZ_PAIR_ID
#define PQCFUZZ_PAIR_ID "adhoc_liboqs_vs_pqclean"
#endif

#ifndef PQCFUZZ_RESULT_DIR
#define PQCFUZZ_RESULT_DIR "workspace/results/adhoc_pqcfuzz_kem_job"
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
#define PQCFUZZ_EXPECTED_ALGORITHM "ML-KEM-768"
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

#ifndef PQCFUZZ_CIPHERTEXT_EXCHANGE
#define PQCFUZZ_CIPHERTEXT_EXCHANGE 1
#endif

#ifndef PQCFUZZ_SECRET_KEY_EXCHANGE
#define PQCFUZZ_SECRET_KEY_EXCHANGE 1
#endif

#ifndef PQCFUZZ_SECRET_KEY_FORMAT_COMPATIBLE
#define PQCFUZZ_SECRET_KEY_FORMAT_COMPATIBLE 0
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
    pqcfuzz::RecordEnvelopeParseRejected(PQCFUZZ_RESULT_DIR);
    return 0;
  }
  pqcfuzz::RecordEnvelopeParsed(PQCFUZZ_RESULT_DIR);

  const std::string algorithm = pqcfuzz::AlgorithmName(envelope.algorithm);
  const std::string expected_algorithm = PQCFUZZ_EXPECTED_ALGORITHM;
  if (algorithm != expected_algorithm) {
    pqcfuzz::RecordAlgorithmRejected(PQCFUZZ_RESULT_DIR);
    return 0;  // Invalid input: a fixed binary cannot be relabelled by its envelope.
  }
  pqcfuzz::MlKemParams params{};
  pqcfuzz::AigisEncParams aigis_params{};
  const bool is_aigis = pqcfuzz::GetAigisEncParams(expected_algorithm, &aigis_params);
  if (is_aigis) {
    params = {aigis_params.algorithm, aigis_params.pk_len, aigis_params.sk_len,
              aigis_params.ct_len, aigis_params.ss_len, aigis_params.k,
              aigis_params.c1_bits, aigis_params.c2_bits};
  } else if (!pqcfuzz::GetMlKemParams(expected_algorithm, &params)) {
    return 0;
  }
  static const pqcfuzz_kem_adapter *const target =
      pqcfuzz::GetKemAdapterByProjectAndId(PQCFUZZ_LEFT_PROJECT_ID, PQCFUZZ_EXPECTED_IMPLEMENTATION_ID);
  std::string routing_error;
  const pqcfuzz::AdapterRoutingExpectation expected_routing{
      PQCFUZZ_LEFT_PROJECT_ID, PQCFUZZ_EXPECTED_IMPLEMENTATION_ID, expected_algorithm,
      params.pk_len, params.sk_len, params.ct_len, params.ss_len, 0};
  if (!pqcfuzz::ValidateKemAdapterRouting(target, expected_routing, &routing_error)) {
    pqcfuzz::RecordRoutingRejected(PQCFUZZ_RESULT_DIR);
    return 0;
  }

  pqcfuzz::KEMOracleTrace trace;
  if (std::string(PQCFUZZ_ORACLE_SUITE) == "metamorphic") {
    pqcfuzz::MetamorphicKemConfig config;
    config.job_id = PQCFUZZ_JOB_ID;
    config.pair_id = PQCFUZZ_PAIR_ID;
    config.algorithm = expected_algorithm;
    config.oracle_id = pqcfuzz::OracleName(envelope.oracle_id);
    config.params = params;
    config.target = target;
    config.seed = envelope.seed;
    config.mutation = envelope.mutation;
    trace = pqcfuzz::ExecuteMetamorphicKemOracle(config);
  } else {
    pqcfuzz::OracleExecutorConfig config;
    config.job_id = PQCFUZZ_JOB_ID;
    config.pair_id = PQCFUZZ_PAIR_ID;
    config.algorithm = expected_algorithm;
    config.oracle_id = pqcfuzz::OracleName(envelope.oracle_id);
    config.params = params;
    config.left = target;
    config.right = pqcfuzz::GetKemAdapterByProjectAndId(PQCFUZZ_RIGHT_PROJECT_ID, PQCFUZZ_RIGHT_IMPLEMENTATION_ID);
    config.exchange_contract.public_key_exchange = PQCFUZZ_PUBLIC_KEY_EXCHANGE != 0;
    config.exchange_contract.ciphertext_exchange = PQCFUZZ_CIPHERTEXT_EXCHANGE != 0;
    config.exchange_contract.secret_key_exchange = PQCFUZZ_SECRET_KEY_EXCHANGE != 0;
    config.exchange_contract.secret_key_format_compatible = PQCFUZZ_SECRET_KEY_FORMAT_COMPATIBLE != 0;
    config.seed = envelope.seed;
    config.mutation = envelope.mutation;
    trace = pqcfuzz::ExecuteKemOracle(config);
  }
  trace.oracle_suite = PQCFUZZ_ORACLE_SUITE;
  trace.relation_mode = PQCFUZZ_RELATION_MODE;
  trace.configured_algorithm = expected_algorithm;
  trace.adapter_algorithm = target->algorithm;
  trace.project_id = target->project_id;
  trace.implementation_id = target->implementation_id;
  trace.adapter_pk_len = target->pk_len;
  trace.adapter_sk_len = target->sk_len;
  trace.adapter_ct_len = target->ct_len;
  trace.adapter_ss_len = target->ss_len;
  pqcfuzz::RecordOracleTrace(PQCFUZZ_RESULT_DIR, trace);
  if (pqcfuzz::IsPersistableRawEvidence(trace)) {
    pqcfuzz::FindingArtifactInput artifacts;
    artifacts.job_id = PQCFUZZ_JOB_ID;
    artifacts.pair_id = PQCFUZZ_PAIR_ID;
    artifacts.algorithm = algorithm;
    artifacts.primitive = "kem";
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

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "mutators/envelope.h"
#include "mutators/ml_dsa_layout.h"
#include "mutators/ml_kem_layout.h"
#include "mutators/slh_dsa_layout.h"
#include "oracles/metamorphic_executor.h"
#include "oracles/oracle_executor.h"
#include "runtime/adapter_registry.h"
#include "runtime/exit_codes.h"
#include "runtime/replay_args.h"

namespace {

bool ReadFile(const std::string &path, std::vector<uint8_t> *out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return false;
  }
  out->assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  return true;
}

bool WriteFile(const std::string &path, const std::string &text) {
  std::ofstream out(path);
  if (!out) {
    return false;
  }
  out << text;
  return true;
}

std::vector<uint8_t> DefaultMessage(const std::vector<uint8_t> &message) {
  if (!message.empty()) {
    return message;
  }
  return {'P', 'Q', 'C', 'F', 'u', 'z', 'z'};
}

}  // namespace

int main(int argc, char **argv) {
  pqcfuzz::ReplayArgs args;
  std::string error;
  if (!pqcfuzz::ParseReplayArgs(argc, argv, &args, &error)) {
    std::cerr << error << "\n" << pqcfuzz::ReplayArgsUsage() << "\n";
    return pqcfuzz::kExitInvalidInputOrConfig;
  }

  std::vector<uint8_t> input;
  if (!ReadFile(args.input, &input)) {
    std::cerr << "failed to read input: " << args.input << "\n";
    return pqcfuzz::kExitInvalidInputOrConfig;
  }

  pqcfuzz::Envelope envelope;
  if (!pqcfuzz::ParseEnvelope(input.data(), input.size(), &envelope, &error)) {
    std::cerr << "failed to parse PQCFuzz envelope: " << error << "\n";
    return pqcfuzz::kExitInvalidInputOrConfig;
  }

  const std::string envelope_algorithm = pqcfuzz::AlgorithmName(envelope.algorithm);
  if (envelope_algorithm != args.algorithm) {
    std::cerr << "input algorithm " << envelope_algorithm << " does not match job algorithm "
              << args.algorithm << "\n";
    return pqcfuzz::kExitInvalidInputOrConfig;
  }

  pqcfuzz::KEMOracleTrace trace;
  if (args.primitive_type == "sig") {
    pqcfuzz::MlDsaParams dsa_params{};
    pqcfuzz::SlhDsaParams slh_params{};
    const bool is_mldsa = pqcfuzz::GetMlDsaParams(args.algorithm, &dsa_params);
    const bool is_slhdsa = pqcfuzz::GetSlhDsaParams(args.algorithm, &slh_params);
    if (!is_mldsa && !is_slhdsa) {
      std::cerr << "unsupported signature algorithm: " << args.algorithm << "\n";
      return pqcfuzz::kExitInvalidInputOrConfig;
    }

    if (args.oracle_suite == pqcfuzz::OracleSuite::kMetamorphic) {
      pqcfuzz::MetamorphicSigConfig config;
      config.job_id = args.job_id;
      config.pair_id = args.pair_id;
      config.algorithm = args.algorithm;
      config.oracle_id = args.oracle_id;
      config.params = dsa_params;
      config.slh_params = slh_params;
      config.is_slh_dsa = is_slhdsa;
      config.target = pqcfuzz::GetSigAdapterByProjectAndId(args.left_project_id, args.left_implementation_id);
      config.seed = envelope.seed;
      config.message = DefaultMessage(envelope.msg);
      config.context = envelope.extra.size() > 255
                           ? std::vector<uint8_t>(envelope.extra.begin(), envelope.extra.begin() + 255)
                           : envelope.extra;
      config.mutation = envelope.mutation;
      trace = pqcfuzz::ExecuteMetamorphicSigOracle(config);
    } else {
      pqcfuzz::SigOracleExecutorConfig config;
      config.job_id = args.job_id;
      config.pair_id = args.pair_id;
      config.algorithm = args.algorithm;
      config.oracle_id = args.oracle_id;
      config.params = dsa_params;
      config.slh_params = slh_params;
      config.is_slh_dsa = is_slhdsa;
      config.left = pqcfuzz::GetSigAdapterByProjectAndId(args.left_project_id, args.left_implementation_id);
      config.right = pqcfuzz::GetSigAdapterByProjectAndId(args.right_project_id, args.right_implementation_id);
      config.exchange_contract.public_key_exchange = args.public_key_exchange;
      config.exchange_contract.signature_exchange = args.signature_exchange;
      config.seed = envelope.seed;
      config.message = DefaultMessage(envelope.msg);
      config.context = envelope.extra.size() > 255
                           ? std::vector<uint8_t>(envelope.extra.begin(), envelope.extra.begin() + 255)
                           : envelope.extra;
      config.mutation = envelope.mutation;
      trace = pqcfuzz::ExecuteSigOracle(config);
    }
  } else {
    pqcfuzz::MlKemParams params{};
    if (!pqcfuzz::GetMlKemParams(args.algorithm, &params)) {
      std::cerr << "unsupported ML-KEM algorithm: " << args.algorithm << "\n";
      return pqcfuzz::kExitInvalidInputOrConfig;
    }

    if (args.oracle_suite == pqcfuzz::OracleSuite::kMetamorphic) {
      pqcfuzz::MetamorphicKemConfig config;
      config.job_id = args.job_id;
      config.pair_id = args.pair_id;
      config.algorithm = args.algorithm;
      config.oracle_id = args.oracle_id;
      config.params = params;
      config.target = pqcfuzz::GetKemAdapterByProjectAndId(args.left_project_id, args.left_implementation_id);
      config.seed = envelope.seed;
      config.mutation = envelope.mutation;
      trace = pqcfuzz::ExecuteMetamorphicKemOracle(config);
    } else {
      pqcfuzz::OracleExecutorConfig config;
      config.job_id = args.job_id;
      config.pair_id = args.pair_id;
      config.algorithm = args.algorithm;
      config.oracle_id = args.oracle_id;
      config.params = params;
      config.left = pqcfuzz::GetKemAdapterByProjectAndId(args.left_project_id, args.left_implementation_id);
      config.right = pqcfuzz::GetKemAdapterByProjectAndId(args.right_project_id, args.right_implementation_id);
      config.exchange_contract.public_key_exchange = args.public_key_exchange;
      config.exchange_contract.ciphertext_exchange = args.ciphertext_exchange;
      config.exchange_contract.secret_key_exchange = args.secret_key_exchange;
      config.exchange_contract.secret_key_format_compatible = args.secret_key_format_compatible;
      config.seed = envelope.seed;
      config.mutation = envelope.mutation;
      trace = pqcfuzz::ExecuteKemOracle(config);
    }
  }

  trace.oracle_suite = pqcfuzz::OracleSuiteName(args.oracle_suite);
  trace.relation_mode = pqcfuzz::RelationModeName(args.relation_mode);
  if (!WriteFile(args.trace, pqcfuzz::TraceToJson(trace))) {
    std::cerr << "failed to write trace: " << args.trace << "\n";
    return pqcfuzz::kExitInvalidInputOrConfig;
  }

  return trace.findings.empty() ? pqcfuzz::kExitNoFinding : pqcfuzz::kExitCryptoOracleViolation;
}

#ifndef PQCFUZZ_ORACLES_ORACLE_EXECUTOR_H
#define PQCFUZZ_ORACLES_ORACLE_EXECUTOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "adapters/adapter_interface.h"
#include "mutators/ml_dsa_layout.h"
#include "mutators/ml_kem_layout.h"
#include "mutators/ml_kem_mutator.h"
#include "mutators/slh_dsa_layout.h"

namespace pqcfuzz {

struct KEMKeyPair {
  std::vector<uint8_t> pk;
  std::vector<uint8_t> sk;
  pqcfuzz_status status = PQCFUZZ_INVALID_INPUT;
};

struct KEMCiphertext {
  std::vector<uint8_t> ct;
  pqcfuzz_status status = PQCFUZZ_INVALID_INPUT;
};

struct KEMSharedSecret {
  std::vector<uint8_t> ss;
  pqcfuzz_status status = PQCFUZZ_INVALID_INPUT;
};

struct SIGKeyPair {
  std::vector<uint8_t> pk;
  std::vector<uint8_t> sk;
  pqcfuzz_status status = PQCFUZZ_INVALID_INPUT;
};

struct SIGSignature {
  std::vector<uint8_t> sig;
  pqcfuzz_status status = PQCFUZZ_INVALID_INPUT;
};

struct SIGVerifyResult {
  pqcfuzz_status status = PQCFUZZ_INVALID_INPUT;
  bool accepted = false;
};

struct PairExchangeContract {
  bool public_key_exchange = false;
  bool ciphertext_exchange = false;
  bool secret_key_exchange = false;
  bool secret_key_format_compatible = false;
  bool signature_exchange = false;
};

struct OracleCallTrace {
  std::string adapter;
  std::string api;
  pqcfuzz_status status = PQCFUZZ_INVALID_INPUT;
  bool has_bool_result = false;
  bool bool_result = false;
};

struct OracleSubtestTrace {
  std::string subtest_id;
  std::string oracle_id;
  std::string expected_relation;
  bool passed = true;
  bool skipped = false;
  std::string note;
  std::vector<OracleCallTrace> calls;
};

struct OracleFindingTrace {
  std::string finding_class;
  std::string finding_subclass;
  std::string summary;
};

struct ObservationTrace {
  pqcfuzz_status status = PQCFUZZ_INVALID_INPUT;
  bool has_bool = false;
  bool bool_value = false;
  std::string output_sha256;
  size_t output_size = 0;
};

struct KEMOracleTrace {
  std::string oracle_suite = "fips";
  std::string relation_mode = "cross-implementation";
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id;
  std::string field;
  std::string expected_relation;
  std::string observed_relation;
  std::string finding_class;
  std::string finding_subclass;
  std::string mutation_target;
  pqcfuzz_status left_status = PQCFUZZ_INVALID_INPUT;
  pqcfuzz_status right_status = PQCFUZZ_INVALID_INPUT;
  bool has_verify_result = false;
  bool verify_result = false;
  bool legal_negative_outcome = false;
  ObservationTrace baseline;
  ObservationTrace mutated;
  std::vector<OracleSubtestTrace> subtests;
  std::vector<MutationRecord> mutations;
  std::vector<OracleFindingTrace> findings;
};

struct OracleExecutorConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id;
  MlKemParams params;
  const pqcfuzz_kem_adapter *left = nullptr;
  const pqcfuzz_kem_adapter *right = nullptr;
  PairExchangeContract exchange_contract;
  std::vector<uint8_t> seed;
  std::vector<uint8_t> mutation;
};

struct SigOracleExecutorConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id;
  MlDsaParams params;
  SlhDsaParams slh_params;
  bool is_slh_dsa = false;
  const pqcfuzz_sig_adapter *left = nullptr;
  const pqcfuzz_sig_adapter *right = nullptr;
  PairExchangeContract exchange_contract;
  std::vector<uint8_t> seed;
  std::vector<uint8_t> message;
  std::vector<uint8_t> context;
  std::vector<uint8_t> mutation;
  std::vector<uint8_t> oid;
};

KEMOracleTrace ExecuteKemOracle(const OracleExecutorConfig &config);
KEMOracleTrace ExecuteSigOracle(const SigOracleExecutorConfig &config);
std::string TraceToJson(const KEMOracleTrace &trace);

}  // namespace pqcfuzz

#endif

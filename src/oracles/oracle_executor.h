#ifndef PQCFUZZ_ORACLES_ORACLE_EXECUTOR_H
#define PQCFUZZ_ORACLES_ORACLE_EXECUTOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "adapters/adapter_interface.h"
#include "mutators/aigis_enc_layout.h"
#include "mutators/aigis_sig_layout.h"
#include "mutators/ml_dsa_layout.h"
#include "mutators/ml_kem_layout.h"
#include "mutators/ml_kem_mutator.h"
#include "mutators/slh_dsa_layout.h"
#include "oracles/oracle_result.h"

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
  bool executor_dispatched = false;
  bool adapter_entered = false;
  bool target_entered = false;
  bool target_returned = false;
  std::string rejection_layer;
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
  EvidenceKind evidence_kind = EvidenceKind::kSemantic;
  std::string source_phase = "fuzz";
  std::string fingerprint;
};

struct OracleDiagnosticTrace {
  std::string code;
  std::string stage;
  std::string summary;
};

struct ObservationTrace {
  pqcfuzz_status status = PQCFUZZ_INVALID_INPUT;
  bool has_bool = false;
  bool bool_value = false;
  std::string output_sha256;
  size_t output_size = 0;
};

struct RngInterventionTrace {
  std::string baseline_tape_id;
  std::string mutated_tape_id;
  std::string baseline_tape_sha256;
  std::string mutated_tape_sha256;
  bool tapes_distinct = false;
  bool baseline_override_active = false;
  bool mutated_override_active = false;
  size_t baseline_bytes_consumed = 0;
  size_t mutated_bytes_consumed = 0;
};

struct KEMOracleTrace {
  int oracle_semantics_version = 4;
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
  std::string configured_algorithm;
  std::string adapter_algorithm;
  std::string project_id;
  std::string implementation_id;
  size_t adapter_pk_len = 0;
  size_t adapter_sk_len = 0;
  size_t adapter_ct_len = 0;
  size_t adapter_ss_len = 0;
  size_t adapter_sig_max_len = 0;
  // valid_setup is retained only for in-process source compatibility with v2
  // executors.  It is intentionally never serialized or used for v3 verdicts.
  bool valid_setup = true;
  bool baseline_setup_valid = true;
  bool mutated_setup_valid = true;
  bool baseline_adapter_entered = false;
  bool baseline_target_entered = false;
  bool mutated_adapter_entered = false;
  bool mutated_target_entered = false;
  bool relation_evaluable = true;
  bool intervention_supported = true;
  bool intervention_effective = true;
  std::string diagnostic_event;
  pqcfuzz_status left_status = PQCFUZZ_INVALID_INPUT;
  pqcfuzz_status right_status = PQCFUZZ_INVALID_INPUT;
  bool has_verify_result = false;
  bool verify_result = false;
  bool legal_negative_outcome = false;
  ObservationTrace baseline;
  ObservationTrace mutated;
  std::vector<OracleSubtestTrace> subtests;
  std::vector<MutationRecord> mutations;
  std::vector<RngInterventionTrace> rng_interventions;
  std::vector<OracleDiagnosticTrace> diagnostics;
  std::vector<OracleFindingTrace> findings;
};

struct OracleExecutorConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id;
  MlKemParams params;
  AigisEncParams aigis_params;
  bool is_aigis_enc = false;
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
  AigisSigParams aigis_sig_params;
  bool is_slh_dsa = false;
  bool is_aigis_sig = false;
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

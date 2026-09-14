#ifndef PQCFUZZ_ORACLES_KAT_EXECUTOR_H
#define PQCFUZZ_ORACLES_KAT_EXECUTOR_H

#include <cstddef>
#include <string>
#include <vector>

#include "adapters/adapter_interface.h"
#include "oracles/oracle_executor.h"

namespace pqcfuzz {

// One reference vector row from src/oracles/kat/generated_kat_vectors.inc.
struct KATVector {
  const char *case_id;
  const char *parameter_set;
  const char *operation;
  const char *input_a_hex;
  const char *input_b_hex;
  const char *input_c_hex;
  const char *expected_a_hex;
  const char *expected_b_hex;
};

struct KATOracleConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;   // parameter-set filter; empty matches every vector
  std::string oracle_id;   // fips203_kat_keygen | fips203_kat_encaps | fips203_kat_decaps | fips205_kat_keygen
  const pqcfuzz_kem_adapter *kem = nullptr;
  const pqcfuzz_sig_adapter *sig = nullptr;
};

// Exact-byte reference-vector oracle.  A mismatch is a NONCONFORMANT finding;
// missing deterministic hooks yield NOT_APPLICABLE subtests.
KEMOracleTrace ExecuteKATOracle(const KATOracleConfig &config);

}  // namespace pqcfuzz

#endif

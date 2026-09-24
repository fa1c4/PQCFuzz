#ifndef PQCFUZZ_ORACLES_NTRU_EXECUTOR_H
#define PQCFUZZ_ORACLES_NTRU_EXECUTOR_H

#include <string>
#include <vector>

#include "adapters/adapter_interface.h"
#include "mutators/ntru_layout.h"
#include "oracles/oracle_executor.h"

namespace pqcfuzz {

// NTRU has its own KEM params/layout and a SHA3-256 implicit-rejection
// contract, so it executes through this entry point instead of MlKemParams.
// Fuzz and replay call exactly this function.
struct NtruOracleConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id;
  NtruParams params{};
  const pqcfuzz_kem_adapter *left = nullptr;
  const pqcfuzz_kem_adapter *right = nullptr;
  PairExchangeContract exchange_contract;
  std::vector<uint8_t> seed;
  std::vector<uint8_t> mutation;
};

KEMOracleTrace ExecuteNtruOracle(const NtruOracleConfig &config);

}  // namespace pqcfuzz

#endif

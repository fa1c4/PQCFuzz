#ifndef PQCFUZZ_ORACLES_SIKE_EXECUTOR_H
#define PQCFUZZ_ORACLES_SIKE_EXECUTOR_H

#include <string>
#include <vector>

#include "adapters/adapter_interface.h"
#include "mutators/sike_layout.h"
#include "oracles/oracle_executor.h"

namespace pqcfuzz {

// SIKE uncompressed KEM has its own params, hash contract and re-encryption
// gate, so it executes through this entry point instead of MlKemParams.  Fuzz
// and replay call exactly this function.
struct SikeOracleConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id;
  SikeParams params{};
  const pqcfuzz_kem_adapter *left = nullptr;
  const pqcfuzz_kem_adapter *right = nullptr;
  PairExchangeContract exchange_contract;
  std::vector<uint8_t> seed;
  std::vector<uint8_t> mutation;
};

KEMOracleTrace ExecuteSikeOracle(const SikeOracleConfig &config);

}  // namespace pqcfuzz

#endif

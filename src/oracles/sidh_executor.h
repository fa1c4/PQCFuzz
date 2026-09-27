#ifndef PQCFUZZ_ORACLES_SIDH_EXECUTOR_H
#define PQCFUZZ_ORACLES_SIDH_EXECUTOR_H

#include <string>
#include <vector>

#include "adapters/kex_adapter_interface.h"
#include "mutators/sike_layout.h"
#include "oracles/oracle_executor.h"

namespace pqcfuzz {

// SIDH is an unauthenticated key exchange with role-specific scalar spaces and
// a 2*Np-byte native shared value.  It never runs through the KEM executor.
struct SidhOracleConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id;
  SidhParams params{};
  const pqcfuzz_kex_adapter *left = nullptr;
  const pqcfuzz_kex_adapter *right = nullptr;
  PairExchangeContract exchange_contract;
  std::vector<uint8_t> seed;
  std::vector<uint8_t> mutation;
};

KEMOracleTrace ExecuteSidhOracle(const SidhOracleConfig &config);

}  // namespace pqcfuzz

#endif

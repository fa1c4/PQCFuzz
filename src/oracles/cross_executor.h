#ifndef PQCFUZZ_ORACLES_CROSS_EXECUTOR_H
#define PQCFUZZ_ORACLES_CROSS_EXECUTOR_H

#include <string>
#include <vector>

#include "adapters/adapter_interface.h"
#include "mutators/cross_layout.h"
#include "oracles/oracle_executor.h"

namespace pqcfuzz {

// CROSS has randomized signing and no context interface, so it gets its own
// executor instead of being forced through MlDsaParams and the ML-DSA
// mutators.  Fuzz and replay call exactly this entry point.
struct CrossOracleConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id;
  CrossParams params{};
  const pqcfuzz_sig_adapter *left = nullptr;
  const pqcfuzz_sig_adapter *right = nullptr;
  std::vector<uint8_t> seed;
  std::vector<uint8_t> message;
  std::vector<uint8_t> mutation;
  bool public_key_exchange = false;
  bool signature_exchange = false;
};

KEMOracleTrace ExecuteCrossOracle(const CrossOracleConfig &config);

}  // namespace pqcfuzz

#endif

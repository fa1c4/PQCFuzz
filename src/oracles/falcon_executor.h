#ifndef PQCFUZZ_ORACLES_FALCON_EXECUTOR_H
#define PQCFUZZ_ORACLES_FALCON_EXECUTOR_H

#include <string>
#include <vector>

#include "adapters/adapter_interface.h"
#include "mutators/falcon_layout.h"
#include "oracles/oracle_executor.h"

namespace pqcfuzz {

// Falcon has three signature formats, a variable-length compressed payload and
// no context interface, so it executes through its own params/layout instead of
// MlDsaParams.  Fuzz and replay call exactly this entry point.
struct FalconOracleConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id;
  FalconParams params{};
  const pqcfuzz_sig_adapter *left = nullptr;
  const pqcfuzz_sig_adapter *right = nullptr;
  std::vector<uint8_t> seed;
  std::vector<uint8_t> message;
  std::vector<uint8_t> mutation;
  bool public_key_exchange = false;
  bool signature_exchange = false;
};

KEMOracleTrace ExecuteFalconOracle(const FalconOracleConfig &config);

}  // namespace pqcfuzz

#endif

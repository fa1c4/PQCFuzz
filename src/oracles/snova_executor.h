#ifndef PQCFUZZ_ORACLES_SNOVA_EXECUTOR_H
#define PQCFUZZ_ORACLES_SNOVA_EXECUTOR_H

#include <string>
#include <vector>

#include "adapters/adapter_interface.h"
#include "adapters/snova/sig_adapter.h"
#include "mutators/snova_layout.h"
#include "oracles/oracle_executor.h"

namespace pqcfuzz {

// SNOVA has a NIST signed-message API, a digest-level API, SSK/ESK private-key
// storage formats and two public-key expansion backends, so it gets its own
// params/layout and executor instead of being coerced into MlDsaParams.
struct SnovaOracleConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id;
  SnovaParams params{};
  const pqcfuzz_sig_adapter *left = nullptr;
  const pqcfuzz_snova_api *left_api = nullptr;
  const pqcfuzz_sig_adapter *right = nullptr;
  const pqcfuzz_snova_api *right_api = nullptr;
  bool public_key_exchange = false;
  bool signature_exchange = false;
  std::vector<uint8_t> seed;
  std::vector<uint8_t> message;
  std::vector<uint8_t> mutation;
};

KEMOracleTrace ExecuteSnovaOracle(const SnovaOracleConfig &config);

}  // namespace pqcfuzz

#endif

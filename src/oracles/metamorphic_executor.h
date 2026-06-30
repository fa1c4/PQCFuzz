#ifndef PQCFUZZ_ORACLES_METAMORPHIC_EXECUTOR_H
#define PQCFUZZ_ORACLES_METAMORPHIC_EXECUTOR_H

#include <string>
#include <vector>

#include "adapters/adapter_interface.h"
#include "mutators/ml_dsa_layout.h"
#include "mutators/ml_kem_layout.h"
#include "mutators/slh_dsa_layout.h"
#include "oracles/oracle_executor.h"

namespace pqcfuzz {

struct MetamorphicKemConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id;
  MlKemParams params;
  const pqcfuzz_kem_adapter *target = nullptr;
  std::vector<uint8_t> seed;
  std::vector<uint8_t> mutation;
};

struct MetamorphicSigConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id;
  MlDsaParams params;
  SlhDsaParams slh_params;
  bool is_slh_dsa = false;
  const pqcfuzz_sig_adapter *target = nullptr;
  std::vector<uint8_t> seed;
  std::vector<uint8_t> message;
  std::vector<uint8_t> context;
  std::vector<uint8_t> mutation;
};

KEMOracleTrace ExecuteMetamorphicKemOracle(const MetamorphicKemConfig &config);
KEMOracleTrace ExecuteMetamorphicSigOracle(const MetamorphicSigConfig &config);

}  // namespace pqcfuzz

#endif

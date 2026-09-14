#ifndef PQCFUZZ_ORACLES_ALLOC_FAILURE_ORACLE_H
#define PQCFUZZ_ORACLES_ALLOC_FAILURE_ORACLE_H

#include <cstddef>
#include <string>

#include "adapters/adapter_interface.h"
#include "oracles/oracle_executor.h"

namespace pqcfuzz {

// Allocation-failure contract oracle (design doc Sections 25 and 36.7).
// Requires a binary built with -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc
// and src/runtime/alloc_fault_injector.cc.
struct AllocFailureProbeConfig {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string oracle_id = "alloc_failure_contract";
  const pqcfuzz_kem_adapter *kem = nullptr;
  size_t max_sites = 8;
};

KEMOracleTrace ExecuteAllocFailureProbe(const AllocFailureProbeConfig &config);

}  // namespace pqcfuzz

#endif

#ifndef PQCFUZZ_RUNTIME_ADAPTER_REGISTRY_H
#define PQCFUZZ_RUNTIME_ADAPTER_REGISTRY_H

#include <string>

#include "adapters/adapter_interface.h"

namespace pqcfuzz {

struct AdapterRoutingExpectation {
  std::string project_id;
  std::string implementation_id;
  std::string algorithm;
  size_t pk_len = 0;
  size_t sk_len = 0;
  size_t ct_len = 0;
  size_t ss_len = 0;
  size_t sig_max_len = 0;
};

const pqcfuzz_kem_adapter *GetKemAdapterByProjectAndId(
    const std::string &project_id,
    const std::string &implementation_id);

const pqcfuzz_sig_adapter *GetSigAdapterByProjectAndId(
    const std::string &project_id,
    const std::string &implementation_id);

bool ValidateKemAdapterRouting(
    const pqcfuzz_kem_adapter *adapter,
    const AdapterRoutingExpectation &expected,
    std::string *error);
bool ValidateSigAdapterRouting(
    const pqcfuzz_sig_adapter *adapter,
    const AdapterRoutingExpectation &expected,
    std::string *error);

}  // namespace pqcfuzz

#endif

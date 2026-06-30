#ifndef PQCFUZZ_RUNTIME_ADAPTER_REGISTRY_H
#define PQCFUZZ_RUNTIME_ADAPTER_REGISTRY_H

#include <string>

#include "adapters/adapter_interface.h"

namespace pqcfuzz {

const pqcfuzz_kem_adapter *GetKemAdapterByProjectAndId(
    const std::string &project_id,
    const std::string &implementation_id);

const pqcfuzz_sig_adapter *GetSigAdapterByProjectAndId(
    const std::string &project_id,
    const std::string &implementation_id);

}  // namespace pqcfuzz

#endif

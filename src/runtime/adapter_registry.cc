#include "runtime/adapter_registry.h"

#include "adapters/liboqs/kem_adapter.h"
#include "adapters/liboqs/sig_adapter.h"
#include "adapters/pqclean/kem_adapter.h"
#include "adapters/pqclean/sig_adapter.h"

namespace pqcfuzz {

const pqcfuzz_kem_adapter *GetKemAdapterByProjectAndId(
    const std::string &project_id,
    const std::string &implementation_id) {
  if (project_id == "liboqs" || project_id == "liboqs_self_reference") {
    return pqcfuzz_get_liboqs_adapter(implementation_id.c_str());
  }
  if (project_id == "pqclean") {
    return pqcfuzz_get_pqclean_adapter(implementation_id.c_str());
  }
  return nullptr;
}

const pqcfuzz_sig_adapter *GetSigAdapterByProjectAndId(
    const std::string &project_id,
    const std::string &implementation_id) {
  if (project_id == "liboqs" || project_id == "liboqs_self_reference") {
    return pqcfuzz_get_liboqs_sig_adapter(implementation_id.c_str());
  }
  if (project_id == "pqclean") {
    return pqcfuzz_get_pqclean_sig_adapter(implementation_id.c_str());
  }
  return nullptr;
}

}  // namespace pqcfuzz

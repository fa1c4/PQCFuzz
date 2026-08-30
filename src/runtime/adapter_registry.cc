#include "runtime/adapter_registry.h"

#include <cstring>

#include "adapters/liboqs/kem_adapter.h"
#include "adapters/liboqs/sig_adapter.h"
#include "adapters/pqclean/kem_adapter.h"
#include "adapters/pqclean/sig_adapter.h"
#include "adapters/pqmagic/kem_adapter.h"
#include "adapters/pqmagic/sig_adapter.h"

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
  if (project_id == "pqmagic") {
    return pqcfuzz_get_pqmagic_adapter(implementation_id.c_str());
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
  if (project_id == "pqmagic") {
    return pqcfuzz_get_pqmagic_sig_adapter(implementation_id.c_str());
  }
  return nullptr;
}

namespace {

bool Same(const char *actual, const std::string &expected) {
  return actual != nullptr && actual == expected;
}

bool Fail(std::string *error, const std::string &message) {
  if (error != nullptr) {
    *error = message;
  }
  return false;
}

}  // namespace

bool ValidateKemAdapterRouting(
    const pqcfuzz_kem_adapter *adapter,
    const AdapterRoutingExpectation &expected,
    std::string *error) {
  if (adapter == nullptr) return Fail(error, "adapter unavailable");
  if (!Same(adapter->project_id, expected.project_id)) return Fail(error, "adapter project mismatch");
  if (!Same(adapter->implementation_id, expected.implementation_id)) return Fail(error, "adapter implementation mismatch");
  if (!Same(adapter->algorithm, expected.algorithm)) return Fail(error, "adapter algorithm mismatch");
  if (adapter->pk_len != expected.pk_len || adapter->sk_len != expected.sk_len ||
      adapter->ct_len != expected.ct_len || adapter->ss_len != expected.ss_len) {
    return Fail(error, "adapter ABI length mismatch");
  }
  return true;
}

bool ValidateSigAdapterRouting(
    const pqcfuzz_sig_adapter *adapter,
    const AdapterRoutingExpectation &expected,
    std::string *error) {
  if (adapter == nullptr) return Fail(error, "adapter unavailable");
  if (!Same(adapter->project_id, expected.project_id)) return Fail(error, "adapter project mismatch");
  if (!Same(adapter->implementation_id, expected.implementation_id)) return Fail(error, "adapter implementation mismatch");
  if (!Same(adapter->algorithm, expected.algorithm)) return Fail(error, "adapter algorithm mismatch");
  if (adapter->pk_len != expected.pk_len || adapter->sk_len != expected.sk_len ||
      adapter->sig_max_len != expected.sig_max_len) {
    return Fail(error, "adapter ABI length mismatch");
  }
  return true;
}

}  // namespace pqcfuzz

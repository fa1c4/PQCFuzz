#ifndef PQCFUZZ_ADAPTERS_REFERENCE_REFERENCE_ADAPTER_H
#define PQCFUZZ_ADAPTERS_REFERENCE_REFERENCE_ADAPTER_H

#include "adapters/adapter_interface.h"

namespace pqcfuzz {

// PQClean clean-reference adapters (ML-KEM and ML-DSA).  The translation unit
// compiles without PQClean; the adapters report API_UNSUPPORTED until the
// build links the pinned reference archive with
// -DPQCFUZZ_HAVE_PQCLEAN_REFERENCE.
const pqcfuzz_kem_adapter *pqcfuzz_get_pqclean_reference_kem_adapter(const char *implementation_id);
const pqcfuzz_sig_adapter *pqcfuzz_get_pqclean_reference_sig_adapter(const char *implementation_id);
const char *pqcfuzz_pqclean_reference_version();

}  // namespace pqcfuzz

#endif

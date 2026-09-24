#ifndef PQCFUZZ_ADAPTERS_NTRU_KEM_ADAPTER_H
#define PQCFUZZ_ADAPTERS_NTRU_KEM_ADAPTER_H

#include "adapters/adapter_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

// Returns the NTRU adapter pinned to the implementation_id encoded in the pair
// file, or nullptr when the build does not define PQCFUZZ_HAVE_NTRU.
const pqcfuzz_kem_adapter *pqcfuzz_get_ntru_kem_adapter(const char *implementation_id);

#ifdef __cplusplus
}
#endif

#endif

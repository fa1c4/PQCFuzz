#ifndef PQCFUZZ_ADAPTERS_FALCON_SIG_ADAPTER_H
#define PQCFUZZ_ADAPTERS_FALCON_SIG_ADAPTER_H

#include "adapters/adapter_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

// Returns the Falcon adapter pinned to the implementation_id encoded in the
// pair file (one per parameter set and signature format), or nullptr.
const pqcfuzz_sig_adapter *pqcfuzz_get_falcon_sig_adapter(const char *implementation_id);

#ifdef __cplusplus
}
#endif

#endif

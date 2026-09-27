#ifndef PQCFUZZ_ADAPTERS_SIDH_KEX_ADAPTER_H
#define PQCFUZZ_ADAPTERS_SIDH_KEX_ADAPTER_H

#include "adapters/kex_adapter_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

// Returns the SIDH KEX adapter pinned to the implementation_id encoded in the
// pair file, or nullptr when the build does not define PQCFUZZ_HAVE_SIDH.
const pqcfuzz_kex_adapter *pqcfuzz_get_sidh_kex_adapter(const char *implementation_id);

#ifdef __cplusplus
}
#endif

#endif

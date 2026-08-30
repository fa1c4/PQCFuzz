#ifndef PQCFUZZ_ADAPTERS_PQMAGIC_KEM_ADAPTER_H
#define PQCFUZZ_ADAPTERS_PQMAGIC_KEM_ADAPTER_H

#include "adapters/adapter_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

const pqcfuzz_kem_adapter *pqcfuzz_get_pqmagic_adapter(const char *implementation_id);

#ifdef __cplusplus
}
#endif

#endif

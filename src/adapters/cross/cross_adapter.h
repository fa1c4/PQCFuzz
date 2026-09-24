#ifndef PQCFUZZ_ADAPTERS_CROSS_ADAPTER_H
#define PQCFUZZ_ADAPTERS_CROSS_ADAPTER_H

#include "adapters/adapter_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

// Returns the adapter for the pinned CROSS reference implementation.  The
// translation unit is compiled once per parameter set with
// PQCFUZZ_CROSS_ALGORITHM and the CROSS profile defines; builds without
// PQCFUZZ_HAVE_CROSS return nullptr so routing fails visibly instead of
// pretending a target exists.
const pqcfuzz_sig_adapter *pqcfuzz_get_cross_sig_adapter(const char *implementation_id);

// Deterministic platform CSPRNG seeding shared by the seeded hooks and the
// CROSS test hooks.  Returns 0 on success.
int pqcfuzz_cross_seed_platform_rng(const uint8_t *seed, size_t seed_len);

#ifdef __cplusplus
}
#endif

#endif

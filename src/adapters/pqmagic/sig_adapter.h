#ifndef PQCFUZZ_ADAPTERS_PQMAGIC_SIG_ADAPTER_H
#define PQCFUZZ_ADAPTERS_PQMAGIC_SIG_ADAPTER_H

#include <cstddef>
#include <cstdint>

#include "adapters/adapter_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

const pqcfuzz_sig_adapter *pqcfuzz_get_pqmagic_sig_adapter(const char *implementation_id);
// Direct binding to PQMagic's combined crypto_sign (sig || msg) wrapper.
// Used by the aigissig_ctx256_failure_state oracle to observe the documented
// *smlen += mlen side effect on failure.  Returns the raw crypto_sign rc.
int pqcfuzz_pqmagic_sig_combined_sign(
    const char *implementation_id,
    uint8_t *sm,
    size_t *smlen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *ctx,
    size_t ctx_len,
    const uint8_t *sk);

#ifdef __cplusplus
}
#endif

#endif

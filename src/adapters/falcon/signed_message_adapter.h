#ifndef PQCFUZZ_ADAPTERS_FALCON_SIGNED_MESSAGE_ADAPTER_H
#define PQCFUZZ_ADAPTERS_FALCON_SIGNED_MESSAGE_ADAPTER_H

#include <cstddef>
#include <cstdint>

#include "adapters/status.h"

namespace pqcfuzz {
namespace falcon_internal {

// NIST signed-message (attached) frame from the Falcon specification
// section 3.11.6:
//   BE16(1 + len(comp)) || salt[40] || message || 0x29/0x2A || comp
// The top-level functions are format-agnostic wrappers around the official
// reference falcon_sign_dyn/falcon_verify entry points.
pqcfuzz_status SignAttached(
    unsigned logn,
    uint8_t *signed_message,
    size_t *signed_message_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *secret_key);
pqcfuzz_status SignAttachedSeeded(
    unsigned logn,
    const uint8_t *seed,
    size_t seed_len,
    uint8_t *signed_message,
    size_t *signed_message_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *secret_key);
pqcfuzz_status OpenAttached(
    unsigned logn,
    uint8_t *message,
    size_t *message_len,
    const uint8_t *signed_message,
    size_t signed_message_len,
    const uint8_t *public_key);

}  // namespace falcon_internal
}  // namespace pqcfuzz

#endif

#ifndef PQCFUZZ_ADAPTERS_CROSS_TEST_HOOKS_H
#define PQCFUZZ_ADAPTERS_CROSS_TEST_HOOKS_H

#include <cstddef>
#include <cstdint>

// Test-only probes around the pinned CROSS reference codec and challenge
// sampler.  They are linked into test binaries only and never change the
// behaviour of the adapter entry points.
#ifdef PQCFUZZ_HAVE_CROSS

namespace pqcfuzz {

size_t CrossHookPackY(uint8_t *out, size_t out_len, const uint16_t *coeffs, size_t count);
int CrossHookUnpackY(uint16_t *out, size_t count, const uint8_t *in, size_t in_len);
size_t CrossHookPackV(uint8_t *out, size_t out_len, const uint16_t *coeffs, size_t count);
int CrossHookUnpackV(uint16_t *out, size_t count, const uint8_t *in, size_t in_len);
size_t CrossHookPackSyndrome(uint8_t *out, size_t out_len, const uint16_t *coeffs, size_t count);
int CrossHookUnpackSyndrome(uint16_t *out, size_t count, const uint8_t *in, size_t in_len);

// Writes T bytes (0/1) sampled from the digest with the reference
// expand_digest_to_fixed_weight.
size_t CrossHookExpandFixedWeight(uint8_t *out, size_t out_len, const uint8_t *digest, size_t digest_len);

size_t CrossHookYBytes();
size_t CrossHookVBytes();
size_t CrossHookSynBytes();
size_t CrossHookTreeNodesToStore();
size_t CrossHookT();
size_t CrossHookW();

}  // namespace pqcfuzz

#endif  // PQCFUZZ_HAVE_CROSS

#endif

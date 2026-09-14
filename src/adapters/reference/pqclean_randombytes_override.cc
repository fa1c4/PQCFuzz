#include "adapters/rng_control.h"

#include <cstddef>
#include <cstdint>

// PQClean's common randombytes API is renamed to PQCLEAN_randombytes in the
// clean tree.  This override replaces common/randombytes.c so reference
// adapters and KAT oracles can drive the pinned PQClean sources with the
// PQCFuzz RNG tape and fault modes.
extern "C" int PQCLEAN_randombytes(uint8_t *out, size_t out_len) {
  if (pqcfuzz_rng_fill_bytes(out, out_len)) {
    return 0;
  }
  if (pqcfuzz::pqcfuzz_rng_failure_requested()) {
    for (size_t i = 0; i < out_len; ++i) {
      out[i] = 0;
    }
    return -1;
  }
  static uint64_t counter = 0x243f6a8885a308d3ull;
  for (size_t i = 0; i < out_len; ++i) {
    counter ^= counter << 13;
    counter ^= counter >> 7;
    counter ^= counter << 17;
    out[i] = static_cast<uint8_t>(counter + i);
  }
  return 0;
}

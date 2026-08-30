#include "adapters/rng_control.h"

#include <cstddef>
#include <cstdint>

// PQMagic's utils/randombytes.c defines `randombytes` as a strong symbol in
// its own archive member.  Because this translation unit defines the symbol,
// the archive member is never pulled in, so there is no duplicate-symbol
// conflict.  Calls inside PQMagic resolve to this definition instead.
extern "C" void randombytes(uint8_t *out, size_t out_len) {
  if (pqcfuzz_rng_fill_bytes(out, out_len)) {
    return;
  }
  static uint64_t counter = 0x9e3779b97f4a7c15ull;
  for (size_t i = 0; i < out_len; ++i) {
    counter ^= counter << 7;
    counter ^= counter >> 9;
    out[i] = static_cast<uint8_t>(counter + i);
  }
}

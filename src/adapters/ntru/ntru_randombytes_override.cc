#include "adapters/rng_control.h"

#include <cstddef>
#include <cstdint>

// NIST-style randombytes override used by the pinned NTRU reference when it is
// driven from the oracle executor.  The prototype matches the vendored
// params/rng contract (int randombytes(unsigned char*, unsigned long long)).
extern "C" int randombytes(unsigned char *out, unsigned long long out_len) {
  if (pqcfuzz_rng_fill_bytes(out, static_cast<size_t>(out_len))) {
    return 0;
  }
  if (pqcfuzz::pqcfuzz_rng_failure_requested()) {
    for (unsigned long long i = 0; i < out_len; ++i) {
      out[i] = 0;
    }
    return -1;
  }
  static uint64_t counter = 0x243f6a8885a308d3ull;
  for (unsigned long long i = 0; i < out_len; ++i) {
    counter ^= counter << 13;
    counter ^= counter >> 7;
    counter ^= counter << 17;
    out[i] = static_cast<uint8_t>(counter + i);
  }
  return 0;
}

#include "adapters/rng_control.h"

#include <cstddef>
#include <cstdint>

extern "C" void OQS_randombytes_custom_algorithm(void (*algorithm_ptr)(uint8_t *, size_t))
    __attribute__((weak));

namespace {

void PqcfuzzLiboqsRandombytes(uint8_t *out, size_t out_len) {
  if (pqcfuzz_rng_fill_bytes(out, out_len)) {
    return;
  }
  for (size_t i = 0; i < out_len; ++i) {
    out[i] = static_cast<uint8_t>(0xa5u + (i * 31u));
  }
}

}  // namespace

namespace pqcfuzz {

void pqcfuzz_install_liboqs_rng_hook() {
  if (OQS_randombytes_custom_algorithm != nullptr) {
    OQS_randombytes_custom_algorithm(PqcfuzzLiboqsRandombytes);
  }
}

}  // namespace pqcfuzz

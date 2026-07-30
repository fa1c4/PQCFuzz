#include "adapters/rng_control.h"

#include <cstddef>
#include <cstdint>
#include <random>

extern "C" void OQS_randombytes_custom_algorithm(void (*algorithm_ptr)(uint8_t *, size_t))
    __attribute__((weak));
extern "C" void OQS_randombytes_system(uint8_t *random_array, size_t bytes_to_read)
    __attribute__((weak));

namespace {

void PqcfuzzLiboqsRandombytes(uint8_t *out, size_t out_len) {
  if (pqcfuzz_rng_fill_bytes(out, out_len)) {
    return;
  }
  if (OQS_randombytes_system != nullptr) {
    OQS_randombytes_system(out, out_len);
    return;
  }
  std::random_device random;
  for (size_t i = 0; i < out_len; ++i) {
    out[i] = static_cast<uint8_t>(random());
  }
}

}  // namespace

namespace pqcfuzz {

void pqcfuzz_install_liboqs_rng_hook() {
  if (OQS_randombytes_custom_algorithm != nullptr) {
    OQS_randombytes_custom_algorithm(PqcfuzzLiboqsRandombytes);
  }
}

void pqcfuzz_restore_liboqs_rng_hook() {
  if (OQS_randombytes_custom_algorithm != nullptr) {
    OQS_randombytes_custom_algorithm(OQS_randombytes_system);
  }
}

}  // namespace pqcfuzz

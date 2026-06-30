#ifndef PQCFUZZ_ADAPTERS_RNG_CONTROL_H
#define PQCFUZZ_ADAPTERS_RNG_CONTROL_H

#include <cstddef>
#include <cstdint>

#include "adapters/status.h"

namespace pqcfuzz {

struct RngTape {
  const uint8_t *data = nullptr;
  size_t size = 0;
  bool repeat = true;
};

pqcfuzz_status pqcfuzz_rng_push_tape(const RngTape &tape);
void pqcfuzz_rng_pop_tape();
bool pqcfuzz_rng_is_active();
void pqcfuzz_install_liboqs_rng_hook();

class ScopedRngOverride {
 public:
  explicit ScopedRngOverride(const RngTape &tape);
  ~ScopedRngOverride();
  bool active() const;

 private:
  bool active_ = false;
};

}  // namespace pqcfuzz

extern "C" int pqcfuzz_rng_fill_bytes(uint8_t *out, size_t out_len);

#endif

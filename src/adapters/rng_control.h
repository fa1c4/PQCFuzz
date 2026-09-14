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
  enum class Mode {
    kOk = 0,
    kReportedFailure,
    kShortRead,
    kInterrupted,
    kRepeatedBlock,
    kAllZero,
  } mode = Mode::kOk;
};

pqcfuzz_status pqcfuzz_rng_push_tape(const RngTape &tape);
void pqcfuzz_rng_pop_tape();
bool pqcfuzz_rng_is_active();
// Number of bytes read from the innermost active tape.  This is intentionally
// observable so an RNG metamorphic oracle can prove that its intervention
// reached the adapter without exposing the tape itself.
size_t pqcfuzz_rng_bytes_consumed();
// True when the innermost active tape requests a failure mode.  Void RNG APIs
// cannot report a failure status, so callers use this to suppress fallback
// entropy and record the observation instead.
bool pqcfuzz_rng_failure_requested();
// True once a failure-mode tape has been consumed.
bool pqcfuzz_rng_failure_observed();
void pqcfuzz_rng_reset_failure_observed();
void pqcfuzz_install_liboqs_rng_hook();
void pqcfuzz_restore_liboqs_rng_hook();

class ScopedRngOverride {
 public:
  explicit ScopedRngOverride(const RngTape &tape);
  ~ScopedRngOverride();
  bool active() const;
  size_t bytes_consumed() const;

 private:
  bool active_ = false;
};

}  // namespace pqcfuzz

extern "C" int pqcfuzz_rng_fill_bytes(uint8_t *out, size_t out_len);

#endif

#include "adapters/rng_control.h"

#include <algorithm>
#include <vector>

namespace pqcfuzz {
namespace {

struct TapeState {
  std::vector<uint8_t> data;
  size_t offset = 0;
  bool repeat = true;
};

thread_local std::vector<TapeState> g_tapes;

bool FillFromActiveTape(uint8_t *out, size_t out_len) {
  if (out == nullptr || g_tapes.empty()) {
    return false;
  }
  TapeState &tape = g_tapes.back();
  if (tape.data.empty()) {
    std::fill(out, out + out_len, 0);
    return true;
  }
  for (size_t i = 0; i < out_len; ++i) {
    if (tape.offset >= tape.data.size()) {
      if (tape.repeat) {
        tape.offset = 0;
      } else {
        out[i] = 0;
        continue;
      }
    }
    out[i] = tape.data[tape.offset++];
  }
  return true;
}

}  // namespace

pqcfuzz_status pqcfuzz_rng_push_tape(const RngTape &tape) {
  if (tape.data == nullptr || tape.size == 0) {
    return PQCFUZZ_INVALID_INPUT;
  }
  TapeState state;
  state.data.assign(tape.data, tape.data + tape.size);
  state.repeat = tape.repeat;
  g_tapes.push_back(std::move(state));
  pqcfuzz_install_liboqs_rng_hook();
  return PQCFUZZ_OK;
}

void pqcfuzz_rng_pop_tape() {
  if (!g_tapes.empty()) {
    g_tapes.pop_back();
  }
}

bool pqcfuzz_rng_is_active() {
  return !g_tapes.empty();
}

ScopedRngOverride::ScopedRngOverride(const RngTape &tape) {
  active_ = pqcfuzz_rng_push_tape(tape) == PQCFUZZ_OK;
}

ScopedRngOverride::~ScopedRngOverride() {
  if (active_) {
    pqcfuzz_rng_pop_tape();
  }
}

bool ScopedRngOverride::active() const {
  return active_;
}

}  // namespace pqcfuzz

extern "C" int pqcfuzz_rng_fill_bytes(uint8_t *out, size_t out_len) {
  return pqcfuzz::FillFromActiveTape(out, out_len) ? 1 : 0;
}

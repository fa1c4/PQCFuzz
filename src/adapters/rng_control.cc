#include "adapters/rng_control.h"

#include <algorithm>
#include <mutex>
#include <vector>

namespace pqcfuzz {
namespace {

struct TapeState {
  std::vector<uint8_t> data;
  size_t offset = 0;
  bool repeat = true;
  RngTape::Mode mode = RngTape::Mode::kOk;
};

thread_local std::vector<TapeState> g_tapes;
std::mutex g_hook_mutex;
size_t g_process_scope_depth = 0;
bool g_failure_observed = false;

uint8_t DerivedByte(const TapeState &tape, size_t offset) {
  uint64_t hash = 1469598103934665603ull ^ static_cast<uint64_t>(offset);
  for (uint8_t byte : tape.data) {
    hash ^= byte;
    hash *= 1099511628211ull;
  }
  hash ^= static_cast<uint64_t>(offset >> 8);
  hash *= 1099511628211ull;
  hash ^= static_cast<uint64_t>(offset << 17);
  return static_cast<uint8_t>((hash >> ((offset % 8u) * 8u)) & 0xffu);
}

bool FillFromActiveTape(uint8_t *out, size_t out_len) {
  if (out == nullptr || g_tapes.empty()) {
    return false;
  }
  TapeState &tape = g_tapes.back();
  switch (tape.mode) {
    case RngTape::Mode::kAllZero:
      std::fill(out, out + out_len, 0);
      return true;
    case RngTape::Mode::kReportedFailure:
      std::fill(out, out + out_len, 0);
      g_failure_observed = true;
      return false;
    case RngTape::Mode::kInterrupted:
      g_failure_observed = true;
      return false;
    case RngTape::Mode::kShortRead: {
      const size_t delivered = out_len / 2;
      for (size_t i = 0; i < delivered; ++i) {
        out[i] = tape.data.empty() ? 0 : tape.data[i % tape.data.size()];
      }
      std::fill(out + delivered, out + out_len, 0);
      g_failure_observed = true;
      return true;
    }
    case RngTape::Mode::kRepeatedBlock: {
      if (tape.data.empty()) {
        std::fill(out, out + out_len, 0);
        return true;
      }
      for (size_t i = 0; i < out_len; ++i) {
        out[i] = tape.data[i % tape.data.size()];
      }
      return true;
    }
    case RngTape::Mode::kOk:
      break;
  }
  if (tape.data.empty()) {
    std::fill(out, out + out_len, 0);
    return true;
  }
  for (size_t i = 0; i < out_len; ++i) {
    if (tape.offset >= tape.data.size()) {
      if (tape.repeat) {
        tape.offset = 0;
      } else {
        out[i] = DerivedByte(tape, tape.offset++);
        continue;
      }
    }
    out[i] = tape.data[tape.offset++];
  }
  return true;
}

}  // namespace

pqcfuzz_status pqcfuzz_rng_push_tape(const RngTape &tape) {
  if (tape.data == nullptr || (tape.size == 0 && tape.mode == RngTape::Mode::kOk)) {
    return PQCFUZZ_INVALID_INPUT;
  }
  TapeState state;
  state.data.assign(tape.data, tape.data + tape.size);
  state.repeat = tape.repeat;
  state.mode = tape.mode;
  {
    std::lock_guard<std::mutex> lock(g_hook_mutex);
    if (g_process_scope_depth == 0) {
      pqcfuzz_install_liboqs_rng_hook();
    }
    ++g_process_scope_depth;
    g_tapes.push_back(std::move(state));
  }
  return PQCFUZZ_OK;
}

void pqcfuzz_rng_pop_tape() {
  std::lock_guard<std::mutex> lock(g_hook_mutex);
  if (g_tapes.empty()) {
    return;
  }
  g_tapes.pop_back();
  if (g_process_scope_depth > 0) {
    --g_process_scope_depth;
  }
  if (g_process_scope_depth == 0) {
    pqcfuzz_restore_liboqs_rng_hook();
  }
}

bool pqcfuzz_rng_is_active() {
  return !g_tapes.empty();
}

size_t pqcfuzz_rng_bytes_consumed() {
  return g_tapes.empty() ? 0 : g_tapes.back().offset;
}

bool pqcfuzz_rng_failure_requested() {
  if (g_tapes.empty()) {
    return false;
  }
  const RngTape::Mode mode = g_tapes.back().mode;
  return mode == RngTape::Mode::kReportedFailure || mode == RngTape::Mode::kInterrupted ||
         mode == RngTape::Mode::kShortRead;
}

bool pqcfuzz_rng_failure_observed() {
  return g_failure_observed;
}

void pqcfuzz_rng_reset_failure_observed() {
  g_failure_observed = false;
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

size_t ScopedRngOverride::bytes_consumed() const {
  return active_ ? pqcfuzz_rng_bytes_consumed() : 0;
}

}  // namespace pqcfuzz

extern "C" int pqcfuzz_rng_fill_bytes(uint8_t *out, size_t out_len) {
  return pqcfuzz::FillFromActiveTape(out, out_len) ? 1 : 0;
}

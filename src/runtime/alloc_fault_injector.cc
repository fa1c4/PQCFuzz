#include "runtime/alloc_fault_injector.h"

#include <cstdlib>
#include <cstring>

extern "C" void *__real_malloc(size_t size);
extern "C" void *__real_calloc(size_t count, size_t size);
extern "C" void *__real_realloc(void *pointer, size_t size);

namespace {

struct AllocFaultState {
  size_t fail_at = 0;
  size_t fail_count = 1;
  size_t calls = 0;
  size_t failures = 0;
  bool configured = false;
  bool armed = false;
};

AllocFaultState &State() {
  static AllocFaultState state;
  return state;
}

void ConfigureFromEnvironment() {
  AllocFaultState &state = State();
  state.fail_at = 0;
  state.fail_count = 1;
  const char *fail_at = std::getenv("PQCFUZZ_ALLOC_FAIL_AT");
  const char *fail_count = std::getenv("PQCFUZZ_ALLOC_FAIL_COUNT");
  if (fail_at != nullptr) {
    state.fail_at = static_cast<size_t>(std::strtoull(fail_at, nullptr, 10));
  }
  if (fail_count != nullptr) {
    const unsigned long long parsed = std::strtoull(fail_count, nullptr, 10);
    state.fail_count = parsed == 0 ? 1 : static_cast<size_t>(parsed);
  }
  state.configured = true;
}

bool ShouldFail() {
  AllocFaultState &state = State();
  if (!state.armed) {
    return false;
  }
  ++state.calls;
  if (state.fail_at == 0 || state.calls < state.fail_at) {
    return false;
  }
  if (state.calls >= state.fail_at + state.fail_count) {
    return false;
  }
  ++state.failures;
  return true;
}

}  // namespace

extern "C" void pqcfuzz_alloc_fault_reset(void) {
  AllocFaultState &state = State();
  ConfigureFromEnvironment();
  state.calls = 0;
  state.failures = 0;
  state.armed = true;
}

extern "C" void pqcfuzz_alloc_fault_disarm(void) {
  State().armed = false;
}

extern "C" void pqcfuzz_alloc_fault_configure(size_t fail_at, size_t fail_count) {
  AllocFaultState &state = State();
  state.fail_at = fail_at;
  state.fail_count = fail_count == 0 ? 1 : fail_count;
  state.calls = 0;
  state.failures = 0;
  state.configured = true;
  state.armed = true;
}

extern "C" size_t pqcfuzz_alloc_fault_calls(void) {
  return State().calls;
}

extern "C" size_t pqcfuzz_alloc_fault_failures(void) {
  return State().failures;
}

extern "C" int pqcfuzz_alloc_fault_active(void) {
  AllocFaultState &state = State();
  return state.armed && state.fail_at != 0 ? 1 : 0;
}

extern "C" void *__wrap_malloc(size_t size) {
  if (ShouldFail()) {
    return nullptr;
  }
  return __real_malloc(size);
}

extern "C" void *__wrap_calloc(size_t count, size_t size) {
  if (ShouldFail()) {
    return nullptr;
  }
  return __real_calloc(count, size);
}

extern "C" void *__wrap_realloc(void *pointer, size_t size) {
  if (ShouldFail()) {
    return nullptr;
  }
  return __real_realloc(pointer, size);
}

#pragma once

#include <cstddef>
#include <cstdint>

namespace cryptofuzz {
namespace liboqs_replay {

struct InputView {
    const uint8_t *data = nullptr;
    size_t size = 0;
};

/* The fuzzer driver keeps the complete, original libFuzzer byte sequence in
 * thread-local storage while dispatching an operation.  A module can snapshot
 * it when it emits a semantic finding without relying on process-global
 * environment variables or reconstructed operation JSON. */
inline thread_local InputView currentInput;

class ScopedInput {
    private:
        InputView previous;

    public:
        ScopedInput(const uint8_t *data, size_t size) :
            previous(currentInput) {
            currentInput = {data, size};
        }

        ~ScopedInput() {
            currentInput = previous;
        }

        ScopedInput(const ScopedInput&) = delete;
        ScopedInput& operator=(const ScopedInput&) = delete;
};

inline InputView CurrentInput() {
    return currentInput;
}

} /* namespace liboqs_replay */
} /* namespace cryptofuzz */

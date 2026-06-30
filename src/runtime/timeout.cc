#include "runtime/timeout.h"

namespace pqcfuzz {

Deadline::Deadline(int timeout_seconds)
    : timeout_seconds_(timeout_seconds),
      deadline_(std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds)) {}

bool Deadline::Expired() const {
  return std::chrono::steady_clock::now() >= deadline_;
}

int Deadline::timeout_seconds() const {
  return timeout_seconds_;
}

}  // namespace pqcfuzz

#ifndef PQCFUZZ_RUNTIME_TIMEOUT_H
#define PQCFUZZ_RUNTIME_TIMEOUT_H

#include <chrono>

namespace pqcfuzz {

class Deadline {
 public:
  explicit Deadline(int timeout_seconds);
  bool Expired() const;
  int timeout_seconds() const;

 private:
  int timeout_seconds_ = 0;
  std::chrono::steady_clock::time_point deadline_;
};

}  // namespace pqcfuzz

#endif

#ifndef PQCFUZZ_RUNTIME_ISOLATED_WORKER_H
#define PQCFUZZ_RUNTIME_ISOLATED_WORKER_H

#include <functional>

namespace pqcfuzz {

struct WorkerResult {
  int exit_code = 0;
  bool timed_out = false;
  bool crashed = false;
  int signal = 0;
};

WorkerResult RunIsolatedWorker(const std::function<int()> &worker, int timeout_seconds);

}  // namespace pqcfuzz

#endif

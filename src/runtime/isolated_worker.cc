#include "runtime/isolated_worker.h"

#include "runtime/exit_codes.h"

#if defined(__unix__)
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace pqcfuzz {

WorkerResult RunIsolatedWorker(const std::function<int()> &worker, int timeout_seconds) {
  WorkerResult result;
#if defined(__unix__)
  pid_t pid = fork();
  if (pid == 0) {
    _exit(worker());
  }
  if (pid < 0) {
    result.exit_code = kExitInvalidInputOrConfig;
    result.crashed = true;
    return result;
  }

  int waited = 0;
  int status = 0;
  while (true) {
    pid_t done = waitpid(pid, &status, WNOHANG);
    if (done == pid) {
      break;
    }
    if (done < 0) {
      result.exit_code = kExitNativeCrash;
      result.crashed = true;
      return result;
    }
    if (waited >= timeout_seconds) {
      kill(pid, SIGKILL);
      waitpid(pid, &status, 0);
      result.exit_code = kExitHang;
      result.timed_out = true;
      return result;
    }
    sleep(1);
    ++waited;
  }
  if (WIFSIGNALED(status)) {
    result.exit_code = kExitNativeCrash;
    result.crashed = true;
    result.signal = WTERMSIG(status);
  } else {
    result.exit_code = WEXITSTATUS(status);
  }
  return result;
#else
  (void)timeout_seconds;
  result.exit_code = worker();
  return result;
#endif
}

}  // namespace pqcfuzz

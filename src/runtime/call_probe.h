#ifndef PQCFUZZ_RUNTIME_CALL_PROBE_H
#define PQCFUZZ_RUNTIME_CALL_PROBE_H

#include <string>

namespace pqcfuzz {

struct CallProbeSnapshot {
  bool executor_dispatched = false;
  bool adapter_entered = false;
  bool target_entered = false;
  bool target_returned = false;
  std::string rejection_layer;
};

class CallProbeScope {
 public:
  CallProbeScope();
  ~CallProbeScope();
  CallProbeSnapshot snapshot() const;

 private:
  CallProbeSnapshot previous_;
};

void MarkExecutorDispatched();
void MarkAdapterEntered();
void MarkTargetEntered();
void MarkTargetReturned();
void MarkRejectionLayer(const std::string &layer);
CallProbeSnapshot CurrentCallProbeSnapshot();

}  // namespace pqcfuzz

#endif

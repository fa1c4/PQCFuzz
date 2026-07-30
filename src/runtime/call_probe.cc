#include "runtime/call_probe.h"

namespace pqcfuzz {
namespace {

thread_local CallProbeSnapshot g_snapshot;

}  // namespace

CallProbeScope::CallProbeScope() : previous_(g_snapshot) {
  g_snapshot = {};
}

CallProbeScope::~CallProbeScope() {
  g_snapshot = previous_;
}

CallProbeSnapshot CallProbeScope::snapshot() const {
  return g_snapshot;
}

void MarkExecutorDispatched() {
  g_snapshot.executor_dispatched = true;
}

void MarkAdapterEntered() {
  g_snapshot.adapter_entered = true;
}

void MarkTargetEntered() {
  g_snapshot.target_entered = true;
}

void MarkTargetReturned() {
  g_snapshot.target_returned = true;
}

void MarkRejectionLayer(const std::string &layer) {
  g_snapshot.rejection_layer = layer;
}

CallProbeSnapshot CurrentCallProbeSnapshot() {
  return g_snapshot;
}

}  // namespace pqcfuzz

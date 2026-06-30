#ifndef PQCFUZZ_ORACLES_METAMORPHIC_OBSERVATION_H
#define PQCFUZZ_ORACLES_METAMORPHIC_OBSERVATION_H

#include <cstdint>
#include <string>
#include <vector>

#include "adapters/status.h"
#include "oracles/oracle_executor.h"

namespace pqcfuzz {

struct Observation {
  pqcfuzz_status status = PQCFUZZ_INVALID_INPUT;
  std::vector<uint8_t> bytes;
  bool has_bool = false;
  bool bool_value = false;
  bool crashed = false;
  bool timed_out = false;
  bool unsupported = false;
};

enum class ObservedRelation {
  kObservedEqual,
  kObservedDifferent,
  kObservedCrash,
  kObservedHang,
  kObservedUnsupported,
};

ObservedRelation CompareObservations(const Observation &a, const Observation &b);
const char *ObservedRelationName(ObservedRelation relation);
std::string Sha256Hex(const std::vector<uint8_t> &bytes);
ObservationTrace ToObservationTrace(const Observation &observation);

}  // namespace pqcfuzz

#endif

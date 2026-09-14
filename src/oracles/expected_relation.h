#ifndef PQCFUZZ_ORACLES_EXPECTED_RELATION_H
#define PQCFUZZ_ORACLES_EXPECTED_RELATION_H

#include <string>

namespace pqcfuzz {

enum class ExpectedRelation {
  kSameSharedSecret,
  kDifferentSharedSecret,
  kNoCrash,
  kNoTimeout,
  kNoOutputOnAllocationFailure,
  kRejectOrDifferentSharedSecret,
  kVerifyTrue,
  kVerifyFalse,
  kDecodeReject,
  kVerifyFalseOrDecodeRejectOrApiInvalidInput,
  kVerifyFalseOrApiUnsupported,
  kRejectOrInvalidInput,
  kRejectWithConsistentOutputLengthState,
  kExpectEqual,
  kExpectDifferent,
  kUnknown,
};

const char *ExpectedRelationName(ExpectedRelation relation);
ExpectedRelation ExpectedRelationFromName(const std::string &name);

}  // namespace pqcfuzz

#endif

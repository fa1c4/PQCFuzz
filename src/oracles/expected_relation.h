#ifndef PQCFUZZ_ORACLES_EXPECTED_RELATION_H
#define PQCFUZZ_ORACLES_EXPECTED_RELATION_H

#include <string>

namespace pqcfuzz {

enum class ExpectedRelation {
  kSameSharedSecret,
  kDifferentSharedSecret,
  kNoCrash,
  kNoTimeout,
  kRejectOrDifferentSharedSecret,
  kVerifyTrue,
  kVerifyFalse,
  kDecodeReject,
  kVerifyFalseOrDecodeRejectOrApiInvalidInput,
  kVerifyFalseOrApiUnsupported,
  kExpectEqual,
  kExpectDifferent,
  kUnknown,
};

const char *ExpectedRelationName(ExpectedRelation relation);
ExpectedRelation ExpectedRelationFromName(const std::string &name);

}  // namespace pqcfuzz

#endif

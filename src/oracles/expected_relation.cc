#include "oracles/expected_relation.h"

namespace pqcfuzz {

const char *ExpectedRelationName(ExpectedRelation relation) {
  switch (relation) {
    case ExpectedRelation::kSameSharedSecret:
      return "SAME_SHARED_SECRET";
    case ExpectedRelation::kDifferentSharedSecret:
      return "DIFFERENT_SHARED_SECRET";
    case ExpectedRelation::kNoCrash:
      return "NO_CRASH";
    case ExpectedRelation::kNoTimeout:
      return "NO_TIMEOUT";
    case ExpectedRelation::kRejectOrDifferentSharedSecret:
      return "REJECT_OR_DIFFERENT_SHARED_SECRET";
    case ExpectedRelation::kVerifyTrue:
      return "VERIFY_TRUE";
    case ExpectedRelation::kVerifyFalse:
      return "VERIFY_FALSE";
    case ExpectedRelation::kDecodeReject:
      return "DECODE_REJECT";
    case ExpectedRelation::kVerifyFalseOrDecodeRejectOrApiInvalidInput:
      return "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT";
    case ExpectedRelation::kVerifyFalseOrApiUnsupported:
      return "VERIFY_FALSE_OR_API_UNSUPPORTED";
    case ExpectedRelation::kExpectEqual:
      return "EXPECT_EQUAL";
    case ExpectedRelation::kExpectDifferent:
      return "EXPECT_DIFFERENT";
    case ExpectedRelation::kUnknown:
      return "UNKNOWN";
  }
  return "UNKNOWN";
}

ExpectedRelation ExpectedRelationFromName(const std::string &name) {
  if (name == "SAME_SHARED_SECRET") {
    return ExpectedRelation::kSameSharedSecret;
  }
  if (name == "DIFFERENT_SHARED_SECRET") {
    return ExpectedRelation::kDifferentSharedSecret;
  }
  if (name == "NO_CRASH") {
    return ExpectedRelation::kNoCrash;
  }
  if (name == "NO_TIMEOUT") {
    return ExpectedRelation::kNoTimeout;
  }
  if (name == "REJECT_OR_DIFFERENT_SHARED_SECRET") {
    return ExpectedRelation::kRejectOrDifferentSharedSecret;
  }
  if (name == "VERIFY_TRUE") {
    return ExpectedRelation::kVerifyTrue;
  }
  if (name == "VERIFY_FALSE") {
    return ExpectedRelation::kVerifyFalse;
  }
  if (name == "DECODE_REJECT") {
    return ExpectedRelation::kDecodeReject;
  }
  if (name == "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT") {
    return ExpectedRelation::kVerifyFalseOrDecodeRejectOrApiInvalidInput;
  }
  if (name == "VERIFY_FALSE_OR_API_UNSUPPORTED") {
    return ExpectedRelation::kVerifyFalseOrApiUnsupported;
  }
  if (name == "EXPECT_EQUAL") {
    return ExpectedRelation::kExpectEqual;
  }
  if (name == "EXPECT_DIFFERENT") {
    return ExpectedRelation::kExpectDifferent;
  }
  return ExpectedRelation::kUnknown;
}

}  // namespace pqcfuzz

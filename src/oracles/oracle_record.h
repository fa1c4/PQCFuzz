#ifndef PQCFUZZ_ORACLES_ORACLE_RECORD_H
#define PQCFUZZ_ORACLES_ORACLE_RECORD_H

#include <string>
#include <vector>

namespace pqcfuzz {

// Evidence classes from the test-oracle design document, Section 2.1.
enum class EvidenceClass {
  kNormative,
  kReferenceDerived,
  kImplementationObserved,
  kEngineeringRecommendation,
  kInference,
};

// Verdict vocabulary from the test-oracle design document, Section 4.
enum class Verdict {
  kConformant,
  kNonconformant,
  kHardeningGap,
  kNoCounterexample,
  kInconclusive,
  kNotApplicable,
  kHarnessError,
};

const char *EvidenceClassName(EvidenceClass evidence_class);
const char *VerdictName(Verdict verdict);
bool EvidenceClassFromName(const std::string &name, EvidenceClass *out);
bool VerdictFromName(const std::string &name, Verdict *out);

// Profile-independent oracle metadata bound to an oracle_id.  One primary
// evidence class is used for each claim, per the design document.
struct OracleMetadata {
  std::string claim;
  EvidenceClass evidence_class = EvidenceClass::kInference;
  std::string source_reference;
  std::string scope_api_layer;
  std::vector<std::string> limitations;
  std::string conditional_verdict;
  std::string positive_control;
  std::string negative_control;
};

// A violated claim maps to a verdict using the evidence class:
//   NORMATIVE / REFERENCE_DERIVED  -> NONCONFORMANT
//   ENGINEERING_RECOMMENDATION     -> HARDENING_GAP
//   IMPLEMENTATION_OBSERVED        -> INCONCLUSIVE (needs a stated limitation)
//   INFERENCE                      -> INCONCLUSIVE
Verdict VerdictForViolation(EvidenceClass evidence_class);
bool VerdictIsSecurityProofClaim(Verdict verdict);

struct FindingClassification {
  Verdict verdict = Verdict::kInconclusive;
  EvidenceClass evidence_class = EvidenceClass::kInference;
  std::string conditional_verdict;
  std::string claim;
  std::string source_reference;
  std::vector<std::string> limitations;
};

}  // namespace pqcfuzz

#endif

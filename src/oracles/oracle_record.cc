#include "oracles/oracle_record.h"

namespace pqcfuzz {

const char *EvidenceClassName(EvidenceClass evidence_class) {
  switch (evidence_class) {
    case EvidenceClass::kNormative:
      return "NORMATIVE";
    case EvidenceClass::kReferenceDerived:
      return "REFERENCE_DERIVED";
    case EvidenceClass::kImplementationObserved:
      return "IMPLEMENTATION_OBSERVED";
    case EvidenceClass::kEngineeringRecommendation:
      return "ENGINEERING_RECOMMENDATION";
    case EvidenceClass::kInference:
      return "INFERENCE";
  }
  return "INFERENCE";
}

const char *VerdictName(Verdict verdict) {
  switch (verdict) {
    case Verdict::kConformant:
      return "CONFORMANT";
    case Verdict::kNonconformant:
      return "NONCONFORMANT";
    case Verdict::kHardeningGap:
      return "HARDENING_GAP";
    case Verdict::kNoCounterexample:
      return "NO_COUNTEREXAMPLE";
    case Verdict::kInconclusive:
      return "INCONCLUSIVE";
    case Verdict::kNotApplicable:
      return "NOT_APPLICABLE";
    case Verdict::kHarnessError:
      return "HARNESS_ERROR";
  }
  return "INCONCLUSIVE";
}

bool EvidenceClassFromName(const std::string &name, EvidenceClass *out) {
  if (out == nullptr) {
    return false;
  }
  if (name == "NORMATIVE") {
    *out = EvidenceClass::kNormative;
    return true;
  }
  if (name == "REFERENCE_DERIVED") {
    *out = EvidenceClass::kReferenceDerived;
    return true;
  }
  if (name == "IMPLEMENTATION_OBSERVED") {
    *out = EvidenceClass::kImplementationObserved;
    return true;
  }
  if (name == "ENGINEERING_RECOMMENDATION") {
    *out = EvidenceClass::kEngineeringRecommendation;
    return true;
  }
  if (name == "INFERENCE") {
    *out = EvidenceClass::kInference;
    return true;
  }
  return false;
}

bool VerdictFromName(const std::string &name, Verdict *out) {
  if (out == nullptr) {
    return false;
  }
  if (name == "CONFORMANT") {
    *out = Verdict::kConformant;
    return true;
  }
  if (name == "NONCONFORMANT") {
    *out = Verdict::kNonconformant;
    return true;
  }
  if (name == "HARDENING_GAP") {
    *out = Verdict::kHardeningGap;
    return true;
  }
  if (name == "NO_COUNTEREXAMPLE") {
    *out = Verdict::kNoCounterexample;
    return true;
  }
  if (name == "INCONCLUSIVE") {
    *out = Verdict::kInconclusive;
    return true;
  }
  if (name == "NOT_APPLICABLE") {
    *out = Verdict::kNotApplicable;
    return true;
  }
  if (name == "HARNESS_ERROR") {
    *out = Verdict::kHarnessError;
    return true;
  }
  return false;
}

Verdict VerdictForViolation(EvidenceClass evidence_class) {
  switch (evidence_class) {
    case EvidenceClass::kNormative:
    case EvidenceClass::kReferenceDerived:
      return Verdict::kNonconformant;
    case EvidenceClass::kEngineeringRecommendation:
      return Verdict::kHardeningGap;
    case EvidenceClass::kImplementationObserved:
    case EvidenceClass::kInference:
      return Verdict::kInconclusive;
  }
  return Verdict::kInconclusive;
}

bool VerdictIsSecurityProofClaim(Verdict verdict) {
  // Section 4: CONFORMANT must not be used for computational security
  // properties.  NO_COUNTEREXAMPLE is the only positive security verdict.
  return verdict == Verdict::kConformant;
}

}  // namespace pqcfuzz

#include "oracles/oracle_result.h"

#include "oracles/oracle_executor.h"

namespace pqcfuzz {
namespace {

bool IsSecurityFindingClass(const std::string &finding_class) {
  return !finding_class.empty() && finding_class != "unsupported" && finding_class != "unknown_oracle";
}

bool HasDiagnostic(const KEMOracleTrace &trace) {
  return !trace.diagnostics.empty();
}

bool HasHarnessError(const KEMOracleTrace &trace) {
  for (const auto &diagnostic : trace.diagnostics) {
    if (diagnostic.code == "harness_error") {
      return true;
    }
  }
  return false;
}

}  // namespace

const char *OracleDispositionName(OracleDisposition disposition) {
  switch (disposition) {
    case OracleDisposition::kPass:
      return "pass";
    case OracleDisposition::kDiagnostic:
      return "diagnostic";
    case OracleDisposition::kNotEvaluable:
      return "not_evaluable";
    case OracleDisposition::kRawCandidate:
      return "raw_candidate";
    case OracleDisposition::kSanitizerEvidence:
      return "sanitizer_evidence";
    case OracleDisposition::kHarnessError:
      return "harness_error";
  }
  return "harness_error";
}

const char *EvidenceKindName(EvidenceKind evidence_kind) {
  switch (evidence_kind) {
    case EvidenceKind::kSemantic:
      return "semantic";
    case EvidenceKind::kSanitizer:
      return "sanitizer";
    case EvidenceKind::kProcess:
      return "process";
  }
  return "semantic";
}

bool HasSanitizerEvidence(const KEMOracleTrace &trace) {
  for (const auto &finding : trace.findings) {
    if (finding.evidence_kind == EvidenceKind::kSanitizer && IsSecurityFindingClass(finding.finding_class)) {
      return true;
    }
  }
  return false;
}

bool HasSecurityEvidence(const KEMOracleTrace &trace) {
  for (const auto &finding : trace.findings) {
    if (IsSecurityFindingClass(finding.finding_class) &&
        (finding.evidence_kind == EvidenceKind::kSemantic || finding.evidence_kind == EvidenceKind::kSanitizer ||
         finding.evidence_kind == EvidenceKind::kProcess)) {
      return true;
    }
  }
  return false;
}

OracleDisposition FinalizeDisposition(const KEMOracleTrace &trace) {
  if (HasSanitizerEvidence(trace)) {
    return OracleDisposition::kSanitizerEvidence;
  }
  if (HasHarnessError(trace)) {
    return OracleDisposition::kHarnessError;
  }
  if (!trace.baseline_setup_valid || !trace.mutated_setup_valid || HasDiagnostic(trace)) {
    return OracleDisposition::kDiagnostic;
  }
  if (!trace.intervention_supported) {
    return OracleDisposition::kDiagnostic;
  }
  if (!trace.intervention_effective || !trace.relation_evaluable || !trace.baseline_adapter_entered ||
      !trace.baseline_target_entered || !trace.mutated_adapter_entered || !trace.mutated_target_entered) {
    return OracleDisposition::kNotEvaluable;
  }
  if (HasSecurityEvidence(trace)) {
    return OracleDisposition::kRawCandidate;
  }
  return OracleDisposition::kPass;
}

}  // namespace pqcfuzz

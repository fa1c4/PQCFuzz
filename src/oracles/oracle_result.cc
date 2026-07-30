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
    case OracleDisposition::kProcessEvidence:
      return "process_evidence";
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

bool HasProcessEvidence(const KEMOracleTrace &trace) {
  for (const auto &finding : trace.findings) {
    if (finding.evidence_kind == EvidenceKind::kProcess && IsSecurityFindingClass(finding.finding_class)) {
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
  if (HasHarnessError(trace)) {
    return OracleDisposition::kHarnessError;
  }
  if (HasSanitizerEvidence(trace)) {
    return OracleDisposition::kSanitizerEvidence;
  }
  if (HasProcessEvidence(trace)) {
    return OracleDisposition::kProcessEvidence;
  }
  if (!trace.baseline_setup_valid || !trace.mutated_setup_valid) {
    return OracleDisposition::kNotEvaluable;
  }
  if (HasDiagnostic(trace)) {
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

TraceValidationResult ValidateTraceForPersistence(const KEMOracleTrace &trace) {
  TraceValidationResult result;
  result.disposition = FinalizeDisposition(trace);
  switch (result.disposition) {
    case OracleDisposition::kRawCandidate:
      result.evidence_kind = EvidenceKind::kSemantic;
      result.persistable = false;
      for (const auto &finding : trace.findings) {
        if (finding.evidence_kind == EvidenceKind::kSemantic && IsSecurityFindingClass(finding.finding_class)) {
          result.persistable = true;
          result.reason = "raw_candidate";
          return result;
        }
      }
      result.reason = "missing_semantic_evidence";
      return result;
    case OracleDisposition::kSanitizerEvidence:
      result.evidence_kind = EvidenceKind::kSanitizer;
      result.persistable = HasSanitizerEvidence(trace);
      result.reason = result.persistable ? "sanitizer_evidence" : "missing_sanitizer_evidence";
      return result;
    case OracleDisposition::kProcessEvidence:
      result.evidence_kind = EvidenceKind::kProcess;
      result.persistable = HasProcessEvidence(trace);
      result.reason = result.persistable ? "process_evidence" : "missing_process_evidence";
      return result;
    case OracleDisposition::kHarnessError:
      result.reason = "harness_error";
      return result;
    case OracleDisposition::kPass:
      result.reason = trace.findings.empty() ? "no_security_evidence" : "non_persistable_disposition";
      return result;
    case OracleDisposition::kDiagnostic:
      result.reason = trace.findings.empty() ? "diagnostic" : "non_persistable_disposition";
      return result;
    case OracleDisposition::kNotEvaluable:
      result.reason = trace.findings.empty() ? "not_evaluable" : "non_persistable_disposition";
      return result;
  }
  result.reason = "harness_error";
  return result;
}

bool IsPersistableRawEvidence(const KEMOracleTrace &trace) {
  return ValidateTraceForPersistence(trace).persistable;
}

}  // namespace pqcfuzz

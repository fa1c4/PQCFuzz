#ifndef PQCFUZZ_ORACLES_ORACLE_RESULT_H
#define PQCFUZZ_ORACLES_ORACLE_RESULT_H

namespace pqcfuzz {

struct KEMOracleTrace;

enum class OracleDisposition {
  kPass,
  kDiagnostic,
  kNotEvaluable,
  kRawCandidate,
  kSanitizerEvidence,
  kProcessEvidence,
  kHarnessError,
};

enum class EvidenceKind {
  kSemantic,
  kSanitizer,
  kProcess,
};

const char *OracleDispositionName(OracleDisposition disposition);
const char *EvidenceKindName(EvidenceKind evidence_kind);

struct TraceValidationResult {
  bool persistable = false;
  OracleDisposition disposition = OracleDisposition::kHarnessError;
  EvidenceKind evidence_kind = EvidenceKind::kSemantic;
  const char *reason = "unknown";
};

// These functions are the sole v4 decision point. Callers may record raw
// observations, but must not infer a finding state from relation strings or
// legacy flags.
OracleDisposition FinalizeDisposition(const KEMOracleTrace &trace);
bool HasSecurityEvidence(const KEMOracleTrace &trace);
bool HasSanitizerEvidence(const KEMOracleTrace &trace);
bool HasProcessEvidence(const KEMOracleTrace &trace);
TraceValidationResult ValidateTraceForPersistence(const KEMOracleTrace &trace);
bool IsPersistableRawEvidence(const KEMOracleTrace &trace);

}  // namespace pqcfuzz

#endif

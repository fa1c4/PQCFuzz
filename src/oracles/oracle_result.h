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
  kHarnessError,
};

enum class EvidenceKind {
  kSemantic,
  kSanitizer,
  kProcess,
};

const char *OracleDispositionName(OracleDisposition disposition);
const char *EvidenceKindName(EvidenceKind evidence_kind);

// These functions are the sole v3 decision point.  Callers may record raw
// observations, but must not infer a finding state from a legacy flag.
OracleDisposition FinalizeDisposition(const KEMOracleTrace &trace);
bool HasSecurityEvidence(const KEMOracleTrace &trace);
bool HasSanitizerEvidence(const KEMOracleTrace &trace);

}  // namespace pqcfuzz

#endif

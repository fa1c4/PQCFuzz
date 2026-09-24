#ifndef PQCFUZZ_ORACLES_ORACLE_RESULT_H
#define PQCFUZZ_ORACLES_ORACLE_RESULT_H

#include <string>

#include "oracles/oracle_record.h"
#include "oracles/scheme_claims.h"

namespace pqcfuzz {

struct KEMOracleTrace;

enum class OracleDisposition {
  kPass,
  kDiagnostic,
  kNotEvaluable,
  kNotApplicable,
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

// Binds a violated oracle claim to the design document's verdict vocabulary
// and evidence classes.  Findings inherit the oracle record's one primary
// evidence class; a crash or sanitizer finding is always a concrete failure.
FindingClassification ClassifyFinding(
    const std::string &oracle_id,
    EvidenceKind evidence_kind,
    const std::string &finding_class);

// Variant-aware classification: the caller resolves (oracle_id, profile_id,
// subtest_id) through scheme_claims and the finding keeps the resolved
// claim_id and metadata instead of being overwritten by the oracle_id-only
// record.
FindingClassification ClassifyFindingResolved(
    const ResolvedClaim &resolved,
    EvidenceKind evidence_kind,
    const std::string &finding_class);

}  // namespace pqcfuzz

#endif

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
SPECS_DIR = SRC_ROOT / "oracles" / "specs"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import CORE_EXECUTOR_SOURCES, compile_and_run  # noqa: E402
from replay.replay_one import classify_violation  # noqa: E402


EVIDENCE_CLASSES = {
    "NORMATIVE",
    "REFERENCE_DERIVED",
    "IMPLEMENTATION_OBSERVED",
    "ENGINEERING_RECOMMENDATION",
    "INFERENCE",
}


def test_generated_oracle_specs_are_current() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/generate_oracle_specs.py", "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_every_oracle_record_has_claim_evidence_and_source() -> None:
    seen: set[str] = set()
    for path in sorted(SPECS_DIR.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for entry in payload["oracles"]:
            oracle_id = entry["oracle_id"]
            assert oracle_id not in seen, f"duplicate oracle_id {oracle_id}"
            seen.add(oracle_id)
            assert entry.get("claim"), f"{oracle_id}: missing claim"
            assert entry.get("evidence_class") in EVIDENCE_CLASSES, f"{oracle_id}: bad evidence_class"
            assert entry.get("source_reference"), f"{oracle_id}: missing source_reference"
            assert isinstance(entry.get("limitations", []), list)
    assert len(seen) >= 45


def test_violation_verdicts_follow_the_evidence_class() -> None:
    assert classify_violation("mlkem_tampered_ciphertext_implicit_rejection", "semantic")["verdict"] == "NONCONFORMANT"
    assert classify_violation("mlkem_tampered_ciphertext_implicit_rejection", "semantic")["evidence_class"] == "NORMATIVE"

    aigis = classify_violation("aigissig_exact_length", "semantic")
    assert aigis["verdict"] == "HARDENING_GAP"
    assert aigis["evidence_class"] == "ENGINEERING_RECOMMENDATION"
    assert aigis["conditional_verdict"]

    observed = classify_violation("aigissig_local_sign_verify", "semantic")
    assert observed["verdict"] == "INCONCLUSIVE"
    assert observed["evidence_class"] == "IMPLEMENTATION_OBSERVED"

    sanitizer = classify_violation("unmapped_oracle_id", "sanitizer")
    assert sanitizer["verdict"] == "NONCONFORMANT"


def test_aigis_hardening_findings_are_never_conformant() -> None:
    for oracle_id in (
        "aigisenc_sk_noncanonical_coefficient",
        "aigissig_exact_length",
        "aigissig_unused_sign_bits",
        "aigissig_ctx256_failure_state",
    ):
        classification = classify_violation(oracle_id, "semantic")
        assert classification["verdict"] == "HARDENING_GAP", oracle_id
        assert classification["evidence_class"] == "ENGINEERING_RECOMMENDATION", oracle_id
        assert classification["conditional_verdict"], oracle_id


def test_security_game_findings_are_not_conformant() -> None:
    for oracle_id in ("kem_decaps_c", "sig_verify_m", "sig_verify_sig", "sig_verify_pk"):
        classification = classify_violation(oracle_id, "semantic")
        assert classification["verdict"] == "NONCONFORMANT", oracle_id


def test_cpp_classification_and_trace_serialization(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include <string>
        #include "oracles/oracle_executor.h"
        #include "oracles/oracle_result.h"

        int main() {
          using namespace pqcfuzz;
          const auto hardening = ClassifyFinding(
              "aigissig_exact_length", EvidenceKind::kSemantic, "potential_crypto_vuln");
          if (hardening.verdict != Verdict::kHardeningGap) return 1;
          if (hardening.evidence_class != EvidenceClass::kEngineeringRecommendation) return 2;
          if (hardening.conditional_verdict.empty()) return 3;

          const auto normative = ClassifyFinding(
              "mlkem_tampered_ciphertext_implicit_rejection", EvidenceKind::kSemantic, "potential_crypto_vuln");
          if (normative.verdict != Verdict::kNonconformant) return 4;
          if (normative.evidence_class != EvidenceClass::kNormative) return 5;

          const auto observed = ClassifyFinding(
              "aigissig_local_sign_verify", EvidenceKind::kSemantic, "confirmed_semantic_bug");
          if (observed.verdict != Verdict::kInconclusive) return 6;

          const auto sanitizer = ClassifyFinding("mldsa_mutated_signature_negative",
                                                 EvidenceKind::kSanitizer, "memory_safety");
          if (sanitizer.verdict != Verdict::kNonconformant) return 7;

          if (VerdictForViolation(EvidenceClass::kNormative) == Verdict::kConformant) return 8;
          if (VerdictForViolation(EvidenceClass::kEngineeringRecommendation) != Verdict::kHardeningGap) return 9;

          KEMOracleTrace trace;
          trace.oracle_id = "aigissig_exact_length";
          OracleFindingTrace finding;
          finding.finding_class = "potential_crypto_vuln";
          finding.verdict = hardening.verdict;
          finding.evidence_class = hardening.evidence_class;
          finding.conditional_verdict = hardening.conditional_verdict;
          finding.claim = hardening.claim;
          finding.source_reference = hardening.source_reference;
          finding.limitations = hardening.limitations;
          trace.findings.push_back(finding);
          const std::string json = TraceToJson(trace);
          if (json.find("\\"verdict\\":\\"HARDENING_GAP\\"") == std::string::npos) return 10;
          if (json.find("\\"evidence_class\\":\\"ENGINEERING_RECOMMENDATION\\"") == std::string::npos) return 11;
          if (json.find("\\"conditional_verdict\\":") == std::string::npos) return 12;
          return 0;
        }
        """,
        CORE_EXECUTOR_SOURCES,
    )

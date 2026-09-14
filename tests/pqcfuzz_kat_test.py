from __future__ import annotations

import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
REFERENCE_ARCHIVE = REPO_ROOT / "workspace" / "build" / "reference" / "libpqcfuzz_pqclean_reference.a"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import compile_and_run  # noqa: E402


KAT_SOURCES = [
    "src/oracles/kat_executor.cc",
    "src/adapters/reference/reference_adapter.cc",
    "src/adapters/reference/pqclean_randombytes_override.cc",
    "src/adapters/rng_control.cc",
    "src/adapters/liboqs/rng_control.cc",
    "src/adapters/status.cc",
    "src/oracles/expected_relation.cc",
    "src/oracles/oracle_record.cc",
    "src/oracles/oracle_result.cc",
    "src/oracles/oracle_spec.cc",
    "src/oracles/metamorphic_spec.cc",
    str(REFERENCE_ARCHIVE),
]


POSITIVE_SOURCE = """
#include "adapters/reference/reference_adapter.h"
#include "oracles/kat_executor.h"

int main() {
  const pqcfuzz_kem_adapter *kem = pqcfuzz::pqcfuzz_get_pqclean_reference_kem_adapter("pqclean_ref_mlkem768");
  if (kem == nullptr) return 1;
  const char *oracles[] = {"fips203_kat_keygen", "fips203_kat_encaps", "fips203_kat_decaps"};
  for (const char *oracle_id : oracles) {
    pqcfuzz::KATOracleConfig config;
    config.job_id = "kat-test";
    config.pair_id = "kat-pair";
    config.algorithm = "ML-KEM-768";
    config.oracle_id = oracle_id;
    config.kem = kem;
    auto trace = pqcfuzz::ExecuteKATOracle(config);
    if (trace.subtests.empty()) return 2;
    for (const auto &subtest : trace.subtests) {
      if (subtest.not_applicable) return 3;
      if (!subtest.passed) return 4;
    }
    if (!trace.findings.empty()) return 5;
    if (pqcfuzz::IsPersistableRawEvidence(trace)) return 6;
  }

  const pqcfuzz_sig_adapter *slh = pqcfuzz::pqcfuzz_get_pqclean_reference_sig_adapter("pqclean_ref_slhdsa_sha2_128s");
  if (slh == nullptr || slh->keygen_seeded == nullptr) return 7;
  pqcfuzz::KATOracleConfig slh_config;
  slh_config.job_id = "kat-test";
  slh_config.pair_id = "kat-pair";
  slh_config.algorithm = "SLH-DSA-SHA2-128s";
  slh_config.oracle_id = "fips205_kat_keygen";
  slh_config.sig = slh;
  auto slh_trace = pqcfuzz::ExecuteKATOracle(slh_config);
  if (slh_trace.subtests.empty()) return 8;
  for (const auto &subtest : slh_trace.subtests) {
    if (subtest.not_applicable) return 9;
    if (!subtest.passed) return 10;
  }
  if (!slh_trace.findings.empty()) return 11;
  return 0;
}
"""


NEGATIVE_SOURCE = """
#include <cstring>
#include "oracles/kat_executor.h"

namespace {
pqcfuzz_status KeygenDerand(uint8_t *pk, uint8_t *sk, const uint8_t *) {
  std::memset(pk, 0x00, 800);
  std::memset(sk, 0x00, 1632);
  return PQCFUZZ_OK;
}
pqcfuzz_status EncapsDerand(uint8_t *ct, uint8_t *ss, const uint8_t *, const uint8_t *) {
  std::memset(ct, 0x00, 768);
  std::memset(ss, 0x00, 32);
  return PQCFUZZ_OK;
}
pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *, const uint8_t *) {
  std::memset(ss, 0x00, 32);
  return PQCFUZZ_OK;
}
const pqcfuzz_kem_adapter kAdapter = {
    "fake", "fake_mlkem512", "ML-KEM-512", 800, 1632, 768, 32,
    nullptr, nullptr, Decaps, KeygenDerand, EncapsDerand, nullptr};
}  // namespace

int main() {
  pqcfuzz::KATOracleConfig config;
  config.job_id = "kat-negative";
  config.pair_id = "kat-negative-pair";
  config.algorithm = "ML-KEM-512";
  config.oracle_id = "fips203_kat_keygen";
  config.kem = &kAdapter;
  auto trace = pqcfuzz::ExecuteKATOracle(config);
  if (trace.findings.empty()) return 1;
  for (const auto &finding : trace.findings) {
    if (finding.verdict != pqcfuzz::Verdict::kNonconformant) return 2;
    if (finding.evidence_class != pqcfuzz::EvidenceClass::kReferenceDerived) return 3;
  }
  if (!pqcfuzz::IsPersistableRawEvidence(trace)) return 4;
  return 0;
}
"""


@pytest.mark.skipif(not REFERENCE_ARCHIVE.is_file(), reason="PQClean reference archive is not built")
def test_kat_oracles_match_pinned_acvp_vectors(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        POSITIVE_SOURCE,
        KAT_SOURCES,
        defines=["PQCFUZZ_HAVE_PQCLEAN_REFERENCE"],
    )


def test_kat_oracle_reports_reference_vector_mismatch(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        NEGATIVE_SOURCE,
        KAT_SOURCES,
        defines=["PQCFUZZ_HAVE_PQCLEAN_REFERENCE"],
    )


def test_kat_generated_vectors_are_current() -> None:
    import subprocess

    result = subprocess.run(
        [sys.executable, "scripts/parse_kat_vectors.py", "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

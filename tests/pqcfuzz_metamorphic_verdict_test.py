from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

COMMON_SOURCES = [
    "src/adapters/rng_control.cc",
    "src/adapters/liboqs/rng_control.cc",
    "src/mutators/maul.cc",
    "src/oracles/metamorphic_observation.cc",
    "src/oracles/metamorphic_spec.cc",
    "src/oracles/metamorphic_executor.cc",
    "src/oracles/expected_relation.cc",
    "src/oracles/oracle_record.cc",
    "src/oracles/oracle_result.cc",
    "src/oracles/oracle_spec.cc",
]


SOURCE = """
#include <cstring>
#include <string>
#include "oracles/metamorphic_executor.h"

namespace {
pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1312);
  std::memset(sk, 0x22, 2560);
  return PQCFUZZ_OK;
}
pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                    const uint8_t *, const uint8_t *, size_t) {
  std::memset(sig, 0x33, 2420);
  *sig_len = 2420;
  return PQCFUZZ_OK;
}
pqcfuzz_status Verify(const uint8_t *, size_t sig_len, const uint8_t *, size_t,
                      const uint8_t *, const uint8_t *, size_t) {
  return sig_len == 2420 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
}
const pqcfuzz_sig_adapter kAdapter = {
    "fake", "fake_mldsa44", "ML-DSA-44", 1312, 2560, 2420, 1, 0, 0,
    Keygen, Sign, Verify, nullptr, 1, 0, 0};
}  // namespace

int main() {
  pqcfuzz::MetamorphicSigConfig cfg;
  cfg.job_id = "metamorphic-verdict";
  cfg.pair_id = "metamorphic-verdict-pair";
  cfg.algorithm = "ML-DSA-44";
  cfg.oracle_id = "sig_verify_sig";
  cfg.target = &kAdapter;
  cfg.seed = {1, 2, 3};
  cfg.mutation = {0, 0, 0, 0, 0};
  auto trace = pqcfuzz::ExecuteMetamorphicSigOracle(cfg);
  if (trace.findings.empty()) return 1;
  const auto &finding = trace.findings[0];
  if (finding.verdict != pqcfuzz::Verdict::kNonconformant) return 2;
  if (finding.evidence_class != pqcfuzz::EvidenceClass::kNormative) return 3;
  if (finding.claim.empty() || finding.source_reference.empty() || finding.limitations.empty()) return 4;
  if (trace.controls.positive_control.empty() || trace.controls.negative_control.empty()) return 5;
  if (trace.controls.baseline_repeat_equal) return 6;
  return 0;
}
"""


def test_metamorphic_findings_carry_verdict_evidence_and_controls(tmp_path: Path) -> None:
    main = tmp_path / "main.cc"
    binary = tmp_path / "case"
    main.write_text(textwrap.dedent(SOURCE), encoding="utf-8")
    cxx = os.environ.get("CXX", "clang++")
    subprocess.run(
        [cxx, "-std=c++17", "-O0", "-g", "-Isrc", str(main), *COMMON_SOURCES, "-o", str(binary)],
        cwd=REPO_ROOT,
        check=True,
    )
    subprocess.run([str(binary)], cwd=REPO_ROOT, check=True)

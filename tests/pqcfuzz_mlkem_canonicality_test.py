from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import CORE_EXECUTOR_SOURCES, compile_and_run  # noqa: E402


SOURCE = """
#include <cstring>
#include <string>
#include <vector>
#include "mutators/ml_kem_layout.h"
#include "oracles/oracle_executor.h"

namespace {
bool g_check_canonical = true;
bool g_reject_q_minus_1 = false;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1184);
  std::memset(sk, 0x22, 2400);
  return PQCFUZZ_OK;
}

pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
  if (g_check_canonical) {
    std::vector<uint8_t> public_key(pk, pk + 1184);
    const uint16_t bound = g_reject_q_minus_1 ? 3328 : 3329;
    for (size_t i = 0; i < 3 * 256; ++i) {
      uint16_t value = 0;
      if (!pqcfuzz::DecodeMlKemCoefficient12(public_key, i, &value)) return PQCFUZZ_REJECT;
      if (value >= bound) return PQCFUZZ_REJECT;
    }
  }
  std::memset(ct, 0x33, 1088);
  std::memset(ss, 0x44, 32);
  return PQCFUZZ_OK;
}

pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *, const uint8_t *) {
  std::memset(ss, 0x44, 32);
  return PQCFUZZ_OK;
}

const pqcfuzz_kem_adapter kAdapter = {
    "fake", "fake_mlkem768", "ML-KEM-768", 1184, 2400, 1088, 32, Keygen, Encaps, Decaps};
}  // namespace

int main(int argc, char **argv) {
  const std::string mode = argc > 1 ? argv[1] : "strict";
  g_check_canonical = mode != "accept-all";
  g_reject_q_minus_1 = mode == "over-reject";
  pqcfuzz::OracleExecutorConfig cfg;
  cfg.job_id = "ek-canonicality-test";
  cfg.pair_id = "ek-canonicality-pair";
  cfg.algorithm = "ML-KEM-768";
  cfg.oracle_id = "mlkem_ek_canonicality";
  cfg.left = &kAdapter;
  pqcfuzz::GetMlKemParams(cfg.algorithm, &cfg.params);
  cfg.seed = {1, 2, 3};
  auto trace = pqcfuzz::ExecuteKemOracle(cfg);
  if (trace.subtests.size() != 4) return 1;
  if (mode == "strict") {
    if (!trace.findings.empty()) return 2;
    for (const auto &subtest : trace.subtests) {
      if (!subtest.passed) return 3;
    }
    return 0;
  }
  if (mode == "accept-all") {
    if (trace.findings.size() != 3) return 4;
    for (const auto &finding : trace.findings) {
      if (finding.verdict != pqcfuzz::Verdict::kNonconformant) return 5;
      if (finding.finding_class != "potential_crypto_vuln") return 6;
    }
    return 0;
  }
  // over-reject: q-1 must be accepted, so exactly one finding is expected.
  if (trace.findings.size() != 1) return 7;
  if (trace.findings[0].finding_subclass != "ek_canonical_q_minus_1") return 8;
  return 0;
}
"""


def test_ek_canonicality_passes_for_checking_implementation(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SOURCE, CORE_EXECUTOR_SOURCES, args=["strict"])


def test_ek_canonicality_flags_accepted_noncanonical_coefficients(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SOURCE, CORE_EXECUTOR_SOURCES, args=["accept-all"])


def test_ek_canonicality_flags_over_rejection_of_q_minus_1(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SOURCE, CORE_EXECUTOR_SOURCES, args=["over-reject"])


def test_12bit_coefficient_roundtrip(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include <vector>
        #include "mutators/ml_kem_layout.h"

        int main() {
          std::vector<uint8_t> buffer(384, 0);
          for (uint16_t value : {0, 1, 3328, 3329, 3330, 4095}) {
            if (!pqcfuzz::EncodeMlKemCoefficient12(&buffer, 0, value)) return 1;
            uint16_t decoded = 0;
            if (!pqcfuzz::DecodeMlKemCoefficient12(buffer, 0, &decoded)) return 2;
            if (decoded != value) return 3;
            if (!pqcfuzz::EncodeMlKemCoefficient12(&buffer, 1, value)) return 4;
            if (!pqcfuzz::DecodeMlKemCoefficient12(buffer, 1, &decoded)) return 5;
            if (decoded != value) return 6;
          }
          // A byte-straddling pair must round-trip independently.
          if (!pqcfuzz::EncodeMlKemCoefficient12(&buffer, 127, 3329)) return 7;
          if (!pqcfuzz::EncodeMlKemCoefficient12(&buffer, 128, 4095)) return 8;
          uint16_t low = 0;
          uint16_t high = 0;
          if (!pqcfuzz::DecodeMlKemCoefficient12(buffer, 127, &low)) return 9;
          if (!pqcfuzz::DecodeMlKemCoefficient12(buffer, 128, &high)) return 10;
          if (low != 3329 || high != 4095) return 11;
          return 0;
        }
        """,
        ["src/mutators/ml_kem_layout.cc"],
    )

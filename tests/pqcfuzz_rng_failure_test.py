from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import CORE_EXECUTOR_SOURCES, compile_and_run  # noqa: E402

TEST_SOURCES = list(CORE_EXECUTOR_SOURCES) + ["src/adapters/randombytes_override.cc"]


KEM_SOURCE = """
#include <cstring>
#include <string>
#include "adapters/rng_control.h"
#include "oracles/oracle_executor.h"

extern "C" void randombytes(uint8_t *out, size_t out_len);

namespace {
bool g_check_failure = false;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  if (g_check_failure && pqcfuzz::pqcfuzz_rng_failure_requested()) return PQCFUZZ_INVALID_INPUT;
  uint8_t coins[32];
  randombytes(coins, sizeof(coins));
  std::memset(pk, 0x11, 1184);
  std::memset(sk, 0x22, 2400);
  return PQCFUZZ_OK;
}
pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *) {
  if (g_check_failure && pqcfuzz::pqcfuzz_rng_failure_requested()) return PQCFUZZ_INVALID_INPUT;
  uint8_t coins[32];
  randombytes(coins, sizeof(coins));
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
  g_check_failure = argc > 1 && std::string(argv[1]) == "checking";
  pqcfuzz::OracleExecutorConfig cfg;
  cfg.job_id = "rng-failure-test";
  cfg.pair_id = "rng-failure-pair";
  cfg.algorithm = "ML-KEM-768";
  cfg.oracle_id = "mlkem_rng_failure";
  cfg.left = &kAdapter;
  pqcfuzz::GetMlKemParams(cfg.algorithm, &cfg.params);
  cfg.seed = {1, 2, 3};
  auto trace = pqcfuzz::ExecuteKemOracle(cfg);
  if (trace.subtests.size() != 2) return 1;
  if (g_check_failure) {
    if (!trace.findings.empty()) return 2;
    for (const auto &subtest : trace.subtests) {
      if (!subtest.passed) return 3;
    }
    return 0;
  }
  if (trace.findings.size() != 2) return 4;
  for (const auto &finding : trace.findings) {
    if (finding.verdict != pqcfuzz::Verdict::kHardeningGap) return 5;
    if (finding.evidence_class != pqcfuzz::EvidenceClass::kEngineeringRecommendation) return 6;
  }
  return 0;
}
"""


SIG_SOURCE = """
#include <cstring>
#include <string>
#include "adapters/rng_control.h"
#include "oracles/oracle_executor.h"

extern "C" void randombytes(uint8_t *out, size_t out_len);

namespace {
bool g_check_failure = false;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  if (g_check_failure && pqcfuzz::pqcfuzz_rng_failure_requested()) return PQCFUZZ_INVALID_INPUT;
  uint8_t coins[32];
  randombytes(coins, sizeof(coins));
  std::memset(pk, 0x11, 1312);
  std::memset(sk, 0x22, 2560);
  return PQCFUZZ_OK;
}
pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                    const uint8_t *, const uint8_t *, size_t) {
  if (g_check_failure && pqcfuzz::pqcfuzz_rng_failure_requested()) return PQCFUZZ_INVALID_INPUT;
  uint8_t coins[32];
  randombytes(coins, sizeof(coins));
  std::memset(sig, 0x33, 2420);
  *sig_len = 2420;
  return PQCFUZZ_OK;
}
pqcfuzz_status Verify(const uint8_t *, size_t, const uint8_t *, size_t,
                      const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_OK;
}
const pqcfuzz_sig_adapter kAdapter = {
    "fake", "fake_mldsa44", "ML-DSA-44", 1312, 2560, 2420, 1, 0, 0,
    Keygen, Sign, Verify, nullptr, 1, 0, 0};
}  // namespace

int main(int argc, char **argv) {
  g_check_failure = argc > 1 && std::string(argv[1]) == "checking";
  pqcfuzz::SigOracleExecutorConfig cfg;
  cfg.job_id = "rng-failure-sig-test";
  cfg.pair_id = "rng-failure-sig-pair";
  cfg.algorithm = "ML-DSA-44";
  cfg.oracle_id = "mldsa_rng_failure";
  cfg.left = &kAdapter;
  cfg.message = {'m'};
  cfg.seed = {1, 2, 3};
  auto trace = pqcfuzz::ExecuteSigOracle(cfg);
  if (trace.subtests.size() != 2) return 1;
  if (g_check_failure) {
    if (!trace.findings.empty()) return 2;
    for (const auto &subtest : trace.subtests) {
      if (!subtest.passed) return 3;
    }
    return 0;
  }
  if (trace.findings.size() != 2) return 4;
  for (const auto &finding : trace.findings) {
    if (finding.verdict != pqcfuzz::Verdict::kHardeningGap) return 5;
  }
  return 0;
}
"""


def test_kem_rng_failure_oracle_flags_ignored_failure(tmp_path: Path) -> None:
    compile_and_run(tmp_path, KEM_SOURCE, TEST_SOURCES, args=["ignoring"])


def test_kem_rng_failure_oracle_accepts_reported_failure(tmp_path: Path) -> None:
    compile_and_run(tmp_path, KEM_SOURCE, TEST_SOURCES, args=["checking"])


def test_sig_rng_failure_oracle_flags_ignored_failure(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SIG_SOURCE, TEST_SOURCES, args=["ignoring"])


def test_sig_rng_failure_oracle_accepts_reported_failure(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SIG_SOURCE, TEST_SOURCES, args=["checking"])

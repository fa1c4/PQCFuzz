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
#include "oracles/oracle_executor.h"

namespace {
bool g_check_hint = true;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1312);
  std::memset(sk, 0x22, 2560);
  return PQCFUZZ_OK;
}

// Canonical hint: cumulative counts [2, 4, 4, 4], positions 5, 9, 20, 21.
pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                    const uint8_t *, const uint8_t *, size_t) {
  std::memset(sig, 0x33, 2420);
  uint8_t *h = sig + 2420 - 84;
  h[0] = 2; h[1] = 4; h[2] = 4; h[3] = 4;
  h[4] = 5; h[5] = 9; h[6] = 20; h[7] = 21;
  for (size_t i = 8; i < 84; ++i) h[i] = 0;
  *sig_len = 2420;
  return PQCFUZZ_OK;
}

bool CanonicalHint(const uint8_t *sig, size_t sig_len) {
  if (sig_len != 2420) return false;
  const uint8_t *h = sig + sig_len - 84;
  const size_t k = 4;
  const size_t omega = 80;
  size_t previous_count = 0;
  for (size_t poly = 0; poly < k; ++poly) {
    const size_t count = h[poly];
    if (count < previous_count || count > omega) return false;
    for (size_t i = previous_count; i < count; ++i) {
      if (i > previous_count && h[k + i] <= h[k + i - 1]) return false;
    }
    previous_count = count;
  }
  for (size_t i = previous_count; i < omega; ++i) {
    if (h[k + i] != 0) return false;
  }
  return true;
}

pqcfuzz_status Verify(const uint8_t *sig, size_t sig_len, const uint8_t *, size_t,
                      const uint8_t *, const uint8_t *, size_t) {
  if (g_check_hint && !CanonicalHint(sig, sig_len)) return PQCFUZZ_REJECT;
  return PQCFUZZ_OK;
}

const pqcfuzz_sig_adapter kAdapter = {
    "fake", "fake_mldsa44", "ML-DSA-44", 1312, 2560, 2420, 1, 0, 0,
    Keygen, Sign, Verify, nullptr, 1, 0, 0};
}  // namespace

int main(int argc, char **argv) {
  g_check_hint = !(argc > 1 && std::string(argv[1]) == "lax");
  pqcfuzz::SigOracleExecutorConfig cfg;
  cfg.job_id = "hint-test";
  cfg.pair_id = "hint-pair";
  cfg.algorithm = "ML-DSA-44";
  cfg.oracle_id = "mldsa_hint_canonicality";
  cfg.left = &kAdapter;
  cfg.message = {'m'};
  cfg.seed = {1, 2, 3};
  auto trace = pqcfuzz::ExecuteSigOracle(cfg);
  if (trace.subtests.size() != 4) return 1;
  if (g_check_hint) {
    if (!trace.findings.empty()) return 2;
    for (const auto &subtest : trace.subtests) {
      if (!subtest.passed) return 3;
    }
    return 0;
  }
  if (trace.findings.size() != 4) return 4;
  for (const auto &finding : trace.findings) {
    if (finding.verdict != pqcfuzz::Verdict::kNonconformant) return 5;
    if (finding.finding_class != "potential_crypto_vuln") return 6;
  }
  return 0;
}
"""


def test_hint_canonicality_passes_for_strict_verifier(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SOURCE, CORE_EXECUTOR_SOURCES, args=["strict"])


def test_hint_canonicality_flags_lax_verifier(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SOURCE, CORE_EXECUTOR_SOURCES, args=["lax"])


def test_hint_mutations_are_effective(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include <vector>
        #include "mutators/ml_dsa_mutator.h"

        int main() {
          pqcfuzz::MlDsaParams params{};
          if (!pqcfuzz::GetMlDsaParams("ML-DSA-44", &params)) return 1;
          if (params.omega != 80 || params.k != 4) return 2;
          std::vector<uint8_t> signature(2420, 0);
          uint8_t *h = signature.data() + 2420 - 84;
          h[0] = 2; h[1] = 4; h[2] = 4; h[3] = 4;
          h[4] = 5; h[5] = 9; h[6] = 20; h[7] = 21;
          for (pqcfuzz::MlDsaHintMutation mutation : {
                   pqcfuzz::MlDsaHintMutation::kCountRollback,
                   pqcfuzz::MlDsaHintMutation::kCountOverflow,
                   pqcfuzz::MlDsaHintMutation::kNonIncreasingIndex,
                   pqcfuzz::MlDsaHintMutation::kTrailingNonZero}) {
            std::vector<uint8_t> candidate = signature;
            auto records = pqcfuzz::MutateMlDsaHintCanonical(params, mutation, &candidate);
            if (records.size() != 1 || !records[0].effective || records[0].skipped) return 3;
            if (candidate == signature) return 4;
          }
          return 0;
        }
        """,
        ["src/mutators/ml_dsa_layout.cc", "src/mutators/ml_dsa_mutator.cc", "src/mutators/ml_kem_layout.cc"],
    )

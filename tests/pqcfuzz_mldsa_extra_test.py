from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import CORE_EXECUTOR_SOURCES, compile_and_run  # noqa: E402


Z_NORM_SOURCE = """
#include <cstring>
#include <string>
#include <vector>
#include "oracles/oracle_executor.h"

namespace {
bool g_accept_mutated = false;
std::vector<uint8_t> g_valid_signature;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1312);
  std::memset(sk, 0x22, 2560);
  return PQCFUZZ_OK;
}
pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                    const uint8_t *, const uint8_t *, size_t) {
  std::memset(sig, 0x00, 2420);
  *sig_len = 2420;
  g_valid_signature.assign(sig, sig + 2420);
  return PQCFUZZ_OK;
}
pqcfuzz_status Verify(const uint8_t *sig, size_t sig_len, const uint8_t *, size_t,
                      const uint8_t *, const uint8_t *, size_t) {
  if (g_accept_mutated) return sig_len == 2420 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
  if (sig_len != 2420) return PQCFUZZ_REJECT;
  return std::memcmp(sig, g_valid_signature.data(), 2420) == 0 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
}
const pqcfuzz_sig_adapter kAdapter = {
    "fake", "fake_mldsa44", "ML-DSA-44", 1312, 2560, 2420, 1, 0, 0,
    Keygen, Sign, Verify, nullptr, 1, 0, 0};
}  // namespace

int main(int argc, char **argv) {
  g_accept_mutated = argc > 1 && std::string(argv[1]) == "accept-mutated";
  pqcfuzz::SigOracleExecutorConfig cfg;
  cfg.job_id = "znorm-test";
  cfg.pair_id = "znorm-pair";
  cfg.algorithm = "ML-DSA-44";
  cfg.oracle_id = "mldsa_z_norm_boundary";
  cfg.left = &kAdapter;
  cfg.message = {'m'};
  cfg.seed = {1, 2, 3};
  auto trace = pqcfuzz::ExecuteSigOracle(cfg);
  if (trace.subtests.size() != 3) return 1;
  if (g_accept_mutated) {
    if (trace.findings.size() != 2) return 2;
    for (const auto &finding : trace.findings) {
      if (finding.verdict != pqcfuzz::Verdict::kNonconformant) return 3;
    }
    return 0;
  }
  if (!trace.findings.empty()) return 4;
  for (const auto &subtest : trace.subtests) {
    if (!subtest.passed) return 5;
  }
  return 0;
}
"""


RND_SOURCE = """
#include <cstring>
#include <string>
#include <vector>
#include "oracles/oracle_executor.h"

extern "C" void randombytes(uint8_t *out, size_t out_len);

namespace {
pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1312);
  std::memset(sk, 0x22, 2560);
  return PQCFUZZ_OK;
}
pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                    const uint8_t *, const uint8_t *, size_t) {
  std::memset(sig, 0x33, 2420);
  randombytes(sig, 32);
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
  pqcfuzz::SigOracleExecutorConfig cfg;
  cfg.job_id = "rnd-test";
  cfg.pair_id = "rnd-pair";
  cfg.algorithm = "ML-DSA-44";
  cfg.oracle_id = "mldsa_rnd_determinism";
  cfg.left = &kAdapter;
  cfg.message = {'m'};
  cfg.seed = {1, 2, 3};
  auto trace = pqcfuzz::ExecuteSigOracle(cfg);
  if (trace.subtests.size() != 4) return 1;
  for (const auto &subtest : trace.subtests) {
    if (subtest.not_applicable) return 2;
    if (!subtest.passed) return 3;
  }
  if (!trace.findings.empty()) return 4;
  return 0;
}
"""


NA_SOURCE = """
#include "oracles/oracle_executor.h"

int main() {
  const pqcfuzz_sig_adapter adapter = {
      "fake", "fake_mldsa44", "ML-DSA-44", 1312, 2560, 2420, 1, 0, 0,
      nullptr, nullptr, nullptr, nullptr, 1, 0, 0};
  pqcfuzz::SigOracleExecutorConfig cfg;
  cfg.job_id = "na-test";
  cfg.pair_id = "na-pair";
  cfg.algorithm = "ML-DSA-44";
  cfg.oracle_id = "mldsa_pure_prehash_separation";
  cfg.left = &adapter;
  cfg.message = {'m'};
  cfg.seed = {1, 2, 3};
  auto trace = pqcfuzz::ExecuteSigOracle(cfg);
  if (trace.subtests.size() != 1) return 1;
  if (!trace.subtests[0].not_applicable) return 2;
  if (!trace.findings.empty()) return 3;
  if (pqcfuzz::FinalizeDisposition(trace) != pqcfuzz::OracleDisposition::kNotApplicable) return 4;
  if (pqcfuzz::IsPersistableRawEvidence(trace)) return 5;
  return 0;
}
"""


def test_z_norm_boundary_rejects_and_flags_out_of_norm(tmp_path: Path) -> None:
    compile_and_run(tmp_path, Z_NORM_SOURCE, CORE_EXECUTOR_SOURCES, args=["strict"])
    compile_and_run(tmp_path, Z_NORM_SOURCE, CORE_EXECUTOR_SOURCES, args=["accept-mutated"])


def test_rnd_determinism_oracle_uses_tape_control(tmp_path: Path) -> None:
    sources = list(CORE_EXECUTOR_SOURCES)
    sources.append("src/adapters/randombytes_override.cc")
    compile_and_run(tmp_path, RND_SOURCE, sources)


def test_prehash_oracles_record_not_applicable(tmp_path: Path) -> None:
    compile_and_run(tmp_path, NA_SOURCE, CORE_EXECUTOR_SOURCES)


def test_z_norm_mutation_encodes_boundary_values(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include <cstring>
        #include <vector>
        #include "mutators/ml_dsa_mutator.h"

        int main() {
          pqcfuzz::MlDsaParams params{};
          if (!pqcfuzz::GetMlDsaParams("ML-DSA-44", &params)) return 1;
          if (params.gamma1 != (1u << 17) || params.beta != 78 || params.gamma1_bits != 18) return 2;
          std::vector<uint8_t> signature(2420, 0);
          auto records = pqcfuzz::MutateMlDsaZNormBoundary(
              params, pqcfuzz::MlDsaZNormMutation::kOverBoundary, &signature);
          if (records.size() != 1 || !records[0].effective || records[0].skipped) return 3;
          if (records[0].target != "signature.z") return 4;
          // beta = 78 must appear in the first 18 bits of the z region (offset 32).
          const uint64_t value = static_cast<uint64_t>(signature[32]) |
                                 (static_cast<uint64_t>(signature[33]) << 8) |
                                 (static_cast<uint64_t>(signature[34]) << 16);
          if ((value & 0x3FFFFu) != 78u) return 5;
          return 0;
        }
        """,
        ["src/mutators/ml_kem_layout.cc", "src/mutators/ml_dsa_layout.cc", "src/mutators/ml_dsa_mutator.cc"],
    )

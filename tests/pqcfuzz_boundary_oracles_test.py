from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import CORE_EXECUTOR_SOURCES, compile_and_run  # noqa: E402


EXACT_LENGTH_SOURCE = """
#include <cstring>
#include <string>
#include <vector>
#include "oracles/oracle_executor.h"

namespace {
bool g_accept_oversized = false;
size_t g_last_sign_ctx_len = 0;
std::vector<uint8_t> g_last_sign_ctx;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1312);
  std::memset(sk, 0x22, 2560);
  return PQCFUZZ_OK;
}
pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                    const uint8_t *, const uint8_t *ctx, size_t ctx_len) {
  if (ctx_len > 255) return PQCFUZZ_REJECT;
  std::memset(sig, 0x33, 2420);
  *sig_len = 2420;
  g_last_sign_ctx_len = ctx_len;
  g_last_sign_ctx.assign(ctx, ctx + ctx_len);
  return PQCFUZZ_OK;
}
pqcfuzz_status Verify(const uint8_t *, size_t sig_len, const uint8_t *, size_t,
                      const uint8_t *, const uint8_t *ctx, size_t ctx_len) {
  if (g_accept_oversized) return sig_len >= 2420 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
  if (sig_len != 2420) return PQCFUZZ_REJECT;
  if (ctx_len != g_last_sign_ctx_len) return PQCFUZZ_REJECT;
  if (ctx_len != 0 && std::memcmp(ctx, g_last_sign_ctx.data(), ctx_len) != 0) return PQCFUZZ_REJECT;
  return PQCFUZZ_OK;
}
const pqcfuzz_sig_adapter kAdapter = {
    "fake", "fake_mldsa44", "ML-DSA-44", 1312, 2560, 2420, 1, 0, 0,
    Keygen, Sign, Verify, nullptr, 1, 1, 1};
}  // namespace

int main(int argc, char **argv) {
  const std::string mode = argc > 1 ? argv[1] : "";
  g_accept_oversized = mode == "accept-oversized";
  pqcfuzz::SigOracleExecutorConfig cfg;
  cfg.job_id = "boundary-test";
  cfg.pair_id = "boundary-pair";
  cfg.algorithm = "ML-DSA-44";
  cfg.oracle_id = "mldsa_verify_exact_lengths";
  cfg.left = &kAdapter;
  cfg.message = {'m'};
  cfg.seed = {1, 2, 3};
  auto trace = pqcfuzz::ExecuteSigOracle(cfg);
  if (mode == "accept-oversized") {
    if (trace.findings.size() != 3) return 1;
    bool saw_nonzero = false;
    for (const auto &finding : trace.findings) {
      if (finding.finding_subclass == "exact_length_long_nonzero") saw_nonzero = true;
      if (finding.verdict != pqcfuzz::Verdict::kNonconformant) return 2;
    }
    if (!saw_nonzero) return 3;
    return 0;
  }
  if (!trace.findings.empty()) return 4;
  for (const auto &subtest : trace.subtests) {
    if (!subtest.passed) return 5;
  }
  return 0;
}
"""


CTX_SOURCE = """
#include <cstring>
#include <string>
#include <vector>
#include "oracles/oracle_executor.h"

namespace {
size_t g_last_sign_ctx_len = 0;
std::vector<uint8_t> g_last_sign_ctx;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1312);
  std::memset(sk, 0x22, 2560);
  return PQCFUZZ_OK;
}
pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                    const uint8_t *, const uint8_t *ctx, size_t ctx_len) {
  if (ctx_len > 255) return PQCFUZZ_REJECT;
  std::memset(sig, 0x33, 2420);
  *sig_len = 2420;
  g_last_sign_ctx_len = ctx_len;
  g_last_sign_ctx.assign(ctx, ctx + ctx_len);
  return PQCFUZZ_OK;
}
pqcfuzz_status Verify(const uint8_t *, size_t sig_len, const uint8_t *, size_t,
                      const uint8_t *, const uint8_t *ctx, size_t ctx_len) {
  if (sig_len != 2420) return PQCFUZZ_REJECT;
  if (ctx_len != g_last_sign_ctx_len) return PQCFUZZ_REJECT;
  if (ctx_len != 0 && std::memcmp(ctx, g_last_sign_ctx.data(), ctx_len) != 0) return PQCFUZZ_REJECT;
  return PQCFUZZ_OK;
}
}  // namespace

int main(int argc, char **argv) {
  const int supports_context = argc > 1 && std::string(argv[1]) == "no-context" ? 0 : 1;
  const pqcfuzz_sig_adapter adapter = {
      "fake", "fake_mldsa44", "ML-DSA-44", 1312, 2560, 2420, supports_context, 0, 0,
      Keygen, Sign, Verify, nullptr, 1, supports_context, supports_context};
  pqcfuzz::SigOracleExecutorConfig cfg;
  cfg.job_id = "ctx-test";
  cfg.pair_id = "ctx-pair";
  cfg.algorithm = "ML-DSA-44";
  cfg.oracle_id = "mldsa_ctx_boundaries";
  cfg.left = &adapter;
  cfg.message = {'m'};
  cfg.seed = {1, 2, 3};
  auto trace = pqcfuzz::ExecuteSigOracle(cfg);
  if (!supports_context) {
    if (trace.subtests.size() != 1) return 1;
    if (!trace.subtests[0].not_applicable) return 2;
    return 0;
  }
  if (!trace.findings.empty()) return 3;
  for (const auto &subtest : trace.subtests) {
    if (!subtest.passed) return 4;
  }
  return 0;
}
"""


RAW_LENGTH_SOURCE = """
#include <cstring>
#include "oracles/oracle_executor.h"

namespace {
pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1184);
  std::memset(sk, 0x22, 2400);
  return PQCFUZZ_OK;
}
pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *) {
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

int main() {
  pqcfuzz::OracleExecutorConfig cfg;
  cfg.job_id = "raw-length-test";
  cfg.pair_id = "raw-length-pair";
  cfg.algorithm = "ML-KEM-768";
  cfg.oracle_id = "mlkem_raw_length_boundary";
  cfg.left = &kAdapter;
  pqcfuzz::GetMlKemParams(cfg.algorithm, &cfg.params);
  cfg.seed = {1, 2, 3};
  auto trace = pqcfuzz::ExecuteKemOracle(cfg);
  if (trace.subtests.size() != 1) return 1;
  if (!trace.subtests[0].not_applicable) return 2;
  if (trace.subtests[0].skipped) return 3;
  if (pqcfuzz::FinalizeDisposition(trace) != pqcfuzz::OracleDisposition::kNotApplicable) return 4;
  if (pqcfuzz::IsPersistableRawEvidence(trace)) return 5;
  return 0;
}
"""


def test_exact_length_oracle_passes_when_target_rejects(tmp_path: Path) -> None:
    compile_and_run(tmp_path, EXACT_LENGTH_SOURCE, CORE_EXECUTOR_SOURCES, args=["strict"])


def test_exact_length_oracle_flags_oversized_acceptance(tmp_path: Path) -> None:
    compile_and_run(tmp_path, EXACT_LENGTH_SOURCE, CORE_EXECUTOR_SOURCES, args=["accept-oversized"])


def test_context_boundaries_pass_and_not_applicable(tmp_path: Path) -> None:
    compile_and_run(tmp_path, CTX_SOURCE, CORE_EXECUTOR_SOURCES, args=["with-context"])
    compile_and_run(tmp_path, CTX_SOURCE, CORE_EXECUTOR_SOURCES, args=["no-context"])


def test_mlkem_raw_length_boundary_is_not_applicable(tmp_path: Path) -> None:
    compile_and_run(tmp_path, RAW_LENGTH_SOURCE, CORE_EXECUTOR_SOURCES)


def test_oracle_enum_maps_agree_for_new_ids() -> None:
    from replay.replay_one import ORACLE_BY_ENUM
    from jobs.generated_config_writer import ORACLE_ENUM_BY_NAME

    for enum_value, name in ORACLE_BY_ENUM.items():
        if enum_value >= 46:
            assert ORACLE_ENUM_BY_NAME.get(name) == enum_value, name

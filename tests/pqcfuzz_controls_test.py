from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import CORE_EXECUTOR_SOURCES, compile_and_run  # noqa: E402


CONTROLS_SOURCE = """
#include <cstring>
#include <string>
#include <vector>
#include "mutators/ml_kem_layout.h"
#include "oracles/oracle_executor.h"

namespace {
uint8_t g_valid_ct[1568];
size_t g_valid_ct_len = 0;
uint8_t g_valid_ss[32];

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1184);
  std::memset(sk, 0x22, 2400);
  return PQCFUZZ_OK;
}
pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *) {
  std::memset(ct, 0x33, 1088);
  std::memset(ss, 0x44, 32);
  std::memcpy(g_valid_ct, ct, 1088);
  std::memcpy(g_valid_ss, ss, 32);
  g_valid_ct_len = 1088;
  return PQCFUZZ_OK;
}
pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  if (g_valid_ct_len != 0 && std::memcmp(ct, g_valid_ct, g_valid_ct_len) == 0) {
    std::memcpy(ss, g_valid_ss, 32);
    return PQCFUZZ_OK;
  }
  for (size_t i = 0; i < 32; ++i) ss[i] = static_cast<uint8_t>(0x5A ^ ct[0] ^ sk[2400 - 32 + i]);
  return PQCFUZZ_OK;
}
const pqcfuzz_kem_adapter kAdapter = {
    "fake", "fake_mlkem768", "ML-KEM-768", 1184, 2400, 1088, 32, Keygen, Encaps, Decaps};
}  // namespace

int main() {
  pqcfuzz::OracleExecutorConfig cfg;
  cfg.job_id = "controls-test";
  cfg.pair_id = "controls-pair";
  cfg.algorithm = "ML-KEM-768";
  cfg.oracle_id = "mlkem_implicit_rejection_relations";
  cfg.left = &kAdapter;
  pqcfuzz::GetMlKemParams(cfg.algorithm, &cfg.params);
  cfg.seed = {1, 2, 3};
  cfg.mutation = {0, 0, 0, 0, 0xA5};
  auto trace = pqcfuzz::ExecuteKemOracle(cfg);
  if (!trace.controls.baseline_repeat_equal) return 1;
  if (trace.controls.positive_control.empty()) return 2;
  if (trace.controls.negative_control.empty()) return 3;
  const std::string json = pqcfuzz::TraceToJson(trace);
  if (json.find("\\"controls\\"") == std::string::npos) return 4;
  if (json.find("\\"baseline_repeat_equal\\":") == std::string::npos) return 5;
  return 0;
}
"""


SENTINEL_SOURCE = """
#include <cstring>
#include <string>
#include "adapters/pqmagic/sig_adapter.h"
#include "oracles/oracle_executor.h"

namespace {
bool g_leak = false;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x41, 1056);
  std::memset(sk, 0x42, 2448);
  return PQCFUZZ_OK;
}
pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                    const uint8_t *, const uint8_t *, size_t ctx_len) {
  if (ctx_len > 255) {
    if (g_leak) {
      sig[0] = 0x00;
      *sig_len = 0;
    }
    return PQCFUZZ_REJECT;
  }
  std::memset(sig, 0x43, 1852);
  *sig_len = 1852;
  return PQCFUZZ_OK;
}
pqcfuzz_status Verify(const uint8_t *, size_t, const uint8_t *, size_t,
                      const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_OK;
}
const pqcfuzz_sig_adapter kAdapter = {
    "pqmagic", "pqmagic_aigis_sig1_std_sm3", "AIGIS-SIG-1",
    1056, 2448, 1852, 1, 0, 1, Keygen, Sign, Verify, nullptr, 1, 1, 1};
}  // namespace

int main(int argc, char **argv) {
  g_leak = argc > 1 && std::string(argv[1]) == "leak";
  pqcfuzz::SigOracleExecutorConfig cfg;
  cfg.algorithm = "AIGIS-SIG-1";
  cfg.oracle_id = "aigissig_ctx256_failure_state";
  cfg.left = &kAdapter;
  cfg.message = {'m'};
  cfg.seed = {1, 2, 3};
  auto trace = pqcfuzz::ExecuteSigOracle(cfg);
  if (trace.subtests.empty()) return 1;
  if (g_leak) {
    if (trace.subtests[0].passed) return 2;
    if (trace.findings.size() != 1) return 3;
    return 0;
  }
  if (!trace.subtests[0].passed) return 4;
  if (!trace.findings.empty()) return 5;
  return 0;
}
"""


def test_relations_oracle_records_controls(tmp_path: Path) -> None:
    compile_and_run(tmp_path, CONTROLS_SOURCE, CORE_EXECUTOR_SOURCES)


def test_failure_sentinel_accepts_clean_rejection(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SENTINEL_SOURCE, CORE_EXECUTOR_SOURCES, args=["clean"])


def test_failure_sentinel_flags_partial_output(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SENTINEL_SOURCE, CORE_EXECUTOR_SOURCES, args=["leak"])

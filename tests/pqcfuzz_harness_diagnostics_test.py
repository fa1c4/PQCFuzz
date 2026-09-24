from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import CORE_EXECUTOR_SOURCES, compile_and_run  # noqa: E402


SOURCE = """
#include <cstring>
#include "oracles/oracle_executor.h"

namespace {
pqcfuzz_status KemKeygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1184);
  std::memset(sk, 0x22, 2400);
  return PQCFUZZ_OK;
}
pqcfuzz_status KemEncaps(uint8_t *ct, uint8_t *ss, const uint8_t *) {
  std::memset(ct, 0x33, 1088);
  std::memset(ss, 0x44, 32);
  return PQCFUZZ_OK;
}
pqcfuzz_status KemDecaps(uint8_t *ss, const uint8_t *, const uint8_t *) {
  std::memset(ss, 0x44, 32);
  return PQCFUZZ_OK;
}
const pqcfuzz_kem_adapter kKem = {
    "fake", "fake_mlkem768", "ML-KEM-768", 1184, 2400, 1088, 32, KemKeygen, KemEncaps, KemDecaps};

pqcfuzz_status SigKeygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1312);
  std::memset(sk, 0x22, 2560);
  return PQCFUZZ_OK;
}
pqcfuzz_status SigSign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                       const uint8_t *, const uint8_t *, size_t) {
  std::memset(sig, 0x33, 2420);
  *sig_len = 2420;
  return PQCFUZZ_OK;
}
pqcfuzz_status SigVerify(const uint8_t *, size_t, const uint8_t *, size_t,
                         const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_OK;
}
const pqcfuzz_sig_adapter kSig = {
    "fake", "fake_mldsa44", "ML-DSA-44", 1312, 2560, 2420, 1, 0, 0,
    SigKeygen, SigSign, SigVerify, nullptr, 1, 0, 0};
}  // namespace

int main() {
  pqcfuzz::OracleExecutorConfig kem;
  kem.job_id = "harness";
  kem.pair_id = "harness";
  kem.algorithm = "ML-KEM-768";
  kem.oracle_id = "mlkem_local_roundtrip";
  kem.left = &kKem;
  kem.right = nullptr;
  pqcfuzz::GetMlKemParams(kem.algorithm, &kem.params);
  auto kem_trace = pqcfuzz::ExecuteKemOracle(kem);
  if (kem_trace.diagnostics.empty() || kem_trace.diagnostics[0].code != "harness_error") return 1;
  if (pqcfuzz::FinalizeDisposition(kem_trace) != pqcfuzz::OracleDisposition::kHarnessError) return 2;

  pqcfuzz::SigOracleExecutorConfig sig;
  sig.job_id = "harness";
  sig.pair_id = "harness";
  sig.algorithm = "ML-DSA-44";
  sig.oracle_id = "mldsa_local_sign_verify";
  sig.left = &kSig;
  sig.right = nullptr;
  auto sig_trace = pqcfuzz::ExecuteSigOracle(sig);
  if (sig_trace.diagnostics.empty() || sig_trace.diagnostics[0].code != "harness_error") return 3;
  if (pqcfuzz::FinalizeDisposition(sig_trace) != pqcfuzz::OracleDisposition::kHarnessError) return 4;
  return 0;
}
"""


def test_missing_right_adapter_is_a_harness_error(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SOURCE, CORE_EXECUTOR_SOURCES)

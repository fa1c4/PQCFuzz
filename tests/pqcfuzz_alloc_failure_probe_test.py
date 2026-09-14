from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import compile_and_run  # noqa: E402


SOURCES = [
    "src/oracles/alloc_failure_oracle.cc",
    "src/runtime/alloc_fault_injector.cc",
    "src/runtime/isolated_worker.cc",
    "src/oracles/oracle_record.cc",
    "src/oracles/oracle_result.cc",
    "src/oracles/oracle_spec.cc",
    "src/oracles/metamorphic_spec.cc",
    "src/oracles/expected_relation.cc",
    "src/adapters/status.cc",
]
FLAGS = ["-O0", "-g", "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=realloc"]


SOURCE = """
#include <cstdlib>
#include <cstring>
#include <string>
#include "oracles/alloc_failure_oracle.h"

namespace {
enum class Contract { kGood, kLeaky, kIgnoring };
Contract g_contract = Contract::kGood;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  switch (g_contract) {
    case Contract::kGood: {
      void *probe = std::malloc(16);
      if (probe == nullptr) return PQCFUZZ_INVALID_INPUT;
      std::free(probe);
      std::memset(pk, 0x11, 800);
      std::memset(sk, 0x22, 1632);
      return PQCFUZZ_OK;
    }
    case Contract::kLeaky: {
      std::memset(pk, 0x11, 800);
      void *probe = std::malloc(16);
      if (probe == nullptr) return PQCFUZZ_INVALID_INPUT;
      std::free(probe);
      std::memset(sk, 0x22, 1632);
      return PQCFUZZ_OK;
    }
    case Contract::kIgnoring: {
      void *probe = std::malloc(16);
      (void)probe;
      std::memset(pk, 0x11, 800);
      std::memset(sk, 0x22, 1632);
      return PQCFUZZ_OK;
    }
  }
  return PQCFUZZ_INVALID_INPUT;
}

const pqcfuzz_kem_adapter kAdapter = {
    "fake", "fake_mlkem512", "ML-KEM-512", 800, 1632, 768, 32,
    Keygen, nullptr, nullptr, nullptr, nullptr, nullptr};
}  // namespace

int main(int argc, char **argv) {
  const std::string mode = argc > 1 ? argv[1] : "good";
  g_contract = mode == "leaky" ? Contract::kLeaky : (mode == "ignoring" ? Contract::kIgnoring : Contract::kGood);
  pqcfuzz::AllocFailureProbeConfig config;
  config.job_id = "alloc-test";
  config.pair_id = "alloc-pair";
  config.algorithm = "ML-KEM-512";
  config.kem = &kAdapter;
  config.max_sites = 3;
  auto trace = pqcfuzz::ExecuteAllocFailureProbe(config);
  if (trace.subtests.empty()) return 1;
  if (mode == "good") {
    if (!trace.findings.empty()) return 2;
    if (!trace.subtests[0].passed) return 3;
    if (trace.subtests[0].skipped) return 4;
    return 0;
  }
  if (trace.findings.empty()) return 5;
  for (const auto &finding : trace.findings) {
    if (finding.verdict != pqcfuzz::Verdict::kHardeningGap) return 6;
    if (finding.finding_subclass != "alloc_fail_site_1") return 7;
  }
  return 0;
}
"""


def test_alloc_failure_probe_accepts_clean_failure_contract(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SOURCE, SOURCES, flags=FLAGS, args=["good"])


def test_alloc_failure_probe_flags_partial_output(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SOURCE, SOURCES, flags=FLAGS, args=["leaky"])


def test_alloc_failure_probe_flags_ignored_allocation_failure(tmp_path: Path) -> None:
    compile_and_run(tmp_path, SOURCE, SOURCES, flags=FLAGS, args=["ignoring"])

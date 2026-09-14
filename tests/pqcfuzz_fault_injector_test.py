from __future__ import annotations

import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import compile_and_run  # noqa: E402


ALLOC_SOURCE = """
#include <cstdlib>
#include "runtime/alloc_fault_injector.h"

int main() {
  pqcfuzz_alloc_fault_reset();
  void *first = malloc(32);
  void *second = malloc(32);
  if (first == nullptr) return 1;
  if (second != nullptr) return 2;
  if (pqcfuzz_alloc_fault_failures() != 1) return 3;
  if (pqcfuzz_alloc_fault_calls() != 2) return 4;
  free(first);
  pqcfuzz_alloc_fault_disarm();
  void *third = malloc(32);
  if (third == nullptr) return 5;
  free(third);
  return 0;
}
"""


RNG_SOURCE = """
#include <cstdint>
#include "adapters/rng_control.h"

int main() {
  uint8_t tape[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint8_t out[8] = {0};

  {
    pqcfuzz::ScopedRngOverride rng({tape, 8, true, pqcfuzz::RngTape::Mode::kRepeatedBlock});
    if (pqcfuzz_rng_fill_bytes(out, 8) != 1) return 1;
    for (int i = 0; i < 8; ++i) {
      if (out[i] != tape[i]) return 2;
    }
  }
  {
    pqcfuzz::ScopedRngOverride rng({tape, 8, true, pqcfuzz::RngTape::Mode::kAllZero});
    if (pqcfuzz_rng_fill_bytes(out, 8) != 1) return 3;
    for (int i = 0; i < 8; ++i) {
      if (out[i] != 0) return 4;
    }
  }
  {
    pqcfuzz::ScopedRngOverride rng({tape, 8, true, pqcfuzz::RngTape::Mode::kReportedFailure});
    pqcfuzz::pqcfuzz_rng_reset_failure_observed();
    if (pqcfuzz::pqcfuzz_rng_failure_requested() != true) return 5;
    if (pqcfuzz_rng_fill_bytes(out, 8) != 0) return 6;
    if (!pqcfuzz::pqcfuzz_rng_failure_observed()) return 7;
  }
  {
    pqcfuzz::ScopedRngOverride rng({tape, 8, true, pqcfuzz::RngTape::Mode::kShortRead});
    if (pqcfuzz_rng_fill_bytes(out, 8) != 1) return 8;
    if (out[0] != tape[0] || out[3] != tape[3]) return 9;
    if (out[4] != 0 || out[7] != 0) return 10;
  }
  {
    pqcfuzz::ScopedRngOverride rng({tape, 8, true, pqcfuzz::RngTape::Mode::kInterrupted});
    pqcfuzz::pqcfuzz_rng_reset_failure_observed();
    if (pqcfuzz_rng_fill_bytes(out, 8) != 0) return 11;
    if (!pqcfuzz::pqcfuzz_rng_failure_observed()) return 12;
  }
  return 0;
}
"""


def test_alloc_fault_injector_fails_configured_allocation(tmp_path: Path) -> None:
    os.environ["PQCFUZZ_ALLOC_FAIL_AT"] = "2"
    os.environ["PQCFUZZ_ALLOC_FAIL_COUNT"] = "1"
    try:
        compile_and_run(
            tmp_path,
            ALLOC_SOURCE,
            ["src/runtime/alloc_fault_injector.cc"],
            flags=["-O0", "-g", "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=realloc"],
        )
    finally:
        os.environ.pop("PQCFUZZ_ALLOC_FAIL_AT", None)
        os.environ.pop("PQCFUZZ_ALLOC_FAIL_COUNT", None)


def test_rng_fault_modes(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        RNG_SOURCE,
        ["src/adapters/rng_control.cc", "src/adapters/liboqs/rng_control.cc"],
    )

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def compile_and_run(tmp_path: Path, source: str, extra_sources: list[str] | None = None) -> None:
    main = tmp_path / "main.cc"
    binary = tmp_path / "case"
    main.write_text(textwrap.dedent(source), encoding="utf-8")
    cxx = os.environ.get("CXX", "clang++")
    cmd = [
        cxx,
        "-std=c++17",
        "-O0",
        "-g",
        "-Isrc",
        str(main),
        "src/adapters/rng_control.cc",
        "src/adapters/liboqs/rng_control.cc",
        *(extra_sources or []),
        "-o",
        str(binary),
    ]
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    subprocess.run([str(binary)], cwd=REPO_ROOT, check=True)


def test_rng_tape_zero_and_repeat(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "adapters/rng_control.h"
        #include <cstdint>
        int main() {
          uint8_t zeros[2] = {0, 0};
          uint8_t out[4] = {1, 1, 1, 1};
          {
            pqcfuzz::ScopedRngOverride rng({zeros, sizeof(zeros), true});
            if (!rng.active() || !pqcfuzz_rng_fill_bytes(out, sizeof(out))) return 1;
          }
          for (uint8_t byte : out) {
            if (byte != 0) return 2;
          }
          uint8_t pattern[2] = {7, 9};
          {
            pqcfuzz::ScopedRngOverride rng({pattern, sizeof(pattern), true});
            if (!pqcfuzz_rng_fill_bytes(out, sizeof(out))) return 3;
          }
          return out[0] == 7 && out[1] == 9 && out[2] == 7 && out[3] == 9 ? 0 : 4;
        }
        """,
    )


def test_rng_driven_fake_keygen_changes_with_tape(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "adapters/rng_control.h"
        #include <cstdint>
        int main() {
          uint8_t a[4] = {1, 2, 3, 4};
          uint8_t b[4] = {9, 8, 7, 6};
          uint8_t out_a[4] = {};
          uint8_t out_b[4] = {};
          {
            pqcfuzz::ScopedRngOverride rng({a, sizeof(a), true});
            pqcfuzz_rng_fill_bytes(out_a, sizeof(out_a));
          }
          {
            pqcfuzz::ScopedRngOverride rng({b, sizeof(b), true});
            pqcfuzz_rng_fill_bytes(out_b, sizeof(out_b));
          }
          for (int i = 0; i < 4; ++i) {
            if (out_a[i] == out_b[i]) return 1;
          }
          return 0;
        }
        """,
    )


def test_ignored_rng_keygen_reports_malleability(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "adapters/adapter_interface.h"
        #include "oracles/metamorphic_executor.h"
        namespace {
        pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
          for (size_t i = 0; i < 4; ++i) { pk[i] = 1; sk[i] = 2; }
          return PQCFUZZ_OK;
        }
        pqcfuzz_status Encaps(uint8_t *, uint8_t *, const uint8_t *) { return PQCFUZZ_API_UNSUPPORTED; }
        pqcfuzz_status Decaps(uint8_t *, const uint8_t *, const uint8_t *) { return PQCFUZZ_API_UNSUPPORTED; }
        }
        int main() {
          static const pqcfuzz_kem_adapter adapter = {"fake", "ignored_rng", "ML-KEM-768", 4, 4, 4, 4, Keygen, Encaps, Decaps};
          pqcfuzz::MetamorphicKemConfig cfg;
          cfg.job_id = "test";
          cfg.pair_id = "test";
          cfg.algorithm = "ML-KEM-768";
          cfg.oracle_id = "kem_keygen_badrng";
          cfg.target = &adapter;
          cfg.seed = {1, 2, 3};
          auto trace = pqcfuzz::ExecuteMetamorphicKemOracle(cfg);
          return trace.finding_class == "malleability" && trace.finding_subclass == "keygen_rng_ignored" ? 0 : 1;
        }
        """,
        [
            "src/mutators/maul.cc",
            "src/oracles/metamorphic_observation.cc",
            "src/oracles/metamorphic_spec.cc",
            "src/oracles/metamorphic_executor.cc",
        ],
    )

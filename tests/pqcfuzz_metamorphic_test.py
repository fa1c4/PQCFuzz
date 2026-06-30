from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from triage.classify_finding import classify_trace

COMMON_SOURCES = [
    "src/adapters/rng_control.cc",
    "src/adapters/liboqs/rng_control.cc",
    "src/mutators/maul.cc",
    "src/oracles/metamorphic_observation.cc",
    "src/oracles/metamorphic_spec.cc",
    "src/oracles/metamorphic_executor.cc",
]


def compile_and_run(tmp_path: Path, source: str, extra_sources: list[str]) -> subprocess.CompletedProcess[str]:
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
        *COMMON_SOURCES,
        *extra_sources,
        "-o",
        str(binary),
    ]
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    return subprocess.run([str(binary)], cwd=REPO_ROOT, check=True, text=True, capture_output=True)


def test_expect_different_equal_kem_reports_malleability(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "oracles/metamorphic_executor.h"
        extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_kem_equal_adapter();
        int main() {
          pqcfuzz::MetamorphicKemConfig cfg;
          cfg.job_id = "test";
          cfg.pair_id = "test";
          cfg.algorithm = "ML-KEM-768";
          cfg.oracle_id = "kem_decaps_c";
          cfg.target = pqcfuzz_fake_kem_equal_adapter();
          cfg.seed = {1, 2, 3};
          cfg.mutation = {0, 0, 1};
          auto trace = pqcfuzz::ExecuteMetamorphicKemOracle(cfg);
          return trace.finding_class == "malleability" && trace.finding_subclass == "ciphertext_malleability" ? 0 : 1;
        }
        """,
        ["tests/fake_adapters/fake_kem_equal.cc"],
    )


def test_expect_different_different_kem_has_no_finding(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "oracles/metamorphic_executor.h"
        extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_kem_different_adapter();
        int main() {
          pqcfuzz::MetamorphicKemConfig cfg;
          cfg.job_id = "test";
          cfg.pair_id = "test";
          cfg.algorithm = "ML-KEM-768";
          cfg.oracle_id = "kem_decaps_c";
          cfg.target = pqcfuzz_fake_kem_different_adapter();
          cfg.seed = {1, 2, 3};
          cfg.mutation = {0, 0, 1};
          auto trace = pqcfuzz::ExecuteMetamorphicKemOracle(cfg);
          return trace.findings.empty() ? 0 : 1;
        }
        """,
        ["tests/fake_adapters/fake_kem_different.cc"],
    )


def test_sig_verify_accepts_mutated_signature_reports_malleability(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "oracles/metamorphic_executor.h"
        extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_sig_verify_accepts_mutation_adapter();
        int main() {
          pqcfuzz::MetamorphicSigConfig cfg;
          cfg.job_id = "test";
          cfg.pair_id = "test";
          cfg.algorithm = "ML-DSA-44";
          cfg.oracle_id = "sig_verify_sig";
          cfg.target = pqcfuzz_fake_sig_verify_accepts_mutation_adapter();
          cfg.message = {'m'};
          cfg.mutation = {0, 0, 1};
          auto trace = pqcfuzz::ExecuteMetamorphicSigOracle(cfg);
          return trace.finding_class == "malleability" && trace.finding_subclass == "signature_malleability" ? 0 : 1;
        }
        """,
        ["tests/fake_adapters/fake_sig_verify_accepts_mutation.cc"],
    )


def test_unsupported_adapter_reports_unsupported(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "oracles/metamorphic_executor.h"
        int main() {
          pqcfuzz::MetamorphicKemConfig cfg;
          cfg.job_id = "test";
          cfg.pair_id = "test";
          cfg.algorithm = "ML-KEM-768";
          cfg.oracle_id = "kem_decaps_c";
          auto trace = pqcfuzz::ExecuteMetamorphicKemOracle(cfg);
          return trace.finding_class == "unsupported" ? 0 : 1;
        }
        """,
        [],
    )


def test_classification_relation_cases() -> None:
    assert classify_trace({"expected_relation": "EXPECT_DIFFERENT", "observed_relation": "OBSERVED_EQUAL", "findings": []}) == "malleability"
    assert classify_trace({"expected_relation": "EXPECT_EQUAL", "observed_relation": "OBSERVED_DIFFERENT", "findings": []}) == "non_malleability"
    assert classify_trace({"findings": [{"class": "crash", "summary": "boom"}]}) == "crash"
    assert classify_trace({"findings": [{"class": "hang", "summary": "slow"}]}) == "hang"

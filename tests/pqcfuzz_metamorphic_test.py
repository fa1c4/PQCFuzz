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


def test_every_metamorphic_oracle_executes_with_effective_controls(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include <string>
        #include <vector>
        #include "oracles/metamorphic_executor.h"
        extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_kem_oracle_contract_adapter();
        extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_sig_oracle_contract_adapter();

        bool Check(const pqcfuzz::KEMOracleTrace &trace, const std::string &id, bool rng) {
          if (trace.oracle_id != id || !trace.findings.empty() || !trace.valid_setup ||
              !trace.relation_evaluable || !trace.intervention_effective || trace.subtests.empty() ||
              trace.subtests.front().skipped) return false;
          return !rng || (!trace.rng_interventions.empty() &&
                          trace.rng_interventions.front().baseline_bytes_consumed > 0 &&
                          trace.rng_interventions.front().mutated_bytes_consumed > 0);
        }

        int main() {
          const std::vector<std::string> kem = {
              "kem_decaps_c", "kem_decaps_sk", "kem_encaps_badrng", "kem_encaps_pk_0",
              "kem_encaps_pk", "kem_keygen_badrng"};
          for (size_t i = 0; i < kem.size(); ++i) {
            const auto &id = kem[i];
            pqcfuzz::MetamorphicKemConfig cfg;
            cfg.job_id = "test"; cfg.pair_id = "test"; cfg.algorithm = "ML-KEM-768";
            cfg.oracle_id = id; cfg.target = pqcfuzz_fake_kem_oracle_contract_adapter();
            cfg.seed = {1, 2, 3}; cfg.mutation = {0, 0, 1};
            if (!Check(pqcfuzz::ExecuteMetamorphicKemOracle(cfg), id, id.find("badrng") != std::string::npos)) return 1;
          }
          const std::vector<std::string> sig = {
              "sig_keygen_badrng", "sig_sign_badrng", "sig_sign_m", "sig_sign_sk",
              "sig_verify_m", "sig_verify_sig", "sig_verify_pk"};
          for (size_t i = 0; i < sig.size(); ++i) {
            const auto &id = sig[i];
            pqcfuzz::MetamorphicSigConfig cfg;
            cfg.job_id = "test"; cfg.pair_id = "test"; cfg.algorithm = "ML-DSA-44";
            cfg.oracle_id = id; cfg.target = pqcfuzz_fake_sig_oracle_contract_adapter();
            cfg.seed = {1, 2, 3}; cfg.message = {'m', 's', 'g'}; cfg.context = {'c'}; cfg.mutation = {0, 0, 1};
            if (!Check(pqcfuzz::ExecuteMetamorphicSigOracle(cfg), id, id.find("badrng") != std::string::npos)) return 2;
          }
          return 0;
        }
        """,
        ["tests/fake_adapters/fake_oracle_contract.cc"],
    )


def test_kem_setup_keygen_failure_is_skipped_not_malleability(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "oracles/metamorphic_executor.h"
        extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_kem_keygen_fails_adapter();
        int main() {
          pqcfuzz::MetamorphicKemConfig cfg;
          cfg.job_id = "test";
          cfg.pair_id = "test";
          cfg.algorithm = "ML-KEM-768";
          cfg.oracle_id = "kem_decaps_c";
          cfg.target = pqcfuzz_fake_kem_keygen_fails_adapter();
          cfg.seed = {1, 2, 3};
          cfg.mutation = {0, 0, 1};
          auto trace = pqcfuzz::ExecuteMetamorphicKemOracle(cfg);
          return trace.findings.empty() &&
                         trace.observed_relation == "OBSERVED_SETUP_FAILED" &&
                         !trace.subtests.empty() &&
                         trace.subtests[0].skipped &&
                         trace.subtests[0].note == "setup keygen failed"
                     ? 0
                     : 1;
        }
        """,
        ["tests/fake_adapters/fake_kem_keygen_fails.cc"],
    )


def test_kem_setup_encaps_failure_is_skipped_not_malleability(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "oracles/metamorphic_executor.h"
        extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_kem_encaps_fails_adapter();
        int main() {
          pqcfuzz::MetamorphicKemConfig cfg;
          cfg.job_id = "test";
          cfg.pair_id = "test";
          cfg.algorithm = "ML-KEM-768";
          cfg.oracle_id = "kem_decaps_c";
          cfg.target = pqcfuzz_fake_kem_encaps_fails_adapter();
          cfg.seed = {1, 2, 3};
          cfg.mutation = {0, 0, 1};
          auto trace = pqcfuzz::ExecuteMetamorphicKemOracle(cfg);
          return trace.findings.empty() &&
                         trace.observed_relation == "OBSERVED_SETUP_FAILED" &&
                         !trace.subtests.empty() &&
                         trace.subtests[0].skipped &&
                         trace.subtests[0].note == "setup encaps failed"
                     ? 0
                     : 1;
        }
        """,
        ["tests/fake_adapters/fake_kem_encaps_fails.cc"],
    )


def test_sig_setup_sign_failure_is_skipped_not_malleability(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "oracles/metamorphic_executor.h"
        extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_sig_sign_fails_adapter();
        int main() {
          pqcfuzz::MetamorphicSigConfig cfg;
          cfg.job_id = "test";
          cfg.pair_id = "test";
          cfg.algorithm = "ML-DSA-44";
          cfg.oracle_id = "sig_verify_sig";
          cfg.target = pqcfuzz_fake_sig_sign_fails_adapter();
          cfg.message = {'m'};
          cfg.mutation = {0, 0, 1};
          auto trace = pqcfuzz::ExecuteMetamorphicSigOracle(cfg);
          return trace.findings.empty() &&
                         trace.observed_relation == "OBSERVED_SETUP_FAILED" &&
                         !trace.subtests.empty() &&
                         trace.subtests[0].skipped &&
                         trace.subtests[0].note == "setup sign failed"
                     ? 0
                     : 1;
        }
        """,
        ["tests/fake_adapters/fake_sig_sign_fails.cc"],
    )


def test_classification_relation_cases() -> None:
    assert classify_trace({"expected_relation": "EXPECT_DIFFERENT", "observed_relation": "OBSERVED_EQUAL", "findings": []}) == "malleability"
    assert classify_trace({"expected_relation": "EXPECT_EQUAL", "observed_relation": "OBSERVED_DIFFERENT", "findings": []}) == "non_malleability"
    assert classify_trace({"findings": [{"class": "crash", "summary": "boom"}]}) == "crash"
    assert classify_trace({"findings": [{"class": "hang", "summary": "slow"}]}) == "hang"

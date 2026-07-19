from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_fips_randomness_oracles_use_observed_distinct_rng_controls(tmp_path: Path) -> None:
    main = tmp_path / "main.cc"
    binary = tmp_path / "fips_randomness_case"
    main.write_text(
        textwrap.dedent(
            """
            #include "oracles/oracle_executor.h"
            extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_kem_oracle_contract_adapter();
            extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_sig_oracle_contract_adapter();

            bool Check(const pqcfuzz::KEMOracleTrace &trace) {
              return trace.findings.empty() && trace.valid_setup && trace.relation_evaluable &&
                     trace.intervention_effective && trace.rng_interventions.size() == 1 &&
                     trace.rng_interventions[0].baseline_bytes_consumed > 0 &&
                     trace.rng_interventions[0].mutated_bytes_consumed > 0 &&
                     !trace.subtests.empty() && trace.subtests[0].passed && !trace.subtests[0].skipped;
            }

            int main() {
              pqcfuzz::OracleExecutorConfig kem;
              kem.algorithm = "ML-KEM-768";
              kem.oracle_id = "mlkem_bad_randomness_sanity";
              kem.left = pqcfuzz_fake_kem_oracle_contract_adapter();
              kem.seed = {1, 2, 3};
              if (!Check(pqcfuzz::ExecuteKemOracle(kem))) return 1;

              pqcfuzz::SigOracleExecutorConfig sig;
              sig.algorithm = "ML-DSA-44";
              sig.oracle_id = "mldsa_bad_randomness_sanity";
              sig.left = pqcfuzz_fake_sig_oracle_contract_adapter();
              sig.seed = {1, 2, 3};
              sig.message = {'m'};
              if (!Check(pqcfuzz::ExecuteSigOracle(sig))) return 2;
              return 0;
            }
            """
        ),
        encoding="utf-8",
    )
    sources = [
        "src/adapters/status.cc",
        "src/adapters/rng_control.cc",
        "src/adapters/liboqs/rng_control.cc",
        "src/mutators/maul.cc",
        "src/mutators/ml_kem_layout.cc",
        "src/mutators/ml_kem_mutator.cc",
        "src/mutators/ml_dsa_layout.cc",
        "src/mutators/ml_dsa_mutator.cc",
        "src/mutators/slh_dsa_layout.cc",
        "src/mutators/slh_dsa_mutator.cc",
        "src/oracles/expected_relation.cc",
        "src/oracles/oracle_result.cc",
        "src/oracles/metamorphic_observation.cc",
        "src/oracles/oracle_executor.cc",
        "tests/fake_adapters/fake_oracle_contract.cc",
    ]
    command = [os.environ.get("CXX", "clang++"), "-std=c++17", "-Isrc", str(main), *sources, "-o", str(binary)]
    subprocess.run(command, cwd=REPO_ROOT, check=True)
    subprocess.run([str(binary)], cwd=REPO_ROOT, check=True)

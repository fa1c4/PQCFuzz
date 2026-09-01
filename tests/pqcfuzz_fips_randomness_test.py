from __future__ import annotations

from pathlib import Path

from _test_sources import CORE_EXECUTOR_SOURCES, compile_and_run


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_fips_randomness_oracles_use_observed_distinct_rng_controls(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
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
        """,
        sources=[*CORE_EXECUTOR_SOURCES, "tests/fake_adapters/fake_oracle_contract.cc"],
    )

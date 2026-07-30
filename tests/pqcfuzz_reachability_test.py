from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def compile_and_run(tmp_path: Path, source: str, extra_sources: list[str]) -> None:
    main = tmp_path / "main.cc"
    binary = tmp_path / "case"
    main.write_text(textwrap.dedent(source), encoding="utf-8")
    sources = [
        "src/adapters/rng_control.cc",
        "src/adapters/liboqs/rng_control.cc",
        "src/mutators/maul.cc",
        "src/oracles/metamorphic_observation.cc",
        "src/oracles/metamorphic_spec.cc",
        "src/oracles/metamorphic_executor.cc",
        *extra_sources,
    ]
    subprocess.run(
        [os.environ.get("CXX", "clang++"), "-std=c++17", "-O0", "-g", "-Isrc", str(main), *sources, "-o", str(binary)],
        cwd=REPO_ROOT,
        check=True,
    )
    subprocess.run([str(binary)], cwd=REPO_ROOT, check=True)


def test_context_precheck_records_executor_rejection_without_target_entry(tmp_path: Path) -> None:
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
          cfg.context.assign(256, 'c');
          cfg.mutation = {0, 0, 1};
          auto trace = pqcfuzz::ExecuteMetamorphicSigOracle(cfg);
          if (!trace.findings.empty() || trace.relation_evaluable) return 1;
          if (trace.subtests.empty() || trace.subtests[0].calls.size() < 2) return 2;
          const auto &call = trace.subtests[0].calls.back();
          return call.status == PQCFUZZ_INVALID_INPUT &&
                         !call.executor_dispatched &&
                         !call.adapter_entered &&
                         !call.target_entered &&
                         !call.target_returned &&
                         call.rejection_layer == "executor"
                     ? 0
                     : 3;
        }
        """,
        ["tests/fake_adapters/fake_sig_verify_accepts_mutation.cc"],
    )


def test_legal_context_boundaries_reach_the_target(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "oracles/metamorphic_executor.h"
        #include <cstddef>
        extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_sig_verify_accepts_mutation_adapter();

        int main() {
          for (size_t context_len : {0u, 1u, 255u}) {
            pqcfuzz::MetamorphicSigConfig cfg;
            cfg.job_id = "test";
            cfg.pair_id = "test";
            cfg.algorithm = "ML-DSA-44";
            cfg.oracle_id = "sig_verify_sig";
            cfg.target = pqcfuzz_fake_sig_verify_accepts_mutation_adapter();
            cfg.message = {'m'};
            cfg.context.assign(context_len, 'c');
            cfg.mutation = {0, 0, 1};
            auto trace = pqcfuzz::ExecuteMetamorphicSigOracle(cfg);
            if (!trace.relation_evaluable) return 1;
            bool saw_target_verify = false;
            for (const auto &subtest : trace.subtests) {
              for (const auto &call : subtest.calls) {
                if (call.api == "verify" && call.executor_dispatched &&
                    call.adapter_entered && call.target_entered && call.target_returned &&
                    call.rejection_layer != "executor") {
                  saw_target_verify = true;
                }
              }
            }
            if (!saw_target_verify) return 2;
          }
          return 0;
        }
        """,
        ["tests/fake_adapters/fake_sig_verify_accepts_mutation.cc"],
    )

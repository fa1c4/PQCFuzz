from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_oracle_registry_has_one_descriptor_per_metamorphic_oracle(tmp_path: Path) -> None:
    main = tmp_path / "main.cc"
    binary = tmp_path / "case"
    main.write_text(
        textwrap.dedent(
            """
            #include "oracles/metamorphic_spec.h"
            #include "oracles/oracle_registry.h"
            #include <set>
            #include <string>

            int main() {
              std::set<std::string> seen;
              for (const auto &descriptor : pqcfuzz::OracleRegistry()) {
                if (!seen.insert(descriptor.oracle_id).second) return 1;
                if (pqcfuzz::FindMetamorphicSpec(descriptor.oracle_id) == nullptr) return 2;
              }
              for (const auto &oracle : pqcfuzz::DefaultMetamorphicKemOracles()) {
                if (pqcfuzz::FindOracleDescriptor(oracle) == nullptr) return 3;
              }
              for (const auto &oracle : pqcfuzz::DefaultMetamorphicSigOracles()) {
                if (pqcfuzz::FindOracleDescriptor(oracle) == nullptr) return 4;
              }
              const auto *verify = pqcfuzz::FindOracleDescriptor("sig_verify_sig");
              const auto *badrng = pqcfuzz::FindOracleDescriptor("sig_sign_badrng");
              if (verify == nullptr || pqcfuzz::EvidenceTierName(verify->evidence_tier) != std::string("security")) return 5;
              if (badrng == nullptr || pqcfuzz::EvidenceTierName(badrng->evidence_tier) != std::string("diagnostic")) return 6;
              return pqcfuzz::FindOracleDescriptor("unknown") == nullptr ? 0 : 7;
            }
            """
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [
            os.environ.get("CXX", "clang++"),
            "-std=c++17",
            "-Isrc",
            str(main),
            "src/oracles/metamorphic_spec.cc",
            "src/oracles/oracle_registry.cc",
            "-o",
            str(binary),
        ],
        cwd=REPO_ROOT,
        check=True,
    )
    subprocess.run([str(binary)], cwd=REPO_ROOT, check=True)

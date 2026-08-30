from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_adapter_routing_requires_algorithm_identity_and_abi(tmp_path: Path) -> None:
    source = tmp_path / "main.cc"
    binary = tmp_path / "case"
    source.write_text(
        textwrap.dedent(
            """
            #include "runtime/adapter_registry.h"
            int main() {
              pqcfuzz_kem_adapter adapter = {"fake", "fake-768", "ML-KEM-768", 1184, 2400, 1088, 32, nullptr, nullptr, nullptr};
              pqcfuzz::AdapterRoutingExpectation expected{"fake", "fake-768", "ML-KEM-768", 1184, 2400, 1088, 32, 0};
              std::string error;
              if (!pqcfuzz::ValidateKemAdapterRouting(&adapter, expected, &error)) return 1;
              expected.algorithm = "ML-KEM-512";
              if (pqcfuzz::ValidateKemAdapterRouting(&adapter, expected, &error)) return 2;
              expected.algorithm = "ML-KEM-768";
              expected.pk_len = 800;
              return pqcfuzz::ValidateKemAdapterRouting(&adapter, expected, &error) ? 3 : 0;
            }
            """
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [
            os.environ.get("CXX", "clang++"), "-std=c++17", "-Isrc", str(source),
            "src/runtime/adapter_registry.cc",
            "src/adapters/liboqs/kem_adapter.cc", "src/adapters/liboqs/sig_adapter.cc",
            "src/adapters/pqclean/kem_adapter.cc", "src/adapters/pqclean/sig_adapter.cc",
            "src/adapters/pqmagic/kem_adapter.cc", "src/adapters/pqmagic/sig_adapter.cc",
            "src/adapters/status.cc",
            "-o", str(binary),
        ],
        cwd=REPO_ROOT,
        check=True,
    )
    subprocess.run([str(binary)], cwd=REPO_ROOT, check=True)

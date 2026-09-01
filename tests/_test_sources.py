"""Shared compile-time sources and helpers for PQCFuzz C++ harness tests."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


# Superset of translation units used by the executor-based tests.  Linking
# extra objects is harmless; keeping one list removes the drift between the
# per-test compile commands.
CORE_EXECUTOR_SOURCES = [
    "src/adapters/status.cc",
    "src/adapters/rng_control.cc",
    "src/adapters/liboqs/rng_control.cc",
    "src/adapters/liboqs/kem_adapter.cc",
    "src/adapters/liboqs/sig_adapter.cc",
    "src/adapters/pqclean/kem_adapter.cc",
    "src/adapters/pqclean/sig_adapter.cc",
    "src/adapters/pqmagic/kem_adapter.cc",
    "src/adapters/pqmagic/sig_adapter.cc",
    "src/mutators/envelope.cc",
    "src/mutators/maul.cc",
    "src/mutators/ml_kem_layout.cc",
    "src/mutators/ml_kem_mutator.cc",
    "src/mutators/ml_dsa_layout.cc",
    "src/mutators/ml_dsa_mutator.cc",
    "src/mutators/slh_dsa_layout.cc",
    "src/mutators/slh_dsa_mutator.cc",
    "src/mutators/aigis_enc_layout.cc",
    "src/mutators/aigis_enc_mutator.cc",
    "src/mutators/aigis_sig_layout.cc",
    "src/mutators/aigis_sig_mutator.cc",
    "src/oracles/expected_relation.cc",
    "src/oracles/oracle_spec.cc",
    "src/oracles/oracle_spec_loader.cc",
    "src/oracles/oracle_result.cc",
    "src/oracles/oracle_executor.cc",
    "src/oracles/metamorphic_observation.cc",
    "src/oracles/metamorphic_spec.cc",
    "src/oracles/metamorphic_executor.cc",
    "src/runtime/adapter_registry.cc",
    "src/triage/finding_writer.cc",
]


def compile_and_run(
    tmp_path: Path,
    source: str,
    sources: list[str] | None = None,
    defines: list[str] | None = None,
    flags: list[str] | None = None,
    args: list[str] | None = None,
) -> Path:
    """Compile a C++ test main and run it, returning the binary path."""
    main = tmp_path / "main.cc"
    binary = tmp_path / "case"
    main.write_text(textwrap.dedent(source), encoding="utf-8")
    command = [
        os.environ.get("CXX", "clang++"),
        "-std=c++17",
        *(["-O0", "-g"] if flags is None else flags),
        "-Isrc",
        *([f"-D{flag}" for flag in defines] if defines else []),
        str(main),
        *(sources if sources is not None else CORE_EXECUTOR_SOURCES),
        "-o",
        str(binary),
    ]
    subprocess.run(command, cwd=REPO_ROOT, check=True)
    subprocess.run([str(binary), *(args or [])], cwd=REPO_ROOT, check=True)
    return binary

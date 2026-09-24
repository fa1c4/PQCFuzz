"""Shared compile helpers for the Falcon oracle/model test lanes."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FALCON_REF = REPO_ROOT / "projects" / "FALCON" / "reference"
FALCON_KAT = REPO_ROOT / "projects" / "FALCON" / "kat"
CXX = os.environ.get("CXX", "clang++")
CC = os.environ.get("CC", "clang")

REFERENCE_SOURCES = ["falcon", "codec", "common", "fft", "fpr", "keygen", "rng", "shake", "sign", "vrfy"]

FALCON_CORE_SOURCES = [
    "src/adapters/status.cc",
    "src/adapters/rng_control.cc",
    "src/adapters/liboqs/rng_control.cc",
    "src/adapters/falcon/sig_adapter.cc",
    "src/adapters/falcon/signed_message_adapter.cc",
    "src/mutators/envelope.cc",
    "src/mutators/scheme_mutation.cc",
    "src/mutators/falcon_layout.cc",
    "src/mutators/falcon_mutator.cc",
    "src/oracles/expected_relation.cc",
    "src/oracles/oracle_spec.cc",
    "src/oracles/oracle_record.cc",
    "src/oracles/oracle_result.cc",
    "src/oracles/scheme_claims.cc",
    "src/oracles/metamorphic_spec.cc",
    "src/oracles/falcon_executor.cc",
]


def falcon_sources_present() -> bool:
    return (FALCON_REF / "falcon.h").is_file() and (FALCON_REF / "falcon.c").is_file()


def require_falcon_sources() -> None:
    import pytest

    if not falcon_sources_present():
        pytest.skip("vendored Falcon reference is not present (projects/FALCON/reference)")


def compile_reference_objects(out_dir: Path) -> list[Path]:
    objects: list[Path] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in REFERENCE_SOURCES:
        obj = out_dir / f"{name}.o"
        if not obj.is_file():
            subprocess.run(
                [CC, "-O2", "-g", f"-I{FALCON_REF}", "-c", str(FALCON_REF / f"{name}.c"), "-o", str(obj)],
                check=True,
                capture_output=True,
            )
        objects.append(obj)
    kat_obj = out_dir / "katrng.o"
    if not kat_obj.is_file():
        subprocess.run(
            [CC, "-O2", "-g", f"-I{FALCON_KAT}", "-c", str(FALCON_KAT / "katrng.c"), "-o", str(kat_obj)],
            check=True,
            capture_output=True,
        )
    objects.append(kat_obj)
    return objects


def compile_hook_cli(out_dir: Path) -> Path:
    require_falcon_sources()
    binary = out_dir / "falcon_hook_cli"
    objects = compile_reference_objects(out_dir)
    if not binary.is_file():
        subprocess.run(
            [
                CXX,
                "-std=c++17",
                "-O2",
                "-g",
                "-Isrc",
                f"-I{FALCON_REF}",
                f"-I{FALCON_KAT}",
                "-DPQCFUZZ_HAVE_FALCON",
                "tests/falcon_hook_cli.cc",
                "src/adapters/falcon/falcon_test_hooks.cc",
                "src/adapters/falcon/signed_message_adapter.cc",
                "src/adapters/status.cc",
                "src/adapters/rng_control.cc",
                "src/adapters/liboqs/rng_control.cc",
                *[str(obj) for obj in objects],
                "-lm",
                "-o",
                str(binary),
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
        )
    return binary


def compile_test_main(
    tmp_path: Path,
    source: str,
    *,
    extra_sources: list[str] | None = None,
    extra_includes: list[str] | None = None,
    extra_defines: list[str] | None = None,
    link_reference: bool = False,
    reference_dir: Path | None = None,
    flags: list[str] | None = None,
) -> Path:
    """Compile a Falcon C++ test main; returns the binary path."""
    main = tmp_path / "falcon_test_main.cc"
    main.write_text(textwrap.dedent(source), encoding="utf-8")
    binary = tmp_path / "falcon_test_main"
    objects: list[Path] = []
    include_flags = ["-Isrc"]
    for include in extra_includes or []:
        include_flags.append(f"-I{include}")
    defines = list(extra_defines or [])
    if link_reference:
        require_falcon_sources()
        ref_dir = reference_dir or (tmp_path / "falcon-ref-obj")
        objects = compile_reference_objects(ref_dir)
        include_flags.extend([f"-I{FALCON_REF}", f"-I{FALCON_KAT}"])
        defines.append("PQCFUZZ_HAVE_FALCON")
    command = [
        CXX,
        "-std=c++17",
        *(flags if flags is not None else ["-O1", "-g"]),
        *include_flags,
        *[f"-D{define}" for define in defines],
        str(main),
        *(extra_sources if extra_sources is not None else FALCON_CORE_SOURCES),
        *[str(obj) for obj in objects],
        "-lm",
        "-o",
        str(binary),
    ]
    subprocess.run(command, cwd=REPO_ROOT, check=True, capture_output=True)
    return binary


def run_command(binary: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(binary), *args], cwd=REPO_ROOT, check=True, capture_output=True, text=True)

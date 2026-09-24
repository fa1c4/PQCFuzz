"""Shared compile helpers for the NTRU oracle/model test lanes."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
NTRU_REF = REPO_ROOT / "projects" / "NTRU" / "reference"
NTRU_KAT = REPO_ROOT / "projects" / "NTRU" / "kat"
CXX = os.environ.get("CXX", "clang++")
CC = os.environ.get("CC", "clang")

# algorithm -> (source dir, symbol namespace, implementation id)
PARAMS = {
    "NTRU-HPS-2048-509": ("ntruhps2048509", "ntru_hps509_", "ntru_reference_ntru_hps_2048_509"),
    "NTRU-HPS-2048-677": ("ntruhps2048677", "ntru_hps677_", "ntru_reference_ntru_hps_2048_677"),
    "NTRU-HPS-4096-821": ("ntruhps4096821", "ntru_hps821_", "ntru_reference_ntru_hps_4096_821"),
    "NTRU-HRSS-701": ("ntruhrss701", "ntru_hrss701_", "ntru_reference_ntru_hrss_701"),
}

NTRU_CORE_SOURCES = [
    "src/adapters/status.cc",
    "src/adapters/rng_control.cc",
    "src/adapters/liboqs/rng_control.cc",
    "src/mutators/envelope.cc",
    "src/mutators/sha3.cc",
    "src/mutators/scheme_mutation.cc",
    "src/mutators/ntru_layout.cc",
    "src/mutators/ntru_mutator.cc",
    "src/oracles/expected_relation.cc",
    "src/oracles/oracle_spec.cc",
    "src/oracles/oracle_record.cc",
    "src/oracles/oracle_result.cc",
    "src/oracles/scheme_claims.cc",
    "src/oracles/metamorphic_spec.cc",
    "src/oracles/ntru_executor.cc",
]


def ntru_sources_present() -> bool:
    return (NTRU_REF / "ntruhps2048509" / "kem.c").is_file() and (NTRU_KAT / "katrng.c").is_file()


def require_ntru_sources() -> None:
    import pytest

    if not ntru_sources_present():
        pytest.skip("vendored NTRU reference is not present (projects/NTRU/reference)")


def reference_sources(algorithm: str) -> list[Path]:
    source_dir = NTRU_REF / PARAMS[algorithm][0]
    return sorted(path for path in source_dir.iterdir() if path.suffix == ".c")


def compile_reference_objects(algorithm: str, out_dir: Path, *, with_drbg: bool = True) -> list[Path]:
    source_dir, namespace, _ = PARAMS[algorithm]
    objects: list[Path] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    for source in sorted((NTRU_REF / source_dir).iterdir()):
        if source.suffix != ".c":
            continue
        obj = out_dir / f"{source.stem}.o"
        if not obj.is_file():
            subprocess.run(
                [
                    CC, "-O2", "-g", f"-I{NTRU_REF / source_dir}", f"-I{NTRU_KAT}",
                    f"-DCRYPTO_NAMESPACE(s)={namespace}##s",
                    "-c", str(source), "-o", str(obj),
                ],
                check=True,
                capture_output=True,
            )
        objects.append(obj)
    kat_obj = out_dir / "katrng.o"
    if not kat_obj.is_file():
        subprocess.run(
            [CC, "-O2", "-g", f"-I{NTRU_KAT}", "-c", str(NTRU_KAT / "katrng.c"), "-o", str(kat_obj)],
            check=True,
            capture_output=True,
        )
    if with_drbg:
        objects.append(kat_obj)
    return objects


def compile_hook_cli(algorithm: str, out_dir: Path) -> Path:
    require_ntru_sources()
    source_dir, namespace, _ = PARAMS[algorithm]
    binary = out_dir / f"ntru_hook_cli_{source_dir}"
    objects = compile_reference_objects(algorithm, out_dir / "obj")
    command = [
        CXX,
        "-std=c++17",
        "-O2",
        "-g",
        "-Isrc",
        f"-I{NTRU_REF / source_dir}",
        f"-I{NTRU_KAT}",
        "-DPQCFUZZ_HAVE_NTRU_REFERENCE",
        f"-DCRYPTO_NAMESPACE(s)={namespace}##s",
        "tests/ntru_hook_cli.cc",
        "src/adapters/ntru/reference_adapter.cc",
        *[str(obj) for obj in objects],
        "-o",
        str(binary),
    ]
    subprocess.run(command, cwd=REPO_ROOT, check=True, capture_output=True)
    return binary


def compile_adapter_binary(algorithm: str, tmp_path: Path, main_source: str) -> Path:
    """Compile a test main against the real per-parameter NTRU adapter."""
    require_ntru_sources()
    source_dir, namespace, implementation_id = PARAMS[algorithm]
    main = tmp_path / "ntru_main.cc"
    main.write_text(textwrap.dedent(main_source), encoding="utf-8")
    binary = tmp_path / "ntru_adapter_binary"
    objects = compile_reference_objects(algorithm, tmp_path / "obj", with_drbg=False)
    command = [
        CXX,
        "-std=c++17",
        "-O1",
        "-g",
        "-Isrc",
        f"-I{NTRU_REF / source_dir}",
        f"-I{NTRU_KAT}",
        "-DPQCFUZZ_HAVE_NTRU",
        f"-DCRYPTO_NAMESPACE(s)={namespace}##s",
        f"-DPQCFUZZ_NTRU_ALGORITHM=\"{algorithm}\"",
        f"-DPQCFUZZ_NTRU_IMPLEMENTATION_ID=\"{implementation_id}\"",
        str(main),
        *NTRU_CORE_SOURCES,
        "src/adapters/ntru/kem_adapter.cc",
        "src/adapters/ntru/ntru_randombytes_override.cc",
        *[str(obj) for obj in objects],
        "-o",
        str(binary),
    ]
    subprocess.run(command, cwd=REPO_ROOT, check=True, capture_output=True)
    return binary

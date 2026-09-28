"""Shared build helpers for the SNOVA oracle tests.

The real-implementation lane requires the pinned round-2 source tree under
projects/SNOVA/reference (gitignored, fetched separately).  Tests that need it
skip with an explicit message when it is absent; the fake-adapter lane always
runs.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
SNOVA_SRC = REPO_ROOT / "projects" / "SNOVA" / "reference"

SNOVA_C_SOURCES = [
    "snova.c",
    "ct_functions.c",
    "shake/KeccakHash.c",
    "shake/KeccakSponge.c",
    "shake/KeccakP-1600-opt64.c",
    "shake/SimpleFIPS202.c",
    "shake/snova_shake_ref.c",
    "aes/aes_c.c",
    "aes/snova_aes.c",
]

import json

SNOVA_ALGORITHM_SETS: Dict[str, Dict[str, object]] = {}
_profile_path = REPO_ROOT / "src" / "config" / "scheme_profiles" / "snova.json"
if _profile_path.is_file():
    for _entry in json.loads(_profile_path.read_text(encoding="utf-8"))["parameter_sets"]:
        SNOVA_ALGORITHM_SETS[_entry["algorithm"]] = {
            "v": _entry["snova_v"],
            "o": _entry["snova_o"],
            "l": _entry["snova_l"],
            "pk_expand_shake": _entry["pk_expand_shake"],
            "category": _entry["category"],
        }


def have_reference_source() -> bool:
    return all((SNOVA_SRC / source).is_file() for source in SNOVA_C_SOURCES)


def reference_skip_reason() -> str:
    return (
        "pinned SNOVA round-2 source is not vendored under projects/SNOVA/reference; "
        "fetch PQCLAB-SNOVA/SNOVA @ 13182903755ade177e02d1fea77f0bd2e1e1a280"
    )


def parameter_defines(algorithm: str, sk_format: str, category: int = 1) -> List[str]:
    info = SNOVA_ALGORITHM_SETS[algorithm]
    return [
        f"v_SNOVA={info['v']}",
        f"o_SNOVA={info['o']}",
        f"l_SNOVA={info['l']}",
        f"PK_EXPAND_SHAKE={info['pk_expand_shake']}",
        "OPTIMISATION=0",
        "FIXED_ABQ=2",
        "sk_is_seed=1" if sk_format == "SSK" else "sk_is_seed=0",
    ]


def compile_with_snova(
    tmp_path: Path,
    algorithm: str,
    sk_format: str,
    main_source: Path,
    *,
    extra_sources: Optional[Sequence[Path]] = None,
    cxx: Optional[str] = None,
    extra_defines: Optional[Sequence[str]] = None,
    sanitizers: bool = False,
) -> Path:
    """Compile one SNOVA parameter set + adapter + `main_source` into a binary."""
    if not have_reference_source():
        raise FileNotFoundError(reference_skip_reason())
    tmp_path.mkdir(parents=True, exist_ok=True)
    info = SNOVA_ALGORITHM_SETS[algorithm]
    defines = parameter_defines(algorithm, sk_format, int(info.get("category", 1)))
    defines.append(f'CRYPTO_ALGNAME="SNOVA_test"')
    defines.append("PQCFUZZ_HAVE_SNOVA")
    defines.append(f'PQCFUZZ_SNOVA_ALGORITHM="{algorithm}"')
    defines.append('PQCFUZZ_SNOVA_IMPLEMENTATION_BASE="snova_reference"')
    defines.append(f'PQCFUZZ_SNOVA_TEST_ID="snova_reference_{sk_format.lower()}"')
    if extra_defines:
        defines.extend(extra_defines)
    cc = os.environ.get("CC", "clang")
    cxx_bin = cxx or os.environ.get("CXX", "clang++")
    cflags = ["-O1", "-g", "-DSKIP_ASSERT", f"-I{SNOVA_SRC}", "-Isrc"]
    if sanitizers:
        cflags.append("-fsanitize=address,undefined")
    objects: List[Path] = []
    for source in SNOVA_C_SOURCES:
        obj = tmp_path / (source.replace("/", "_") + ".o")
        subprocess.run(
            [cc, "-std=c11", *cflags, *[f"-D{d}" for d in defines], "-c", str(SNOVA_SRC / source), "-o", str(obj)],
            cwd=REPO_ROOT,
            check=True,
        )
        objects.append(obj)
    adapter_obj = tmp_path / "sig_adapter.o"
    subprocess.run(
        [
            cxx_bin,
            "-std=c++17",
            *cflags,
            *[f"-D{d}" for d in defines],
            "-c",
            str(REPO_ROOT / "src" / "adapters" / "snova" / "sig_adapter.cc"),
            "-o",
            str(adapter_obj),
        ],
        cwd=REPO_ROOT,
        check=True,
    )
    objects.append(adapter_obj)
    rng_objects: List[Path] = []
    for rel in ("src/adapters/status.cc", "src/adapters/rng_control.cc", "src/adapters/liboqs/rng_control.cc"):
        obj = tmp_path / (rel.replace("/", "_") + ".o")
        subprocess.run(
            [cxx_bin, "-std=c++17", *cflags, "-c", str(REPO_ROOT / rel), "-o", str(obj)],
            cwd=REPO_ROOT,
            check=True,
        )
        rng_objects.append(obj)
    binary = tmp_path / "snova_probe"
    command = [cxx_bin, "-std=c++17", *cflags, str(main_source)]
    if extra_sources:
        command.extend(str(source) for source in extra_sources)
    command.extend(str(obj) for obj in objects)
    command.extend(str(obj) for obj in rng_objects)
    command.extend(["-o", str(binary)])
    subprocess.run(command, cwd=REPO_ROOT, check=True)
    return binary


def run_probe(binary: Path, commands: Sequence[str], *, timeout: int = 300) -> List[str]:
    completed = subprocess.run(
        [str(binary)],
        input="\n".join(commands) + "\n",
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )
    return [line for line in completed.stdout.splitlines() if line]


# Source list for executor-level tests.  It is deliberately smaller than
# tests/_test_sources.py CORE_EXECUTOR_SOURCES and omits every adapter getter
# so the test can link either the real SNOVA adapter or the fake one.
SNOVA_EXECUTOR_SOURCES = [
    "src/adapters/status.cc",
    "src/adapters/rng_control.cc",
    "src/adapters/liboqs/rng_control.cc",
    "src/mutators/ml_kem_layout.cc",
    "src/mutators/ml_kem_mutator.cc",
    "src/mutators/scheme_mutation.cc",
    "src/mutators/sha3.cc",
    "src/mutators/snova_layout.cc",
    "src/mutators/snova_mutator.cc",
    "src/oracles/expected_relation.cc",
    "src/oracles/oracle_spec.cc",
    "src/oracles/oracle_record.cc",
    "src/oracles/oracle_result.cc",
    "src/oracles/scheme_claims.cc",
    "src/oracles/metamorphic_spec.cc",
    "src/oracles/snova_public_map.cc",
    "src/oracles/snova_executor.cc",
    "src/triage/oracle_coverage.cc",
]


def compile_kat_with_snova(
    tmp_path: Path,
    algorithm: str,
    sk_format: str,
    main_source: Path,
) -> Path:
    """Compile the official KAT runner (nistkat/rng.c + reference sign.c)."""
    if not have_reference_source():
        raise FileNotFoundError(reference_skip_reason())
    tmp_path.mkdir(parents=True, exist_ok=True)
    info = SNOVA_ALGORITHM_SETS[algorithm]
    defines = parameter_defines(algorithm, sk_format, int(info.get("category", 1)))
    defines.append('CRYPTO_ALGNAME="SNOVA_test"')
    cc = os.environ.get("CC", "clang")
    cxx_bin = os.environ.get("CXX", "clang++")
    cflags = ["-O1", "-g", "-DSKIP_ASSERT", f"-I{SNOVA_SRC}", "-Isrc"]
    sources = list(SNOVA_C_SOURCES) + ["sign.c", "nistkat/rng.c"]
    objects: List[Path] = []
    for source in sources:
        obj = tmp_path / (source.replace("/", "_") + ".o")
        subprocess.run(
            [cc, "-std=c11", *cflags, *[f"-D{d}" for d in defines], "-c", str(SNOVA_SRC / source), "-o", str(obj)],
            cwd=REPO_ROOT,
            check=True,
        )
        objects.append(obj)
    binary = tmp_path / "snova_kat"
    subprocess.run(
        [cxx_bin, "-std=c++17", *cflags, *[f"-D{d}" for d in defines], str(main_source),
         *[str(obj) for obj in objects], "-o", str(binary)],
        cwd=REPO_ROOT,
        check=True,
    )
    return binary


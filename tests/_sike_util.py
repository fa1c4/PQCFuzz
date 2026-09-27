"""Shared compile helpers for the SIKE/SIDH oracle/model test lanes."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SIKE_ROOT = REPO_ROOT / "projects" / "SIKE_SIDH"
SIKE_SRC = SIKE_ROOT / "src"
SIKE_KAT = SIKE_ROOT / "kat"
CXX = os.environ.get("CXX", "clang++")
CC = os.environ.get("CC", "clang")

# algorithm -> parameter metadata for the pinned generic source.
PARAMS = {
    "SIKE-p434": {
        "source_dir": "P434",
        "api_header": "P434_api.h",
        "suffix": "p434",
        "e2": 216,
        "e3": 137,
        "np": 55,
        "nsk3": 28,
        "msg": 16,
        "pk_len": 330,
        "sk_len": 374,
        "ct_len": 346,
        "ss_len": 16,
        "sk_a_len": 27,
        "sk_b_len": 28,
        "shared_len": 110,
        "sidh_kex_impl": "sidh_reference_p434",
        "sike_impl": "sike_reference_p434",
    },
    "SIKE-p503": {
        "source_dir": "P503",
        "api_header": "P503_api.h",
        "suffix": "p503",
        "e2": 250,
        "e3": 159,
        "np": 63,
        "nsk3": 32,
        "msg": 24,
        "pk_len": 378,
        "sk_len": 434,
        "ct_len": 402,
        "ss_len": 24,
        "sk_a_len": 32,
        "sk_b_len": 32,
        "shared_len": 126,
        "sidh_kex_impl": "sidh_reference_p503",
        "sike_impl": "sike_reference_p503",
    },
    "SIKE-p610": {
        "source_dir": "P610",
        "api_header": "P610_api.h",
        "suffix": "p610",
        "e2": 305,
        "e3": 192,
        "np": 77,
        "nsk3": 38,
        "msg": 24,
        "pk_len": 462,
        "sk_len": 524,
        "ct_len": 486,
        "ss_len": 24,
        "sk_a_len": 39,
        "sk_b_len": 38,
        "shared_len": 154,
        "sidh_kex_impl": "sidh_reference_p610",
        "sike_impl": "sike_reference_p610",
    },
    "SIKE-p751": {
        "source_dir": "P751",
        "api_header": "P751_api.h",
        "suffix": "p751",
        "e2": 372,
        "e3": 239,
        "np": 94,
        "nsk3": 48,
        "msg": 32,
        "pk_len": 564,
        "sk_len": 644,
        "ct_len": 596,
        "ss_len": 32,
        "sk_a_len": 47,
        "sk_b_len": 48,
        "shared_len": 188,
        "sidh_kex_impl": "sidh_reference_p751",
        "sike_impl": "sike_reference_p751",
    },
}

# SIDH counterpart names share the same parameter metadata.
for _sike_name, _entry in list(PARAMS.items()):
    _sidh_name = _sike_name.replace("SIKE-", "SIDH-")
    PARAMS[_sidh_name] = {**_entry, "sidh_impl": _entry["sidh_kex_impl"]}


def _defines_for(algorithm: str, *, reference: bool, adapter: bool) -> list[str]:
    entry = PARAMS[algorithm]
    suffix = entry["suffix"]
    defines = [
        f'PQCFUZZ_SIKE_API_HEADER="{entry["api_header"]}"',
        f'PQCFUZZ_SIDH_API_HEADER="{entry["api_header"]}"',
        f'SIKE_API_HEADER="{entry["api_header"]}"',
        f"SIKE_E2_BITS={entry['e2']}",
        f"MSG_BYTES={entry['msg']}",
        f"SECRETKEY_B_BYTES={entry['nsk3']}",
        f"crypto_kem_keypair=crypto_kem_keypair_SIKE{suffix}",
        f"crypto_kem_enc=crypto_kem_enc_SIKE{suffix}",
        f"crypto_kem_dec=crypto_kem_dec_SIKE{suffix}",
        f"random_mod_order_A=random_mod_order_A_SIDH{suffix}",
        f"random_mod_order_B=random_mod_order_B_SIDH{suffix}",
        f"EphemeralKeyGeneration_A=EphemeralKeyGeneration_A_SIDH{suffix}",
        f"EphemeralKeyGeneration_B=EphemeralKeyGeneration_B_SIDH{suffix}",
        f"EphemeralSecretAgreement_A=EphemeralSecretAgreement_A_SIDH{suffix}",
        f"EphemeralSecretAgreement_B=EphemeralSecretAgreement_B_SIDH{suffix}",
    ]
    if adapter:
        defines += [
            "PQCFUZZ_HAVE_SIKE",
            "PQCFUZZ_HAVE_SIDH",
            f'PQCFUZZ_SIKE_ALGORITHM="SIKE-{suffix}"',
            f'PQCFUZZ_SIKE_IMPLEMENTATION_ID="sike_reference_{suffix}"',
            f'PQCFUZZ_SIDH_ALGORITHM="SIDH-{suffix}"',
            f'PQCFUZZ_SIDH_IMPLEMENTATION_ID="sidh_reference_{suffix}"',
            "PQCFUZZ_SIKE_KEYPAIR=crypto_kem_keypair_SIKE" + suffix,
            "PQCFUZZ_SIKE_ENC=crypto_kem_enc_SIKE" + suffix,
            "PQCFUZZ_SIKE_DEC=crypto_kem_dec_SIKE" + suffix,
            "PQCFUZZ_SIDH_KEYGEN_A=EphemeralKeyGeneration_A_SIDH" + suffix,
            "PQCFUZZ_SIDH_KEYGEN_B=EphemeralKeyGeneration_B_SIDH" + suffix,
            "PQCFUZZ_SIDH_DERIVE_A=EphemeralSecretAgreement_A_SIDH" + suffix,
            "PQCFUZZ_SIDH_DERIVE_B=EphemeralSecretAgreement_B_SIDH" + suffix,
            "PQCFUZZ_SIDH_RANDOM_MOD_A=random_mod_order_A_SIDH" + suffix,
            "PQCFUZZ_SIDH_RANDOM_MOD_B=random_mod_order_B_SIDH" + suffix,
        ]
    if reference:
        defines += [
            "PQCFUZZ_HAVE_SIKE_REFERENCE",
            "PQCFUZZ_SIDH_DERIVE_B=EphemeralSecretAgreement_B_SIDH" + suffix,
            "PQCFUZZ_SIDH_KEYGEN_A=EphemeralKeyGeneration_A_SIDH" + suffix,
            "PQCFUZZ_SIDH_KEYGEN_B=EphemeralKeyGeneration_B_SIDH" + suffix,
        ]
    return defines


def sike_sources_present() -> bool:
    return (SIKE_SRC / "P434" / "P434.c").is_file() and (SIKE_KAT / "katrng.c").is_file()


def require_sike_sources() -> None:
    import pytest

    if not sike_sources_present():
        pytest.skip("vendored PQCrypto-SIDH reference is not present (projects/SIKE_SIDH)")


def compile_reference_objects(algorithm: str, out_dir: Path, *, with_drbg: bool = True) -> list[Path]:
    require_sike_sources()
    entry = PARAMS[algorithm]
    source_dir = SIKE_SRC / entry["source_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    objects: list[Path] = []
    sources = [
        source_dir / f"{entry['source_dir']}.c",
        source_dir / "generic" / "fp_generic.c",
        SIKE_SRC / "sha3" / "fips202.c",
    ]
    for source in sources:
        obj = out_dir / f"{source.stem}.o"
        if not obj.is_file():
            subprocess.run(
                [
                    CC,
                    "-O1",
                    "-g",
                    "-D_GENERIC_",
                    "-D_AMD64_",
                    "-D__NIX__",
                    f"-I{source_dir}",
                    f"-I{SIKE_SRC}",
                    "-c",
                    str(source),
                    "-o",
                    str(obj),
                ],
                check=True,
                capture_output=True,
            )
        objects.append(obj)
    if with_drbg:
        kat_obj = out_dir / "katrng.o"
        if not kat_obj.is_file():
            subprocess.run(
                [
                    CC,
                    "-O1",
                    "-g",
                    "-Drandombytes=kat_randombytes",
                    "-Drandombytes_init=kat_randombytes_init",
                    f"-I{SIKE_KAT}",
                    "-c",
                    str(SIKE_KAT / "katrng.c"),
                    "-o",
                    str(kat_obj),
                ],
                check=True,
                capture_output=True,
            )
        objects.append(kat_obj)
    return objects


def compile_hook_cli(algorithm: str, out_dir: Path) -> Path:
    require_sike_sources()
    entry = PARAMS[algorithm]
    binary = out_dir / f"sike_sidh_hook_cli_{entry['suffix']}"
    objects = compile_reference_objects(algorithm, out_dir / "obj")
    command = [
        CXX,
        "-std=c++17",
        "-O1",
        "-g",
        "-Isrc",
        f"-I{SIKE_SRC / entry['source_dir']}",
        f"-I{SIKE_SRC}",
        f"-I{SIKE_KAT}",
        *[f"-D{define}" for define in _defines_for(algorithm, reference=True, adapter=False)],
        "tests/sike_sidh_hook_cli.cc",
        "src/adapters/sike/reference_adapter.cc",
        "src/mutators/sha3.cc",
        "src/adapters/rng_control.cc",
        "src/adapters/liboqs/rng_control.cc",
        "src/adapters/status.cc",
        *[str(obj) for obj in objects],
        "-o",
        str(binary),
    ]
    subprocess.run(command, cwd=REPO_ROOT, check=True, capture_output=True)
    return binary


SIKE_CORE_SOURCES = [
    "src/adapters/status.cc",
    "src/adapters/rng_control.cc",
    "src/adapters/liboqs/rng_control.cc",
    "src/mutators/envelope.cc",
    "src/mutators/sha3.cc",
    "src/mutators/scheme_mutation.cc",
    "src/mutators/sike_layout.cc",
    "src/mutators/sike_mutator.cc",
    "src/oracles/expected_relation.cc",
    "src/oracles/oracle_spec.cc",
    "src/oracles/oracle_record.cc",
    "src/oracles/oracle_result.cc",
    "src/oracles/scheme_claims.cc",
    "src/oracles/metamorphic_spec.cc",
    "src/oracles/sike_executor.cc",
    "src/oracles/sidh_executor.cc",
    "src/adapters/sike/kem_adapter.cc",
    "src/adapters/sike/reference_adapter.cc",
    "src/adapters/sidh/kex_adapter.cc",
]


def compile_adapter_binary(
    algorithm: str,
    tmp_path: Path,
    main_source: str,
    *,
    with_reference: bool = True,
) -> Path:
    """Compile a test main against the real per-parameter SIKE and SIDH adapters."""
    require_sike_sources()
    entry = PARAMS[algorithm]
    main = tmp_path / "sike_main.cc"
    main.write_text(textwrap.dedent(main_source), encoding="utf-8")
    binary = tmp_path / "sike_adapter_binary"
    objects = compile_reference_objects(algorithm, tmp_path / "obj")
    defines = _defines_for(algorithm, reference=with_reference, adapter=True)
    command = [
        CXX,
        "-std=c++17",
        "-O1",
        "-g",
        "-Isrc",
        f"-I{SIKE_SRC / entry['source_dir']}",
        f"-I{SIKE_SRC}",
        f"-I{SIKE_KAT}",
        *[f"-D{define}" for define in defines],
        str(main),
        *SIKE_CORE_SOURCES,
        "src/adapters/sike/sike_randombytes_override.cc",
        *[str(obj) for obj in objects if "katrng" not in obj.name],
        "-o",
        str(binary),
    ]
    subprocess.run(command, cwd=REPO_ROOT, check=True, capture_output=True)
    return binary

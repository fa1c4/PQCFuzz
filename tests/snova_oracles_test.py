#!/usr/bin/env python3
"""SNOVA oracle tests: routing, specs, envelope/recipe, layout reach, honest
target runs, fake-adapter detection and the official KAT subset."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from tests import _snova_util as util  # noqa: E402
from src.jobs import generated_config_writer as writer  # noqa: E402
from src.pairing.pair_alg_loader import enabled_pairs_for_family, load_pair_alg  # noqa: E402
from src.replay.replay_one import ALGORITHM_BY_ENUM, ALGORITHM_ENUM_BY_NAME, ORACLE_BY_ENUM, ORACLE_ENUM_BY_NAME  # noqa: E402

PAIR_ALG = REPO_ROOT / "src" / "config" / "pair_alg.snova.json"
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "snova" / "kat_reference.json"

ALGORITHM_ORDER = [
    "SNOVA-R2-37-17-16-2-AES",
    "SNOVA-R2-37-17-16-2-SHAKE",
    "SNOVA-R2-25-8-16-3-AES",
    "SNOVA-R2-25-8-16-3-SHAKE",
    "SNOVA-R2-24-5-16-4-AES",
    "SNOVA-R2-24-5-16-4-SHAKE",
    "SNOVA-R2-56-25-16-2-AES",
    "SNOVA-R2-56-25-16-2-SHAKE",
    "SNOVA-R2-49-11-16-3-AES",
    "SNOVA-R2-49-11-16-3-SHAKE",
    "SNOVA-R2-37-8-16-4-AES",
    "SNOVA-R2-37-8-16-4-SHAKE",
    "SNOVA-R2-24-5-16-5-AES",
    "SNOVA-R2-24-5-16-5-SHAKE",
    "SNOVA-R2-75-33-16-2-AES",
    "SNOVA-R2-75-33-16-2-SHAKE",
    "SNOVA-R2-66-15-16-3-AES",
    "SNOVA-R2-66-15-16-3-SHAKE",
    "SNOVA-R2-60-10-16-4-AES",
    "SNOVA-R2-60-10-16-4-SHAKE",
    "SNOVA-R2-29-6-16-5-AES",
    "SNOVA-R2-29-6-16-5-SHAKE",
]

SNOVA_ORACLE_NAMES = [
    "snova_kat",
    "snova_local_sign_verify",
    "snova_cross_verify",
    "snova_message_salt_binding",
    "snova_public_seed_binding",
    "snova_exact_lengths",
    "snova_nibble_encoding",
    "snova_gf16_arithmetic",
    "snova_public_map",
    "snova_key_alignment",
    "snova_round2_terms",
    "snova_public_expansion",
    "snova_fixed_abq",
    "snova_ssk_esk_equivalence",
    "snova_gauss_retry",
    "snova_rng_replay",
    "snova_malformed_key_state",
    "snova_backend_profile_gate",
    "snova_fault_checks",
    "snova_timing_resources",
]


def _run_compile(tmp_path: Path, source: str, sources: list[str], defines: list[str] | None = None) -> Path:
    main = tmp_path / "main.cc"
    main.write_text(source)
    binary = tmp_path / "test_binary"
    command = [
        os.environ.get("CXX", "clang++"),
        "-std=c++17",
        "-O0",
        "-g",
        "-Isrc",
        *[f"-D{d}" for d in (defines or [])],
        str(main),
        *sources,
        "-o",
        str(binary),
    ]
    subprocess.run(command, cwd=REPO_ROOT, check=True)
    return binary


def _run(binary: Path, args: list[str] | None = None) -> list[str]:
    completed = subprocess.run([str(binary), *(args or [])], cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    return [line for line in completed.stdout.splitlines() if line]


# ---------------------------------------------------------------------------
# Routing and metadata.
# ---------------------------------------------------------------------------
def test_pair_alg_routing_and_job_generation() -> None:
    document = load_pair_alg(PAIR_ALG)
    pairs = enabled_pairs_for_family(document, "SNOVA")
    # 22 SSK-vs-ESK pairs plus 22 reference-vs-AVX2 second-build pairs.
    assert len(pairs) == 44
    avx2_pairs = 0
    for pair in pairs:
        assert pair["primitive_type"] == "sig"
        assert pair["exchange_contract"] == {"public_key_exchange": True, "signature_exchange": True}
        assert pair["left"]["abi"]["sk_len"] == 48
        if pair["provenance_relation"] == "same-source-reference-vs-avx2":
            avx2_pairs += 1
            assert pair["right"]["implementation_id"] == "snova_avx2_ssk"
            assert pair["right"]["abi"]["sk_len"] == 48
        else:
            assert pair["right"]["abi"]["sk_len"] > 48
        oracles = writer.oracle_ids_for_pair(pair)
        assert "snova_local_sign_verify" in oracles
        assert "snova_cross_verify" in oracles
        assert "snova_fault_checks" not in oracles  # P2 is opt-in
        assert writer.oracle_spec_for_pair(pair) == "src/oracles/specs/snova.json"
        subtests = writer.enabled_subtests_for_pair(pair)
        assert len(subtests) == len(oracles)
        assert all(entry["enabled"] for entry in subtests)
    assert avx2_pairs == 22
    assert ORACLE_ENUM_BY_NAME["snova_kat"] == 140
    assert ORACLE_ENUM_BY_NAME["snova_timing_resources"] == 159
    assert ALGORITHM_BY_ENUM[96] == "SNOVA-R2-37-17-16-2-AES"
    assert ALGORITHM_BY_ENUM[117] == "SNOVA-R2-29-6-16-5-SHAKE"
    for index, algorithm in enumerate(ALGORITHM_ORDER):
        assert ALGORITHM_ENUM_BY_NAME[algorithm] == 96 + index
        assert ALGORITHM_BY_ENUM[96 + index] == algorithm
    for value, name in ORACLE_BY_ENUM.items():
        if value >= 140:
            assert ORACLE_ENUM_BY_NAME.get(name) == value
    assert len(writer.oracle_ids_for_snova()) == 18


def test_snova_oracle_spec_shape() -> None:
    payload = json.loads((REPO_ROOT / "src" / "oracles" / "specs" / "snova.json").read_text())
    records = payload["oracles"]
    assert len(records) == 20
    seen = set()
    for record in records:
        assert record["algorithm_family"] == "SNOVA"
        assert record["primitive_type"] == "sig"
        assert record["evidence_class"] in {
            "NORMATIVE",
            "REFERENCE_DERIVED",
            "IMPLEMENTATION_OBSERVED",
            "ENGINEERING_RECOMMENDATION",
            "INFERENCE",
        }
        assert record["claim"]
        assert record["source_reference"]
        assert record["limitations"]
        assert record["controls"]["positive_control"]
        assert record["controls"]["negative_control"]
        assert record["property_ids"]
        assert record["oracle_id"] not in seen
        seen.add(record["oracle_id"])
    assert [record["oracle_id"] for record in records] == SNOVA_ORACLE_NAMES
    generated = (REPO_ROOT / "src" / "oracles" / "generated_fips_specs.inc").read_text()
    for name in SNOVA_ORACLE_NAMES:
        assert f'"{name}"' in generated


def test_snova_envelope_and_scheme_mutation_roundtrip(tmp_path: Path) -> None:
    index = (70000).to_bytes(4, "little")
    aux = (11).to_bytes(4, "little")
    source = f"""
#include <cassert>
#include <cstdio>
#include <string>
#include "mutators/envelope.h"
#include "mutators/scheme_mutation.h"
int main() {{
  for (int i = 0; i < {len(ALGORITHM_ORDER)}; ++i) {{
    const char *names[] = {{{",".join(f'"{n}"' for n in ALGORITHM_ORDER)}}};
    auto id = pqcfuzz::AlgorithmIdFromName(names[i]);
    assert(pqcfuzz::AlgorithmName(id) == std::string(names[i]));
  }}
  const char *oracles[] = {{{",".join(f'"{n}"' for n in SNOVA_ORACLE_NAMES)}}};
  for (const char *name : oracles) {{
    auto id = pqcfuzz::OracleIdFromName(name);
    assert(pqcfuzz::OracleName(id) == std::string(name));
  }}
  pqcfuzz::SchemeMutation mutation;
  mutation.op = pqcfuzz::SchemeMutationOp::kSetCoefficient;
  mutation.field = pqcfuzz::SchemeMutationField::kSnovaSignatureNibble;
  mutation.index = 70000;
  mutation.aux = 11;
  mutation.payload = {{0x0F}};
  auto encoded = pqcfuzz::EncodeSchemeMutation(mutation);
  assert(encoded[0] == 8);
  assert(encoded[1] == 42);
  assert(encoded[2] == 0x70 && encoded[3] == 0x11);
  pqcfuzz::SchemeMutation decoded;
  std::string error;
  assert(pqcfuzz::DecodeSchemeMutation(encoded, &decoded, &error));
  assert(decoded.index == 70000 && decoded.aux == 11);
  auto public_plan = pqcfuzz::EncodeSchemeMutation({{pqcfuzz::SchemeMutationOp::kSetCoefficient,
      pqcfuzz::SchemeMutationField::kSnovaPublicKeyP22Nibble, 1, 2, {{0x03}}}});
  assert(public_plan[1] == 45);
  printf("ENVELOPE_OK\\n");
  return 0;
}}
"""
    binary = _run_compile(
        tmp_path,
        source,
        ["src/mutators/envelope.cc", "src/mutators/scheme_mutation.cc"],
    )
    assert _run(binary) == ["ENVELOPE_OK"]


def test_snova_layout_offsets_reach_beyond_65535(tmp_path: Path) -> None:
    source = """
#include <cassert>
#include <cstdio>
#include <vector>
#include "mutators/snova_mutator.h"
int main() {
  pqcfuzz::SnovaParams params{};
  assert(pqcfuzz::GetSnovaParams("SNOVA-R2-75-33-16-2-AES", &params));
  assert(params.pk_len == 71890);
  assert(params.esk_len == 704532);
  std::vector<uint8_t> pk(params.pk_len, 0);
  for (size_t offset : {size_t(0), size_t(65535), size_t(65536), size_t(71889)}) {
    auto records = pqcfuzz::MutateSnovaAbsoluteByte(params, offset, 0x01, &pk);
    assert(records.size() == 1 && records[0].effective);
    assert(pk[offset] == 0x01);
    pk[offset] = 0x00;
  }
  auto out_of_range = pqcfuzz::MutateSnovaAbsoluteByte(params, params.pk_len, 0x01, &pk);
  assert(out_of_range.size() == 1 && out_of_range[0].skipped);
  std::vector<uint8_t> esk(params.esk_len, 0);
  auto tail = pqcfuzz::MutateSnovaAbsoluteByte(params, params.esk_len - 1, 0x80, &esk);
  assert(tail[0].effective && esk[params.esk_len - 1] == 0x80);
  // Full 11-parameter ABI table must be internally consistent.
  for (const auto *name : {"SNOVA-R2-37-17-16-2-AES", "SNOVA-R2-29-6-16-5-SHAKE"}) {
    pqcfuzz::SnovaParams p{};
    assert(pqcfuzz::GetSnovaParams(name, &p));
    assert(p.sig_max_len == (p.n_matrices * p.sq_rank + 1) / 2 + 16);
    assert(p.hash_bytes == (p.m_matrices * p.sq_rank + 1) / 2);
  }
  printf("LAYOUT_OK\\n");
  return 0;
}
"""
    binary = _run_compile(
        tmp_path,
        source,
        [
            "src/mutators/ml_kem_layout.cc",
            "src/mutators/ml_kem_mutator.cc",
            "src/mutators/scheme_mutation.cc",
            "src/mutators/snova_layout.cc",
            "src/mutators/snova_mutator.cc",
        ],
    )
    assert _run(binary) == ["LAYOUT_OK"]


# ---------------------------------------------------------------------------
# Executor lanes.
# ---------------------------------------------------------------------------
def _executor_binary(tmp_path: Path, algorithm: str, fake: bool) -> Path:
    extra: list[str] = []
    if fake:
        extra.append("tests/fake_adapters/fake_snova.cc")
    else:
        info = util.SNOVA_ALGORITHM_SETS[algorithm]
        defines = util.parameter_defines(algorithm, "ESK", int(info.get("category", 1)))
        defines.append("PQCFUZZ_HAVE_SNOVA")
        defines.append(f'PQCFUZZ_SNOVA_ALGORITHM="{algorithm}"')
        defines.append('PQCFUZZ_SNOVA_IMPLEMENTATION_BASE="snova_reference"')
        adapter_obj = tmp_path / "snova_adapter.o"
        cxx = os.environ.get("CXX", "clang++")
        cc = os.environ.get("CC", "clang")
        cflags = ["-O1", "-g", "-DSKIP_ASSERT", f"-I{util.SNOVA_SRC}", "-Isrc"]
        for source in util.SNOVA_C_SOURCES:
            obj = tmp_path / (source.replace("/", "_") + ".o")
            subprocess.run(
                [cc, "-std=c11", *cflags, *[f"-D{d}" for d in defines], "-c", str(util.SNOVA_SRC / source), "-o", str(obj)],
                cwd=REPO_ROOT,
                check=True,
            )
            extra.append(str(obj))
        subprocess.run(
            [cxx, "-std=c++17", *cflags, *[f"-D{d}" for d in defines], "-c",
             "src/adapters/snova/sig_adapter.cc", "-o", str(adapter_obj)],
            cwd=REPO_ROOT,
            check=True,
        )
        extra.append(str(adapter_obj))
    return _run_compile(tmp_path, "// no main", ["tests/snova_executor_main.cc", *util.SNOVA_EXECUTOR_SOURCES, *extra])


def test_snova_real_adapter_honest_oracles(tmp_path: Path) -> None:
    if not util.have_reference_source():
        pytest.skip(util.reference_skip_reason())
    binary = _executor_binary(tmp_path, "SNOVA-R2-24-5-16-4-AES", fake=False)
    lines = _run(binary, ["SNOVA-R2-24-5-16-4-AES", "snova_reference_ssk", "snova_reference_esk"])
    assert "UNAVAILABLE" not in lines
    summaries = [line for line in lines if line.startswith("ORACLE ")]
    assert len(summaries) == 13
    for line in summaries:
        assert "findings=0" in line, line
    # The same run must replay identically.
    assert _run(binary, ["SNOVA-R2-24-5-16-4-AES", "snova_reference_ssk", "snova_reference_esk"]) == lines
    subtests = [line for line in lines if line.startswith("SUBTEST ")]
    assert any("ssk_esk_equivalence" in line for line in subtests)


def test_snova_executor_detects_always_accepting_adapter(tmp_path: Path) -> None:
    binary = _executor_binary(tmp_path, "SNOVA-R2-24-5-16-4-AES", fake=True)
    lines = _run(
        binary,
        [
            "SNOVA-R2-24-5-16-4-AES",
            "fake_snova_esk",
            "fake_snova_esk",
            "snova_message_salt_binding",
            "snova_public_seed_binding",
            "snova_exact_lengths",
            "snova_nibble_encoding",
            "snova_public_map",
            "snova_malformed_key_state",
        ],
    )
    all_text = "\n".join(lines)
    assert "UNAVAILABLE" not in all_text
    for oracle_id in (
        "snova_message_salt_binding",
        "snova_public_seed_binding",
        "snova_exact_lengths",
        "snova_public_map",
        "snova_malformed_key_state",
    ):
        assert f"FINDING {oracle_id}" in all_text, all_text
    assert "potential_crypto_vuln" in all_text


# ---------------------------------------------------------------------------
# Official KAT subset.
# ---------------------------------------------------------------------------
KAT_SUBSET = [
    ("SNOVA-R2-24-5-16-4-AES", "SSK"),
    ("SNOVA-R2-24-5-16-4-SHAKE", "ESK"),
    ("SNOVA-R2-25-8-16-3-AES", "SSK"),
    ("SNOVA-R2-75-33-16-2-SHAKE", "SSK"),
]


@pytest.mark.parametrize("algorithm,sk_format", KAT_SUBSET)
def test_official_kat_fixture_reproduces_records(tmp_path: Path, algorithm: str, sk_format: str) -> None:
    if not util.have_reference_source():
        pytest.skip(util.reference_skip_reason())
    fixture = json.loads(FIXTURE.read_text())
    record = next(
        entry for entry in fixture["records"] if entry["algorithm"] == algorithm and entry["sk_format"] == sk_format
    )
    binary = util.compile_kat_with_snova(tmp_path, algorithm, sk_format, REPO_ROOT / "tests" / "snova_kat_main.cc")
    lines = util.run_probe(binary, [f"KAT {record['seed_hex']} {record['msg_hex']}"], timeout=900)
    parts = lines[0].split()
    assert parts[0] == "KAT" and parts[1] == "0", lines[0][-200:]
    pk = bytes.fromhex(parts[2])
    sk = bytes.fromhex(parts[3])
    smlen = int(parts[4])
    sm = bytes.fromhex(parts[5])
    assert pk.hex() == record["pk_hex"]
    assert smlen == record["smlen"]
    assert sm.hex() == record["sm_hex"]
    if sk_format == "SSK":
        assert sk.hex() == record["sk_hex"]
    else:
        import hashlib

        assert hashlib.sha256(sk).hexdigest() == record["sk_sha256"]

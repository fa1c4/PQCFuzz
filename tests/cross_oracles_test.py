#!/usr/bin/env python3
"""CROSS oracle integration tests: routing, envelope, executor, detection."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tests import _test_sources  # noqa: E402
from tests.models import cross_model as model  # noqa: E402

CROSS_INCLUDE = REPO_ROOT / "projects" / "CROSS" / "reference" / "include"
CROSS_LIB = REPO_ROOT / "projects" / "CROSS" / "reference" / "lib"
CROSS_OBJECT_NAMES = (
    "CROSS",
    "csprng_hash",
    "fips202",
    "keccakf1600",
    "merkle",
    "pack_unpack",
    "seedtree",
    "sign",
)


def _compile_cross_objects(tmp_path: Path, defines: list[str]) -> list[str]:
    obj_dir = tmp_path / "cross-obj"
    obj_dir.mkdir(parents=True, exist_ok=True)
    objects = []
    for name in CROSS_OBJECT_NAMES:
        obj = obj_dir / f"{name}.o"
        subprocess.run(
            [
                "clang",
                "-std=c11",
                "-O1",
                "-g",
                "-DSKIP_ASSERT",
                f"-I{CROSS_INCLUDE}",
                *defines,
                "-c",
                str(CROSS_LIB / f"{name}.c"),
                "-o",
                str(obj),
            ],
            check=True,
            cwd=REPO_ROOT,
        )
        objects.append(str(obj))
    return objects


def _run_cpp(
    tmp_path: Path,
    source: str,
    *,
    defines: list[str] | None = None,
    sources: list[str] | None = None,
    include_dirs: list[Path] | None = None,
) -> subprocess.CompletedProcess[str]:
    main = tmp_path / "main.cc"
    binary = tmp_path / "case"
    main.write_text(textwrap.dedent(source), encoding="utf-8")
    command = [
        "clang++",
        "-std=c++17",
        "-O1",
        "-g",
        "-I" + str(REPO_ROOT / "src"),
        *[f"-I{path}" for path in include_dirs or []],
        *([f"-D{define}" for define in defines or []]),
        str(main),
        *(sources if sources is not None else _test_sources.CORE_EXECUTOR_SOURCES),
        "-o",
        str(binary),
    ]
    compile_result = subprocess.run(command, capture_output=True, text=True, cwd=REPO_ROOT)
    if compile_result.returncode != 0:
        raise RuntimeError(f"C++ compile failed:\n{compile_result.stderr}")
    return subprocess.run([str(binary)], capture_output=True, text=True, cwd=REPO_ROOT)


def test_pair_alg_routing_and_job_generation(tmp_path: Path) -> None:
    src_root = REPO_ROOT / "src"
    sys.path.insert(0, str(src_root))
    from jobs.generated_config_writer import (  # noqa: PLC0415
        ORACLE_ENUM_BY_NAME,
        enabled_subtests_for_pair,
        oracle_ids_for_pair,
        oracle_spec_for_pair,
    )
    from pairing.pair_alg_loader import enabled_pairs_for_family, load_pair_alg  # noqa: PLC0415
    from replay.replay_one import ALGORITHM_BY_ENUM, ORACLE_BY_ENUM  # noqa: PLC0415

    document = load_pair_alg(REPO_ROOT / "src" / "config" / "pair_alg.cross.json")
    pairs = enabled_pairs_for_family(document, "CROSS")
    assert len(pairs) == 18
    for pair in pairs:
        assert pair["algorithm_family"] == "CROSS"
        assert pair["primitive_type"] == "sig"
        oracles = oracle_ids_for_pair(pair)
        assert "cross_local_sign_verify" in oracles
        assert "cross_cross_verify" in oracles
        assert oracle_spec_for_pair(pair) == "src/oracles/specs/cross.json"
        subtests = enabled_subtests_for_pair(pair)
        cross_verify = [item for item in subtests if item["oracle_id"] == "cross_cross_verify"][0]
        assert cross_verify["enabled"] is False

    assert ORACLE_ENUM_BY_NAME["cross_kat"] == 120
    assert ORACLE_ENUM_BY_NAME["cross_timing"] == 138
    assert ALGORITHM_BY_ENUM[64] == "CROSS-RSDP-1-FAST"
    assert ALGORITHM_BY_ENUM[81] == "CROSS-RSDPG-5-SMALL"
    assert ORACLE_BY_ENUM[120] == "cross_kat"
    assert ORACLE_BY_ENUM[138] == "cross_timing"


def test_cross_oracle_spec_shape() -> None:
    payload = json.loads((REPO_ROOT / "src" / "oracles" / "specs" / "cross.json").read_text(encoding="utf-8"))
    oracles = payload["oracles"]
    assert len(oracles) == 19
    ids = {entry["oracle_id"] for entry in oracles}
    assert "cross_kat" in ids and "cross_timing" in ids
    for entry in oracles:
        assert entry["algorithm_family"] == "CROSS"
        assert entry["primitive_type"] == "sig"
        assert entry["evidence_class"] in {
            "NORMATIVE",
            "REFERENCE_DERIVED",
            "IMPLEMENTATION_OBSERVED",
            "ENGINEERING_RECOMMENDATION",
            "INFERENCE",
        }
        assert entry["source_reference"]
        assert entry["limitations"]
        assert entry["controls"]["positive_control"]

    generated = (REPO_ROOT / "src" / "oracles" / "generated_fips_specs.inc").read_text(encoding="utf-8")
    for entry in oracles:
        assert f'"{entry["oracle_id"]}"' in generated


def test_cross_envelope_and_scheme_mutation_roundtrip(tmp_path: Path) -> None:
    algorithms = sorted(model.load_profiles())
    oracle_names = [
        "cross_kat",
        "cross_local_sign_verify",
        "cross_cross_verify",
        "cross_message_key_binding",
        "cross_exact_lengths",
        "cross_packed_field_range",
        "cross_vector_padding",
        "cross_challenge_sampling",
        "cross_commitment_digests",
        "cross_domain_transcript",
        "cross_seed_rebuild",
        "cross_merkle_proof",
        "cross_path_proof_consumption",
        "cross_key_algebra",
        "cross_rng_replay",
        "cross_failure_resources",
        "cross_parallel_arithmetic",
        "cross_fault_seed_disclosure",
        "cross_timing",
    ]
    source = """
    #include <cstdio>
    #include <string>
    #include <vector>
    #include "mutators/envelope.h"
    #include "mutators/scheme_mutation.h"

    int main() {
      const char *algorithms[] = {%s};
      for (const char *name : algorithms) {
        pqcfuzz::AlgorithmId id = pqcfuzz::AlgorithmIdFromName(name);
        if (id == pqcfuzz::AlgorithmId::kUnknown) { printf("alg_missing:%%s\\n", name); return 1; }
        if (std::string(pqcfuzz::AlgorithmName(id)) != name) { printf("alg_mismatch:%%s\\n", name); return 1; }
      }
      const char *oracles[] = {%s};
      for (const char *name : oracles) {
        pqcfuzz::OracleId id = pqcfuzz::OracleIdFromName(name);
        if (id == pqcfuzz::OracleId::kUnknown) { printf("oracle_missing:%%s\\n", name); return 1; }
        if (std::string(pqcfuzz::OracleName(id)) != name) { printf("oracle_mismatch:%%s\\n", name); return 1; }
      }
      pqcfuzz::SchemeMutation mutation;
      mutation.op = pqcfuzz::SchemeMutationOp::kSetByte;
      mutation.field = pqcfuzz::SchemeMutationField::kSignatureY;
      mutation.index = 74589;
      mutation.aux = 70000;
      mutation.payload = {0xAB};
      std::vector<uint8_t> encoded = pqcfuzz::EncodeSchemeMutation(mutation);
      pqcfuzz::SchemeMutation decoded;
      std::string error;
      if (!pqcfuzz::DecodeSchemeMutation(encoded, &decoded, &error)) { printf("decode_failed:%%s\\n", error.c_str()); return 1; }
      if (decoded.index != 74589 || decoded.aux != 70000 || decoded.payload.size() != 1 ||
          decoded.payload[0] != 0xAB || decoded.field != pqcfuzz::SchemeMutationField::kSignatureY) {
        printf("roundtrip_mismatch\\n");
        return 1;
      }
      std::vector<uint8_t> bad = {0x02, 0x23, 0, 0, 0, 0, 0, 0, 0, 0};
      if (pqcfuzz::DecodeSchemeMutation(bad, &decoded, &error)) { printf("bad_field_accepted\\n"); return 1; }
      if (encoded.size() < 11 || encoded[0] != 0x07 || encoded[1] != 0x05) { printf("encoding_mismatch\\n"); return 1; }
      printf("ok\\n");
      return 0;
    }
    """ % (
        ", ".join(f'"{name}"' for name in algorithms),
        ", ".join(f'"{name}"' for name in oracle_names),
    )
    result = _run_cpp(
        tmp_path,
        source,
        sources=[
            "src/mutators/envelope.cc",
            "src/mutators/scheme_mutation.cc",
        ],
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


def test_cross_layout_offsets_reach_beyond_65535(tmp_path: Path) -> None:
    source = """
    #include <cstdio>
    #include <vector>
    #include "mutators/cross_layout.h"
    #include "mutators/cross_mutator.h"

    int main() {
      pqcfuzz::CrossParams params{};
      if (!pqcfuzz::GetCrossParams("CROSS-RSDP-5-FAST", &params)) { printf("params_missing\\n"); return 1; }
      std::vector<uint8_t> signature(params.sig_max_len, 0);
      const size_t offsets[] = {0, 65535, 65536, 74589};
      for (size_t offset : offsets) {
        std::vector<uint8_t> candidate = signature;
        auto records = pqcfuzz::MutateCrossAbsoluteByte(params, offset, 0xFF, &candidate);
        if (records.empty() || !records[0].effective || records[0].offset != offset) {
          printf("mutation_failed_at_%zu\\n", offset);
          return 1;
        }
      }
      std::vector<uint8_t> candidate = signature;
      auto records = pqcfuzz::MutateCrossAbsoluteByte(params, 74590, 0xFF, &candidate);
      if (records.empty() || !records[0].skipped || records[0].reason != "offset_out_of_range") {
        printf("bounds_not_rejected\\n");
        return 1;
      }
      printf("ok\\n");
      return 0;
    }
    """
    result = _run_cpp(
        tmp_path,
        source,
        sources=[
            "src/mutators/ml_kem_layout.cc",
            "src/mutators/ml_kem_mutator.cc",
            "src/mutators/scheme_mutation.cc",
            "src/mutators/cross_layout.cc",
            "src/mutators/cross_mutator.cc",
        ],
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


def test_cross_real_adapter_honest_oracles(tmp_path: Path) -> None:
    objects = _compile_cross_objects(tmp_path, ["-DRSDP", "-DCATEGORY_1", "-DSPEED"])
    sources = list(_test_sources.CORE_EXECUTOR_SOURCES) + objects
    source = """
    #include <cstdio>
    #include <string>
    #include <vector>
    #include "mutators/digest.h"
    #include "oracles/cross_executor.h"
    #include "runtime/adapter_registry.h"

    int main() {
      const pqcfuzz_sig_adapter *adapter =
          pqcfuzz::GetSigAdapterByProjectAndId("cross", "cross_reference");
      if (adapter == nullptr) { printf("adapter_missing\\n"); return 1; }
      if (adapter->pk_len != 77 || adapter->sk_len != 32 || adapter->sig_max_len != 18432) {
        printf("abi_mismatch\\n");
        return 1;
      }
      // Reference-derived KAT lane: fixed tape, fixed message.
      {
        std::vector<uint8_t> pk(adapter->pk_len), sk(adapter->sk_len), sig(adapter->sig_max_len);
        std::vector<uint8_t> tape(48);
        for (size_t i = 0; i < tape.size(); ++i) tape[i] = static_cast<uint8_t>(0xA0 + i);
        if (adapter->keygen_seeded(pk.data(), sk.data(), tape.data(), tape.size()) != PQCFUZZ_OK) {
          printf("kat_keygen_failed\\n");
          return 1;
        }
        const std::string message = "PQCFuzz CROSS KAT fixture";
        size_t sig_len = sig.size();
        if (adapter->sign_seeded(sig.data(), &sig_len, reinterpret_cast<const uint8_t *>(message.data()),
                                 message.size(), sk.data(), nullptr, 0, tape.data(), tape.size()) != PQCFUZZ_OK) {
          printf("kat_sign_failed\\n");
          return 1;
        }
        printf("kat_pk=%s\\n", pqcfuzz::MutationSha256Hex(pk).c_str());
        printf("kat_sk=%s\\n", pqcfuzz::MutationSha256Hex(sk).c_str());
        printf("kat_sig=%s\\n", pqcfuzz::MutationSha256Hex(sig).c_str());
      }
      const char *oracles[] = {
          "cross_kat", "cross_local_sign_verify", "cross_exact_lengths", "cross_vector_padding",
          "cross_packed_field_range", "cross_commitment_digests", "cross_merkle_proof",
          "cross_rng_replay", "cross_failure_resources", "cross_challenge_sampling"};
      int total_findings = 0;
      for (const char *oracle_id : oracles) {
        pqcfuzz::CrossOracleConfig config;
        config.job_id = "test";
        config.pair_id = "test";
        config.algorithm = "CROSS-RSDP-1-FAST";
        config.oracle_id = oracle_id;
        if (!pqcfuzz::GetCrossParams(config.algorithm, &config.params)) { printf("params_missing\\n"); return 1; }
        config.left = adapter;
        config.right = adapter;
        config.seed.assign(32, 0x42);
        config.message = {'P', 'Q', 'C', 'F', 'u', 'z', 'z'};
        pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteCrossOracle(config);
        for (const auto &finding : trace.findings) {
          printf("finding:%s:%s:%s\\n", oracle_id, finding.finding_class.c_str(), finding.finding_subclass.c_str());
          ++total_findings;
        }
        if (!trace.relation_not_applicable && !trace.baseline_target_entered) {
          printf("baseline_not_entered:%s\\n", oracle_id);
          return 1;
        }
      }
      if (total_findings != 0) { printf("unexpected_findings:%d\\n", total_findings); return 1; }
      printf("ok\\n");
      return 0;
    }
    """
    result = _run_cpp(
        tmp_path,
        source,
        defines=[
            "RSDP",
            "CATEGORY_1",
            "SPEED",
            "PQCFUZZ_HAVE_CROSS",
            'PQCFUZZ_CROSS_ALGORITHM="CROSS-RSDP-1-FAST"',
        ],
        include_dirs=[CROSS_INCLUDE],
        sources=sources,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    lines = dict(line.split("=", 1) for line in result.stdout.strip().splitlines() if "=" in line)
    assert lines["kat_pk"] == "1f9533b3a3c4db71816c368c29f301bcca2d49a7b691fc759f97c7fc765e1152"
    assert lines["kat_sk"] == "5a177259f73fca35735f82b8a6f1485e809bdb7506ad245de78d65ac89f9f80d"
    assert lines["kat_sig"] == "3c1ea619b562aeeeb0698b63e2a663f81c5ba28eb85c578c66671ec840135c07"

    fixture_path = REPO_ROOT / "tests" / "fixtures" / "cross" / "kat_reference.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    reference = [entry for entry in fixture["profiles"] if entry["algorithm"] == "CROSS-RSDP-1-FAST"][0]
    assert lines["kat_pk"] == reference["pk_sha256"]
    assert lines["kat_sk"] == reference["sk_sha256"]
    assert lines["kat_sig"] == reference["sig_sha256"]
    assert "ok" in result.stdout.splitlines()


def test_cross_executor_detects_always_accepting_adapter(tmp_path: Path) -> None:
    source = """
    #include <cstdio>
    #include <cstring>
    #include <vector>
    #include "oracles/cross_executor.h"

    static pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
      memset(pk, 0x11, 77);
      memset(sk, 0x22, 32);
      return PQCFUZZ_OK;
    }
    static pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t, const uint8_t *,
                               const uint8_t *, size_t) {
      memset(sig, 0x00, 18432);
      *sig_len = 18432;
      return PQCFUZZ_OK;
    }
    static pqcfuzz_status KeygenSeeded(uint8_t *pk, uint8_t *sk, const uint8_t *, size_t) {
      return Keygen(pk, sk);
    }
    static pqcfuzz_status SignSeeded(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                                     const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t) {
      return Sign(sig, sig_len, nullptr, 0, nullptr, nullptr, 0);
    }
    static pqcfuzz_status AcceptVerify(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *,
                                       const uint8_t *, size_t) {
      return PQCFUZZ_OK;
    }
    static const pqcfuzz_sig_adapter kBrokenAdapter = {
        "cross", "cross_reference", "CROSS-RSDP-1-FAST", 77, 32, 18432,
        0, 1, 0, Keygen, Sign, AcceptVerify, SignSeeded, 1, 0, 0, "broken", KeygenSeeded};

    int main() {
      const char *oracles[] = {
          "cross_exact_lengths", "cross_vector_padding", "cross_packed_field_range",
          "cross_message_key_binding", "cross_commitment_digests", "cross_merkle_proof"};
      int expected_subclasses = 0;
      for (const char *oracle_id : oracles) {
        pqcfuzz::CrossOracleConfig config;
        config.job_id = "test";
        config.pair_id = "test";
        config.algorithm = "CROSS-RSDP-1-FAST";
        config.oracle_id = oracle_id;
        if (!pqcfuzz::GetCrossParams(config.algorithm, &config.params)) { printf("params_missing\\n"); return 1; }
        config.left = &kBrokenAdapter;
        config.right = &kBrokenAdapter;
        config.seed.assign(32, 0x42);
        config.message = {'P', 'Q', 'C', 'F', 'u', 'z', 'z'};
        pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteCrossOracle(config);
        if (trace.findings.empty()) {
          printf("not_detected:%s\\n", oracle_id);
          return 1;
        }
        for (const auto &finding : trace.findings) {
          if (finding.finding_class != "potential_crypto_vuln") {
            printf("wrong_class:%s:%s\\n", oracle_id, finding.finding_class.c_str());
            return 1;
          }
          ++expected_subclasses;
        }
      }
      if (expected_subclasses == 0) { printf("no_findings\\n"); return 1; }
      printf("ok\\n");
      return 0;
    }
    """
    result = _run_cpp(
        tmp_path,
        source,
        sources=[
            "src/adapters/status.cc",
            "src/adapters/rng_control.cc",
            "src/adapters/liboqs/rng_control.cc",
            "src/mutators/envelope.cc",
            "src/mutators/ml_kem_layout.cc",
            "src/mutators/ml_kem_mutator.cc",
            "src/mutators/scheme_mutation.cc",
            "src/mutators/cross_layout.cc",
            "src/mutators/cross_mutator.cc",
            "src/oracles/expected_relation.cc",
            "src/oracles/oracle_spec.cc",
            "src/oracles/oracle_spec_loader.cc",
            "src/oracles/oracle_record.cc",
            "src/oracles/oracle_result.cc",
            "src/oracles/metamorphic_spec.cc",
            "src/oracles/cross_executor.cc",
        ],
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"

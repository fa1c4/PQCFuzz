"""SIKE oracle routing, spec, executor, KAT and detection tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(TESTS_DIR))

import _sike_util as util  # noqa: E402
from jobs.generated_config_writer import (  # noqa: E402
    ORACLE_ENUM_BY_NAME,
    enabled_subtests_for_pair,
    oracle_ids_for_pair,
    oracle_spec_for_pair,
)
from pairing.pair_alg_loader import load_pair_alg  # noqa: E402
from replay.replay_one import ALGORITHM_BY_ENUM, ORACLE_BY_ENUM  # noqa: E402


PAIR_ALG = REPO_ROOT / "src" / "config" / "pair_alg.sike_sidh.json"
SPEC_PATH = REPO_ROOT / "src" / "oracles" / "specs" / "sike.json"

SIKE_ORACLES = [
    "sike_kat",
    "sike_local_roundtrip",
    "sike_cross_exchange",
    "sike_reencryption_gate",
    "sike_fallback_exact",
    "sike_fallback_seed_separation",
    "sike_field_encoding",
    "sike_key_consistency",
    "sike_pke_relation",
    "sike_lengths_state",
    "sike_rng_replay",
    "sike_compressed_profile",
    "sike_fault_gate",
]

DEFAULT_SIKE_ORACLES = SIKE_ORACLES[:11]

ALGORITHMS = [name for name in util.PARAMS if name.startswith("SIKE-")]


def test_pair_alg_routing_and_job_generation():
    document = load_pair_alg(PAIR_ALG)
    pairs = [pair for pair in document["pairs"] if pair["status"] == "enabled" and pair["algorithm_family"] == "SIKE"]
    # Four same-source pairs plus the four generic-vs-AMD64 optimized pairs.
    assert len(pairs) == 8
    assert {pair["algorithm"] for pair in pairs} == set(ALGORITHMS)
    for pair in pairs:
        assert pair["primitive_type"] == "kem"
        assert pair["exchange_contract"]["public_key_exchange"] is True
        assert pair["exchange_contract"]["ciphertext_exchange"] is True
        assert pair["exchange_contract"]["secret_key_exchange"] is False
        assert oracle_spec_for_pair(pair) == "src/oracles/specs/sike.json"
        assert oracle_ids_for_pair(pair)[:3] == ["sike_kat", "sike_local_roundtrip", "sike_cross_exchange"]
        subtests = {entry["oracle_id"]: entry for entry in enabled_subtests_for_pair(pair)}
        assert subtests["sike_cross_exchange"]["enabled"] is True
        assert "sike_compressed_profile" not in subtests
        assert "sike_fault_gate" not in subtests

    cross_pairs = [pair for pair in pairs if pair["provenance_relation"] == "same-source-reference-vs-optimized"]
    assert len(cross_pairs) == 4
    for pair in cross_pairs:
        assert pair["right"]["implementation_id"].startswith("sike_optimized_")

    assert ORACLE_ENUM_BY_NAME["sike_kat"] == 80
    assert ORACLE_ENUM_BY_NAME["sike_rng_replay"] == 90
    assert ALGORITHM_BY_ENUM[40] == "SIKE-p434"
    assert ALGORITHM_BY_ENUM[43] == "SIKE-p751"
    assert ORACLE_BY_ENUM[80] == "sike_kat"
    assert ORACLE_BY_ENUM[90] == "sike_rng_replay"
    assert ORACLE_ENUM_BY_NAME["sidh_agreement"] == 91
    assert ORACLE_ENUM_BY_NAME["sike_sidh_timing"] == 99


def test_unknown_family_and_kex_isolation():
    with pytest.raises(ValueError):
        oracle_spec_for_pair({"algorithm_family": "NOT-A-FAMILY"})
    # A kex pair never reaches the KEM oracle list or the KEM fuzzer.
    from jobs.generated_config_writer import fuzzer_source_for_pair, oracle_ids_for_sike

    assert fuzzer_source_for_pair({"primitive_type": "kex"}) == "src/fuzzers/kex_pair_fuzzer.cc"
    assert "sike_kat" in oracle_ids_for_sike()


def test_sike_oracle_spec_shape():
    payload = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    records = payload["oracles"]
    assert len(records) == 13
    assert {record["oracle_id"] for record in records} == set(SIKE_ORACLES)
    for record in records:
        assert record["algorithm_family"] == "SIKE"
        assert record["primitive_type"] == "kem"
        assert record.get("claim") and record.get("source_reference") and record.get("limitations")
        assert record.get("property_ids")
        controls = record.get("controls")
        assert controls.get("positive_control") and controls.get("negative_control")
        assert record.get("precondition") is not None
        for variant in record.get("claim_variants", []):
            assert variant["claim_id"]
            assert variant["conditions"]
            assert variant["evidence_class"] in {
                "NORMATIVE",
                "REFERENCE_DERIVED",
                "IMPLEMENTATION_OBSERVED",
                "ENGINEERING_RECOMMENDATION",
                "INFERENCE",
            }
    generated = (REPO_ROOT / "src" / "oracles" / "generated_fips_specs.inc").read_text(encoding="utf-8")
    for oracle_id in SIKE_ORACLES:
        assert f'"{oracle_id}"' in generated
    disabled = {record["oracle_id"] for record in records if record.get("enabled_by_default") is False}
    assert disabled == {"sike_compressed_profile", "sike_fault_gate"}


def test_claim_variant_resolver(tmp_path):
    source = r"""
    #include <cstdio>
    #include <string>
    #include "oracles/scheme_claims.h"

    int main() {
      pqcfuzz::ResolvedClaim resolved;
      std::string error;
      if (!pqcfuzz::ResolveSchemeClaim("sike_field_encoding", "SIKE-p434", "codec_boundaries",
                                       {std::make_pair(std::string("format"), std::string("codec"))},
                                       &resolved, &error)) {
        printf("codec_failed:%s\n", error.c_str());
        return 1;
      }
      if (resolved.claim_id != "sike_field_encoding.codec_normative" ||
          resolved.metadata.evidence_class != pqcfuzz::EvidenceClass::kNormative) {
        printf("codec_wrong\n");
        return 1;
      }
      if (!pqcfuzz::ResolveSchemeClaim("sike_field_encoding", "SIKE-p434", "api_noncanonical_observation",
                                       {std::make_pair(std::string("format"), std::string("api"))},
                                       &resolved, &error)) {
        printf("api_failed:%s\n", error.c_str());
        return 1;
      }
      if (resolved.metadata.evidence_class != pqcfuzz::EvidenceClass::kImplementationObserved) {
        printf("api_wrong\n");
        return 1;
      }
      if (pqcfuzz::ResolveSchemeClaim("sike_field_encoding", "SIKE-p434", "codec_boundaries", &resolved,
                                      &error)) {
        printf("missing_attribute_resolved\n");
        return 1;
      }
      if (!pqcfuzz::ResolveSchemeClaim("sike_local_roundtrip", "SIKE-p434", "keygen_encaps_decaps",
                                       &resolved, &error)) {
        printf("legacy_failed\n");
        return 1;
      }
      if (resolved.resolved_by_variant ||
          resolved.metadata.evidence_class != pqcfuzz::EvidenceClass::kNormative) {
        printf("legacy_wrong\n");
        return 1;
      }
      printf("ok\n");
      return 0;
    }
    """
    from _falcon_util import compile_test_main

    binary = compile_test_main(
        tmp_path,
        source,
        extra_sources=[
            "src/adapters/status.cc",
            "src/oracles/expected_relation.cc",
            "src/oracles/oracle_record.cc",
            "src/oracles/oracle_spec.cc",
            "src/oracles/scheme_claims.cc",
            "src/oracles/metamorphic_spec.cc",
        ],
    )
    result = subprocess.run([str(binary)], cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "ok"


def test_layout_and_codec(tmp_path):
    source = r"""
    #include <cstdio>
    #include <string>
    #include <vector>
    #include "mutators/sike_layout.h"
    #include "mutators/sike_mutator.h"

    int main() {
      const char *algorithms[] = {"SIKE-p434", "SIKE-p503", "SIKE-p610", "SIKE-p751"};
      for (const char *name : algorithms) {
        pqcfuzz::SikeParams params;
        if (!pqcfuzz::GetSikeParams(name, &params)) { printf("params:%s\n", name); return 1; }
        pqcfuzz::SikeBig p;
        if (!pqcfuzz::ComputeSikeFieldPrime(params.e2, params.e3, &p)) { printf("prime\n"); return 1; }
        size_t sbits = 0;
        if (!pqcfuzz::ComputeSikeBobScalarBits(params.e3, &sbits)) { printf("sbits\n"); return 1; }
        if (sbits != 8 * params.nsk3 - (8 * params.nsk3 - sbits)) { printf("sbits_range\n"); return 1; }
        if (params.sk_sk3_off != params.msg_bytes ||
            params.sk_pk_off != params.msg_bytes + params.nsk3 ||
            params.sk_pk_off + params.pk_len != params.sk_len) { printf("sk_offsets\n"); return 1; }
        if (params.c0_len != 6 * params.np || params.c1_off != params.c0_len ||
            params.c1_off + params.msg_bytes != params.ct_len) { printf("ct_offsets\n"); return 1; }
        std::vector<uint8_t> buffer(6 * params.np, 0);
        for (size_t coordinate = 0; coordinate < 6; ++coordinate) {
          pqcfuzz::MutationRecord r1 = pqcfuzz::SetSikeCiphertextCoordinateBoundary(
              params, coordinate, pqcfuzz::SikeFpValue::kPrimeMinusOne, &buffer);
          if (!r1.effective ||
              !pqcfuzz::SikeFpCanonical(buffer.data() + coordinate * params.np, params.np, p)) {
            printf("minus_one:%s:%zu\n", name, coordinate);
            return 1;
          }
          pqcfuzz::MutationRecord r2 = pqcfuzz::SetSikeCiphertextCoordinateBoundary(
              params, coordinate, pqcfuzz::SikeFpValue::kPrime, &buffer);
          if (!r2.effective ||
              pqcfuzz::SikeFpCanonical(buffer.data() + coordinate * params.np, params.np, p)) {
            printf("prime:%s:%zu\n", name, coordinate);
            return 1;
          }
          pqcfuzz::MutationRecord r3 = pqcfuzz::SetSikeCiphertextCoordinateBoundary(
              params, coordinate, pqcfuzz::SikeFpValue::kAllOnes, &buffer);
          if (!r3.effective ||
              pqcfuzz::SikeFpCanonical(buffer.data() + coordinate * params.np, params.np, p)) {
            printf("allones:%s:%zu\n", name, coordinate);
            return 1;
          }
        }
        std::vector<uint8_t> key(params.sk_len, 0);
        pqcfuzz::MutationRecord s_rec = pqcfuzz::WriteSikeSecretKeySByte(params, 0, 0xA5, &key);
        pqcfuzz::MutationRecord sk3_rec = pqcfuzz::WriteSikeSecretKeySk3Byte(params, params.nsk3 - 1, 0xFF, &key);
        pqcfuzz::MutationRecord pk_rec =
            pqcfuzz::WriteSikeSecretKeyEmbeddedPkByte(params, params.pk_len - 1, 0x11, &key);
        if (!s_rec.effective || !sk3_rec.effective || !pk_rec.effective) { printf("sk_writes\n"); return 1; }
        if (key[0] != 0xA5 || key[params.sk_sk3_off + params.nsk3 - 1] != 0xFF ||
            key[params.sk_len - 1] != 0x11) { printf("sk_offsets_write:%s\n", name); return 1; }
      }
      printf("ok\n");
      return 0;
    }
    """
    from _falcon_util import compile_test_main

    binary = compile_test_main(
        tmp_path,
        source,
        extra_sources=[
            "src/adapters/status.cc",
            "src/mutators/sike_layout.cc",
            "src/mutators/sike_mutator.cc",
            "src/mutators/scheme_mutation.cc",
        ],
    )
    result = subprocess.run([str(binary)], cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "ok"


def test_envelope_and_scheme_mutation_roundtrip(tmp_path):
    source = r"""
    #include <cstdio>
    #include <string>
    #include "mutators/envelope.h"
    #include "mutators/scheme_mutation.h"

    int main() {
      const char *algorithms[] = {"SIKE-p434", "SIKE-p503", "SIKE-p610", "SIKE-p751",
                                  "SIDH-p434", "SIDH-p503", "SIDH-p610", "SIDH-p751"};
      for (const char *name : algorithms) {
        const pqcfuzz::AlgorithmId id = pqcfuzz::AlgorithmIdFromName(name);
        if (id == pqcfuzz::AlgorithmId::kUnknown) { printf("algorithm_unknown:%s\n", name); return 1; }
        if (std::string(pqcfuzz::AlgorithmName(id)) != name) { printf("algorithm_name:%s\n", name); return 1; }
      }
      const char *oracles[] = {
          "sike_kat", "sike_local_roundtrip", "sike_cross_exchange", "sike_reencryption_gate",
          "sike_fallback_exact", "sike_fallback_seed_separation", "sike_field_encoding",
          "sike_key_consistency", "sike_pke_relation", "sike_lengths_state", "sike_rng_replay",
          "sidh_agreement", "sidh_cross_agreement", "sidh_field_curve_checks",
          "sidh_role_scalar_profile", "sidh_isogeny_math", "sike_compressed_profile",
          "sike_fault_gate", "sidh_resources_rng", "sike_sidh_timing"};
      for (const char *name : oracles) {
        const pqcfuzz::OracleId id = pqcfuzz::OracleIdFromName(name);
        if (id == pqcfuzz::OracleId::kUnknown) { printf("oracle_unknown:%s\n", name); return 1; }
        if (std::string(pqcfuzz::OracleName(id)) != name) { printf("oracle_name:%s\n", name); return 1; }
      }
      pqcfuzz::SchemeMutation recipe;
      recipe.op = pqcfuzz::SchemeMutationOp::kSetCoefficient;
      recipe.field = pqcfuzz::SchemeMutationField::kSikeCiphertextCoordinate;
      recipe.index = 3;
      recipe.aux = 2;
      const std::vector<uint8_t> encoded = pqcfuzz::EncodeSchemeMutation(recipe);
      pqcfuzz::SchemeMutation decoded;
      std::string error;
      if (!pqcfuzz::DecodeSchemeMutation(encoded, &decoded, &error) ||
          decoded.field != pqcfuzz::SchemeMutationField::kSikeCiphertextCoordinate) {
        printf("recipe_decode\n");
        return 1;
      }
      std::vector<uint8_t> bad = encoded;
      bad[1] = 200;
      if (pqcfuzz::DecodeSchemeMutation(bad, &decoded, &error)) { printf("bad_field\n"); return 1; }
      printf("ok\n");
      return 0;
    }
    """
    from _falcon_util import compile_test_main

    binary = compile_test_main(
        tmp_path,
        source,
        extra_sources=[
            "src/adapters/status.cc",
            "src/mutators/envelope.cc",
            "src/mutators/scheme_mutation.cc",
        ],
    )
    result = subprocess.run([str(binary)], cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "ok"


REAL_ADAPTER_MAIN = r"""
#include <cstdio>
#include <string>
#include <vector>

#include "oracles/oracle_result.h"
#include "oracles/sike_executor.h"

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_sike_kem_adapter(const char *implementation_id);

int main(int argc, char **argv) {
  const char *algorithm = argv[1];
  const char *implementation_id = argv[2];
  pqcfuzz::SikeParams params;
  if (!pqcfuzz::GetSikeParams(algorithm, &params)) { printf("params\n"); return 1; }
  const pqcfuzz_kem_adapter *adapter = pqcfuzz_get_sike_kem_adapter(implementation_id);
  if (adapter == nullptr) { printf("adapter\n"); return 1; }
  const char *oracles[] = {
      "sike_kat", "sike_local_roundtrip", "sike_cross_exchange", "sike_reencryption_gate",
      "sike_fallback_exact", "sike_fallback_seed_separation", "sike_field_encoding",
      "sike_key_consistency", "sike_pke_relation", "sike_lengths_state", "sike_rng_replay"};
  std::vector<uint8_t> seed(32);
  for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(0xA0 + i);
  int failures = 0;
  for (const char *oracle_id : oracles) {
    pqcfuzz::SikeOracleConfig config;
    config.job_id = "pytest";
    config.pair_id = "pytest";
    config.algorithm = algorithm;
    config.oracle_id = oracle_id;
    config.params = params;
    config.left = adapter;
    config.right = adapter;
    config.exchange_contract.public_key_exchange = true;
    config.exchange_contract.ciphertext_exchange = true;
    config.seed = seed;
    pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteSikeOracle(config);
    if (!trace.findings.empty()) {
      printf("finding:%s:%zu\n", oracle_id, trace.findings.size());
      ++failures;
      continue;
    }
    if (std::string(oracle_id) == "sike_pke_relation" || trace.relation_not_applicable) {
      continue;
    }
    if (!trace.baseline_target_entered) {
      printf("baseline_not_entered:%s\n", oracle_id);
      ++failures;
    }
  }
  if (failures != 0) return 1;
  printf("ok\n");
  return 0;
}
"""


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_real_adapter_honest_oracles(tmp_path, algorithm):
    util.require_sike_sources()
    binary = util.compile_adapter_binary(algorithm, tmp_path, REAL_ADAPTER_MAIN)
    implementation_id = util.PARAMS[algorithm]["sike_impl"]
    result = subprocess.run([str(binary), algorithm, implementation_id], cwd=REPO_ROOT,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


def test_official_kat_fixture(tmp_path):
    util.require_sike_sources()
    fixture = json.loads((REPO_ROOT / "tests" / "fixtures" / "sike_sidh" / "sike_kat_reference.json").read_text())
    for algorithm in ALGORITHMS:
        suffix = util.PARAMS[algorithm]["source_dir"]
        cli = util.compile_hook_cli(algorithm, tmp_path / suffix)
        for record in fixture["records"][suffix.lower()]:
            output = subprocess.run([str(cli), "kat", record["seed"]], cwd=REPO_ROOT,
                                    capture_output=True, text=True, check=True).stdout.strip().splitlines()
            got = {}
            for line in output:
                if "=" in line:
                    key, value = line.split("=", 1)
                    got[key] = value
            assert got["pk"] == record["pk"]
            assert got["sk"] == record["sk"]
            assert got["ct"] == record["ct"]
            assert got["ss"] == record["ss"]


FAKE_MAIN = r"""
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "oracles/oracle_result.h"
#include "oracles/sike_executor.h"

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_sike_adapter();
extern "C" void pqcfuzz_fake_sike_configure(const char *algorithm, size_t pk_len, size_t sk_len, size_t ct_len,
                                            size_t ss_len, size_t e2, int mode);

int main(int argc, char **argv) {
  const char *algorithm = "SIKE-p434";
  const int mode = argc > 1 ? atoi(argv[1]) : 1;
  pqcfuzz::SikeParams params;
  if (!pqcfuzz::GetSikeParams(algorithm, &params)) { printf("params\n"); return 1; }
  pqcfuzz_fake_sike_configure(algorithm, params.pk_len, params.sk_len, params.ct_len, params.ss_len, params.e2, mode);
  const pqcfuzz_kem_adapter *adapter = pqcfuzz_fake_sike_adapter();
  const char *oracles[] = {"sike_reencryption_gate", "sike_fallback_exact",
                           "sike_fallback_seed_separation"};
  for (const char *oracle_id : oracles) {
    pqcfuzz::SikeOracleConfig config;
    config.job_id = "pytest";
    config.pair_id = "pytest";
    config.algorithm = algorithm;
    config.oracle_id = oracle_id;
    config.params = params;
    config.left = adapter;
    config.right = adapter;
    config.seed.assign(32, 0x42);
    pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteSikeOracle(config);
    printf("detected:%s=%d\n", oracle_id, trace.findings.empty() ? 0 : 1);
  }
  printf("ok\n");
  return 0;
}
"""


@pytest.mark.parametrize(
    "mode,required_oracle",
    [
        (1, "sike_reencryption_gate"),
        (2, "sike_fallback_seed_separation"),
        (3, "sike_fallback_exact"),
    ],
)
def test_executor_detects_broken_gate_adapter(tmp_path, mode, required_oracle):
    from _falcon_util import compile_test_main

    sources = [source for source in util.SIKE_CORE_SOURCES
               if "reference_adapter" not in source]
    binary = compile_test_main(
        tmp_path,
        FAKE_MAIN,
        extra_sources=sources + ["tests/fake_adapters/fake_sike_sidh.cc"],
    )
    result = subprocess.run([str(binary), str(mode)], cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    detected = {}
    for line in result.stdout.splitlines():
        if line.startswith("detected:"):
            oracle_id, value = line.split(":", 1)[1].split("=", 1)
            detected[oracle_id] = int(value)
    assert detected.get(required_oracle) == 1, result.stdout
    assert any(value == 1 for value in detected.values()), result.stdout
    assert result.stdout.strip().endswith("ok")

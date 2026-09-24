"""NTRU oracle routing, spec, executor, KAT and detection tests."""

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

import _ntru_util as util  # noqa: E402
from jobs.generated_config_writer import (  # noqa: E402
    ORACLE_ENUM_BY_NAME,
    enabled_subtests_for_pair,
    oracle_ids_for_pair,
    oracle_spec_for_pair,
)
from pairing.pair_alg_loader import load_pair_alg  # noqa: E402
from replay.replay_one import ALGORITHM_BY_ENUM, ORACLE_BY_ENUM  # noqa: E402


PAIR_ALG = REPO_ROOT / "src" / "config" / "pair_alg.ntru.json"
SPEC_PATH = REPO_ROOT / "src" / "oracles" / "specs" / "ntru.json"

NTRU_ORACLES = [
    "ntru_kat",
    "ntru_local_roundtrip",
    "ntru_cross_exchange",
    "ntru_dpke_membership",
    "ntru_ct_padding",
    "ntru_implicit_rejection_exact",
    "ntru_prf_key_separation",
    "ntru_key_algebra",
    "ntru_codec_roundtrip",
    "ntru_sk_malformed",
    "ntru_lengths",
    "ntru_rng_and_replay",
    "ntru_failure_state",
    "ntru_dpke_failure_output",
    "ntru_fault_checks",
    "ntru_timing_resources",
]

ALGORITHMS = list(util.PARAMS)


def test_pair_alg_routing_and_job_generation():
    document = load_pair_alg(PAIR_ALG)
    pairs = [pair for pair in document["pairs"] if pair["status"] == "enabled"]
    assert len(pairs) == 4
    assert {pair["algorithm"] for pair in pairs} == set(ALGORITHMS)
    for pair in pairs:
        assert pair["algorithm_family"] == "NTRU"
        assert pair["primitive_type"] == "kem"
        assert pair["exchange_contract"]["public_key_exchange"] is True
        assert pair["exchange_contract"]["ciphertext_exchange"] is True
        assert pair["exchange_contract"]["secret_key_exchange"] is False
        assert oracle_spec_for_pair(pair) == "src/oracles/specs/ntru.json"
        assert oracle_ids_for_pair(pair)[:3] == ["ntru_kat", "ntru_local_roundtrip", "ntru_cross_exchange"]
        subtests = {entry["oracle_id"]: entry for entry in enabled_subtests_for_pair(pair)}
        assert subtests["ntru_cross_exchange"]["enabled"] is True
        assert "ntru_fault_checks" not in subtests
        assert "ntru_timing_resources" not in subtests

    assert ORACLE_ENUM_BY_NAME["ntru_kat"] == 64
    assert ORACLE_ENUM_BY_NAME["ntru_timing_resources"] == 79
    assert ALGORITHM_BY_ENUM[32] == "NTRU-HPS-2048-509"
    assert ALGORITHM_BY_ENUM[35] == "NTRU-HRSS-701"
    assert ORACLE_BY_ENUM[64] == "ntru_kat"
    assert ORACLE_BY_ENUM[79] == "ntru_timing_resources"
    # Disjoint from the other families.
    assert ORACLE_ENUM_BY_NAME["falcon_kat"] == 100
    assert ORACLE_ENUM_BY_NAME["sig_verify_pk"] == 30


def test_unknown_family_is_rejected():
    with pytest.raises(ValueError):
        oracle_spec_for_pair({"algorithm_family": "NOT-A-FAMILY"})


def test_ntru_oracle_spec_shape():
    payload = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    records = payload["oracles"]
    assert len(records) == 16
    assert {record["oracle_id"] for record in records} == set(NTRU_ORACLES)
    for record in records:
        assert record["algorithm_family"] == "NTRU"
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
                "NORMATIVE", "REFERENCE_DERIVED", "IMPLEMENTATION_OBSERVED",
                "ENGINEERING_RECOMMENDATION", "INFERENCE",
            }
    generated = (REPO_ROOT / "src" / "oracles" / "generated_fips_specs.inc").read_text(encoding="utf-8")
    for oracle_id in NTRU_ORACLES:
        assert f'"{oracle_id}"' in generated
    disabled = {record["oracle_id"] for record in records if record.get("enabled_by_default") is False}
    assert disabled == {"ntru_fault_checks", "ntru_timing_resources"}


def test_claim_variant_resolver(tmp_path):
    source = r"""
    #include <cstdio>
    #include <string>
    #include "oracles/scheme_claims.h"

    int main() {
      pqcfuzz::ResolvedClaim resolved;
      std::string error;
      if (!pqcfuzz::ResolveSchemeClaim("ntru_dpke_membership", "NTRU-HPS-2048-509", "membership",
                                       {std::make_pair(std::string("variant"), std::string("HPS"))},
                                       &resolved, &error)) {
        printf("hps_failed:%s\n", error.c_str());
        return 1;
      }
      if (resolved.claim_id != "ntru_dpke_membership.hps_normative" ||
          resolved.metadata.evidence_class != pqcfuzz::EvidenceClass::kNormative) {
        printf("hps_wrong\n");
        return 1;
      }
      if (!pqcfuzz::ResolveSchemeClaim("ntru_dpke_membership", "NTRU-HRSS-701", "membership",
                                       {std::make_pair(std::string("variant"), std::string("HRSS"))},
                                       &resolved, &error)) {
        printf("hrss_failed:%s\n", error.c_str());
        return 1;
      }
      if (resolved.metadata.evidence_class != pqcfuzz::EvidenceClass::kImplementationObserved) {
        printf("hrss_wrong\n");
        return 1;
      }
      if (pqcfuzz::ResolveSchemeClaim("ntru_dpke_membership", "NTRU-HPS-2048-509", "membership", &resolved,
                                      &error)) {
        printf("missing_attribute_resolved\n");
        return 1;
      }
      if (!pqcfuzz::ResolveSchemeClaim("ntru_local_roundtrip", "NTRU-HPS-2048-509", "roundtrip", &resolved,
                                       &error)) {
        printf("legacy_failed\n");
        return 1;
      }
      if (resolved.resolved_by_variant || resolved.metadata.evidence_class != pqcfuzz::EvidenceClass::kNormative) {
        printf("legacy_wrong\n");
        return 1;
      }
      printf("ok\n");
      return 0;
    }
    """
    from _falcon_util import compile_test_main  # shared compile helper

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


def test_envelope_and_scheme_mutation_roundtrip(tmp_path):
    source = r"""
    #include <cstdio>
    #include <string>
    #include "mutators/envelope.h"
    #include "mutators/scheme_mutation.h"

    int main() {
      const char *algorithms[] = {"NTRU-HPS-2048-509", "NTRU-HPS-2048-677", "NTRU-HPS-4096-821",
                                  "NTRU-HRSS-701"};
      for (const char *name : algorithms) {
        const pqcfuzz::AlgorithmId id = pqcfuzz::AlgorithmIdFromName(name);
        if (id == pqcfuzz::AlgorithmId::kUnknown) { printf("algorithm_unknown:%s\n", name); return 1; }
        if (std::string(pqcfuzz::AlgorithmName(id)) != name) { printf("algorithm_name:%s\n", name); return 1; }
      }
      const char *oracles[] = {
          "ntru_kat", "ntru_local_roundtrip", "ntru_cross_exchange", "ntru_dpke_membership", "ntru_ct_padding",
          "ntru_implicit_rejection_exact", "ntru_prf_key_separation", "ntru_key_algebra", "ntru_codec_roundtrip",
          "ntru_sk_malformed", "ntru_lengths", "ntru_rng_and_replay", "ntru_failure_state",
          "ntru_dpke_failure_output", "ntru_fault_checks", "ntru_timing_resources"};
      for (const char *name : oracles) {
        const pqcfuzz::OracleId id = pqcfuzz::OracleIdFromName(name);
        if (id == pqcfuzz::OracleId::kUnknown) { printf("oracle_unknown:%s\n", name); return 1; }
        if (std::string(pqcfuzz::OracleName(id)) != name) { printf("oracle_name:%s\n", name); return 1; }
      }
      pqcfuzz::SchemeMutation recipe;
      recipe.op = pqcfuzz::SchemeMutationOp::kSetCoefficient;
      recipe.field = pqcfuzz::SchemeMutationField::kKemCiphertextCoefficient;
      recipe.index = 70000;
      recipe.aux = 4095;
      recipe.payload = {0x11};
      const std::vector<uint8_t> encoded = pqcfuzz::EncodeSchemeMutation(recipe);
      if (encoded.size() != 11 || encoded[0] != 0x08 || encoded[1] != 26) { printf("recipe_encoding\n"); return 1; }
      pqcfuzz::SchemeMutation decoded;
      std::string error;
      if (!pqcfuzz::DecodeSchemeMutation(encoded, &decoded, &error) || decoded.index != 70000 ||
          decoded.aux != 4095) {
        printf("recipe_decode\n");
        return 1;
      }
      std::vector<uint8_t> bad = encoded;
      bad[1] = 250;
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


def test_layout_and_padding_probe(tmp_path):
    source = r"""
    #include <cstdio>
    #include <string>
    #include <vector>
    #include "mutators/ntru_layout.h"
    #include "mutators/ntru_mutator.h"

    int main() {
      const char *algorithms[] = {"NTRU-HPS-2048-509", "NTRU-HPS-2048-677", "NTRU-HPS-4096-821",
                                  "NTRU-HRSS-701"};
      for (const char *name : algorithms) {
        pqcfuzz::NtruParams params;
        if (!pqcfuzz::GetNtruParams(name, &params)) { printf("params:%s\n", name); return 1; }
        if (params.b3 != (params.n - 1 + 4) / 5) { printf("b3:%s\n", name); return 1; }
        if (params.bq != ((params.n - 1) * params.logq + 7) / 8) { printf("bq:%s\n", name); return 1; }
        if (params.sk_len != 2 * params.b3 + params.bq + params.prf_key_bytes) { printf("sk:%s\n", name); return 1; }
        std::vector<uint8_t> trits(params.n, 0);
        for (size_t i = 0; i < params.n; ++i) trits[i] = static_cast<uint8_t>(i % 3);
        std::vector<uint8_t> payload;
        std::string error;
        if (!pqcfuzz::EncodeNtruS3(trits, params, &payload, &error)) { printf("s3_encode\n"); return 1; }
        std::vector<uint8_t> decoded;
        if (!pqcfuzz::DecodeNtruS3(payload.data(), payload.size(), params, &decoded, &error)) {
          printf("s3_decode\n");
          return 1;
        }
        for (size_t i = 0; i + 1 < params.n; ++i) {
          if (decoded[i] != trits[i]) { printf("s3_roundtrip:%s\n", name); return 1; }
        }
        if (decoded[params.n - 1] != 0) { printf("s3_last:%s\n", name); return 1; }
        std::vector<uint8_t> bad_trits = trits;
        bad_trits[0] = 3;
        if (pqcfuzz::EncodeNtruS3(bad_trits, params, &payload, &error)) { printf("s3_bad_accepted\n"); return 1; }

        std::vector<uint16_t> coefficients(params.n);
        for (size_t i = 0; i < params.n; ++i) coefficients[i] = static_cast<uint16_t>((i * 13 + 5) % params.q);
        std::vector<uint8_t> qpayload;
        if (!pqcfuzz::EncodeNtruRq0(coefficients, params, &qpayload, &error)) { printf("q_encode\n"); return 1; }
        std::vector<uint16_t> qdecoded;
        if (!pqcfuzz::DecodeNtruRq0(qpayload.data(), qpayload.size(), params, &qdecoded, &error)) {
          printf("q_decode\n");
          return 1;
        }
        uint64_t sum = 0;
        for (uint16_t value : qdecoded) sum += value;
        if (sum % params.q != 0) { printf("q_sum:%s\n", name); return 1; }

        std::vector<uint8_t> ciphertext(params.ct_len, 0);
        if (params.tail_unused_bits > 0) {
          const pqcfuzz::MutationRecord record = pqcfuzz::SetNtruCiphertextPaddingBit(params, 0, &ciphertext);
          if (!record.effective || pqcfuzz::NtruCiphertextPaddingValid(ciphertext.data(), ciphertext.size(), params)) {
            printf("padding:%s\n", name);
            return 1;
          }
        } else {
          const pqcfuzz::MutationRecord record = pqcfuzz::SetNtruCiphertextPaddingBit(params, 0, &ciphertext);
          if (!record.skipped) { printf("padding_should_skip:%s\n", name); return 1; }
        }
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
            "src/mutators/ntru_layout.cc",
            "src/mutators/ntru_mutator.cc",
            "src/mutators/scheme_mutation.cc",
        ],
    )
    result = subprocess.run([str(binary)], cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "ok"


REAL_ADAPTER_MAIN = r"""
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "oracles/ntru_executor.h"
#include "oracles/oracle_result.h"

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_get_ntru_kem_adapter(const char *implementation_id);

int main(int argc, char **argv) {
  const char *algorithm = argv[1];
  const char *implementation_id = argv[2];
  pqcfuzz::NtruParams params;
  if (!pqcfuzz::GetNtruParams(algorithm, &params)) { printf("params\n"); return 1; }
  const pqcfuzz_kem_adapter *adapter = pqcfuzz_get_ntru_kem_adapter(implementation_id);
  if (adapter == nullptr) { printf("adapter\n"); return 1; }
  const char *oracles[] = {
      "ntru_kat", "ntru_local_roundtrip", "ntru_cross_exchange", "ntru_dpke_membership", "ntru_ct_padding",
      "ntru_implicit_rejection_exact", "ntru_prf_key_separation", "ntru_key_algebra", "ntru_codec_roundtrip",
      "ntru_sk_malformed", "ntru_lengths", "ntru_rng_and_replay", "ntru_failure_state",
      "ntru_dpke_failure_output"};
  std::vector<uint8_t> seed(32);
  for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(0xA0 + i);
  int failures = 0;
  for (const char *oracle_id : oracles) {
    const std::string oracle(oracle_id);
    const bool model_lane = oracle == "ntru_dpke_membership" || oracle == "ntru_key_algebra" ||
                            oracle == "ntru_codec_roundtrip" || oracle == "ntru_dpke_failure_output";
    pqcfuzz::NtruOracleConfig config;
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
    pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteNtruOracle(config);
    if (!trace.findings.empty()) {
      printf("finding:%s:%zu\n", oracle_id, trace.findings.size());
      ++failures;
      continue;
    }
    if (model_lane || trace.relation_not_applicable) {
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
    util.require_ntru_sources()
    binary = util.compile_adapter_binary(algorithm, tmp_path, REAL_ADAPTER_MAIN)
    implementation_id = util.PARAMS[algorithm][2]
    result = subprocess.run([str(binary), algorithm, implementation_id], cwd=REPO_ROOT,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


def test_official_kat_fixture(tmp_path):
    util.require_ntru_sources()
    fixture = json.loads((REPO_ROOT / "tests" / "fixtures" / "ntru" / "kat_reference.json").read_text())
    for algorithm in ALGORITHMS:
        source_dir = util.PARAMS[algorithm][0]
        cli = util.compile_hook_cli(algorithm, tmp_path / source_dir)
        for record in fixture["records"][source_dir]:
            output = subprocess.run([str(cli), "kat", record["seed"]], cwd=REPO_ROOT,
                                    capture_output=True, text=True, check=True).stdout.strip().splitlines()
            got = {}
            for line in output:
                for token in line.split():
                    if "=" in token:
                        key, value = token.split("=", 1)
                        got[key] = value
            assert got["pk"] == record["pk"].lower()
            assert got["sk"] == record["sk"].lower()
            assert got["ct"] == record["ct"].lower()
            assert got["ss"] == record["ss"].lower()


FAKE_MAIN = r"""
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "oracles/ntru_executor.h"
#include "oracles/oracle_result.h"

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_ntru_adapter();
extern "C" void pqcfuzz_fake_ntru_configure(const char *algorithm, size_t pk_len, size_t sk_len, size_t ct_len,
                                            size_t ss_len);

int main() {
  const char *algorithm = "NTRU-HPS-2048-509";
  pqcfuzz::NtruParams params;
  if (!pqcfuzz::GetNtruParams(algorithm, &params)) { printf("params\n"); return 1; }
  pqcfuzz_fake_ntru_configure(algorithm, params.pk_len, params.sk_len, params.ct_len, params.ss_len);
  const pqcfuzz_kem_adapter *adapter = pqcfuzz_fake_ntru_adapter();
  const char *oracles[] = {"ntru_ct_padding", "ntru_implicit_rejection_exact", "ntru_prf_key_separation"};
  int findings_total = 0;
  for (const char *oracle_id : oracles) {
    pqcfuzz::NtruOracleConfig config;
    config.job_id = "pytest";
    config.pair_id = "pytest";
    config.algorithm = algorithm;
    config.oracle_id = oracle_id;
    config.params = params;
    config.left = adapter;
    config.right = adapter;
    config.seed.assign(32, 0x42);
    pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteNtruOracle(config);
    if (trace.findings.empty()) {
      printf("not_detected:%s\n", oracle_id);
      return 1;
    }
    findings_total += static_cast<int>(trace.findings.size());
  }
  if (findings_total == 0) { printf("no_findings\n"); return 1; }
  printf("ok\n");
  return 0;
}
"""


def test_executor_detects_broken_fallback_adapter(tmp_path):
    from _falcon_util import compile_test_main

    binary = compile_test_main(
        tmp_path,
        FAKE_MAIN,
        extra_sources=util.NTRU_CORE_SOURCES + ["tests/fake_adapters/fake_ntru.cc"],
    )
    result = subprocess.run([str(binary)], cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"

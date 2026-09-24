"""Falcon oracle routing, spec, executor and detection tests."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(TESTS_DIR))

import _falcon_util as util  # noqa: E402
from jobs.generated_config_writer import (  # noqa: E402
    ORACLE_ENUM_BY_NAME,
    enabled_subtests_for_pair,
    oracle_ids_for_pair,
    oracle_spec_for_pair,
)
from pairing.pair_alg_loader import PairAlgError, load_pair_alg  # noqa: E402
from replay.replay_one import ALGORITHM_BY_ENUM, ORACLE_BY_ENUM  # noqa: E402


PAIR_ALG = REPO_ROOT / "src" / "config" / "pair_alg.falcon.json"
SPEC_PATH = REPO_ROOT / "src" / "oracles" / "specs" / "falcon.json"

FALCON_ORACLES = [
    "falcon_kat",
    "falcon_local_sign_verify",
    "falcon_cross_verify",
    "falcon_message_salt_binding",
    "falcon_header_profile",
    "falcon_pk_coefficients",
    "falcon_compressed_canonicality",
    "falcon_format_lengths",
    "falcon_norm_equation",
    "falcon_norm_boundary_unit",
    "falcon_hash_to_point",
    "falcon_key_equation",
    "falcon_sk_codec",
    "falcon_rng_replay",
    "falcon_failure_state",
    "falcon_signed_message_frame",
    "falcon_sampler_arithmetic",
    "falcon_fault_checks",
    "falcon_timing_resources",
]

ALGORITHMS = [
    "FALCON-512-COMPRESSED",
    "FALCON-1024-COMPRESSED",
    "FALCON-512-PADDED",
    "FALCON-1024-PADDED",
    "FALCON-512-CT",
    "FALCON-1024-CT",
]

ADAPTER_IDS = {
    "FALCON-512-COMPRESSED": "falcon_reference_512_compressed",
    "FALCON-1024-COMPRESSED": "falcon_reference_1024_compressed",
    "FALCON-512-PADDED": "falcon_reference_512_padded",
    "FALCON-1024-PADDED": "falcon_reference_1024_padded",
    "FALCON-512-CT": "falcon_reference_512_ct",
    "FALCON-1024-CT": "falcon_reference_1024_ct",
}


def test_pair_alg_routing_and_job_generation():
    document = load_pair_alg(PAIR_ALG)
    pairs = [pair for pair in document["pairs"] if pair["status"] == "enabled"]
    assert len(pairs) == 6
    assert {pair["algorithm"] for pair in pairs} == set(ALGORITHMS)
    for pair in pairs:
        assert pair["algorithm_family"] == "FALCON"
        assert pair["primitive_type"] == "sig"
        assert pair["exchange_contract"] == {"public_key_exchange": True, "signature_exchange": False}
        assert oracle_spec_for_pair(pair) == "src/oracles/specs/falcon.json"
        assert oracle_ids_for_pair(pair) == [
            "falcon_kat",
            "falcon_local_sign_verify",
            "falcon_cross_verify",
            "falcon_message_salt_binding",
            "falcon_header_profile",
            "falcon_pk_coefficients",
            "falcon_compressed_canonicality",
            "falcon_format_lengths",
            "falcon_norm_equation",
            "falcon_norm_boundary_unit",
            "falcon_hash_to_point",
            "falcon_key_equation",
            "falcon_sk_codec",
            "falcon_rng_replay",
            "falcon_failure_state",
            "falcon_signed_message_frame",
            "falcon_sampler_arithmetic",
        ]
        subtests = {entry["oracle_id"]: entry for entry in enabled_subtests_for_pair(pair)}
        assert subtests["falcon_cross_verify"]["enabled"] is False
        assert subtests["falcon_local_sign_verify"]["enabled"] is True

    assert ORACLE_ENUM_BY_NAME["falcon_kat"] == 100
    assert ORACLE_ENUM_BY_NAME["falcon_timing_resources"] == 118
    assert ALGORITHM_BY_ENUM[56] == "FALCON-512-COMPRESSED"
    assert ALGORITHM_BY_ENUM[61] == "FALCON-1024-CT"
    assert ORACLE_BY_ENUM[100] == "falcon_kat"
    assert ORACLE_BY_ENUM[118] == "falcon_timing_resources"
    # Falcon ids are disjoint from the ML-* and CROSS families.
    assert ORACLE_ENUM_BY_NAME["sig_verify_pk"] == 30
    assert ORACLE_ENUM_BY_NAME["cross_kat"] == 120


def test_unknown_family_is_rejected():
    with pytest.raises(ValueError):
        oracle_spec_for_pair({"algorithm_family": "NOT-A-FAMILY"})


def test_falcon_oracle_spec_shape():
    payload = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    records = payload["oracles"]
    assert len(records) == 19
    assert {record["oracle_id"] for record in records} == set(FALCON_ORACLES)
    for record in records:
        assert record["algorithm_family"] == "FALCON"
        assert record["primitive_type"] == "sig"
        assert record.get("claim")
        assert record.get("source_reference")
        assert record.get("limitations")
        assert record.get("property_ids"), record["oracle_id"]
        controls = record.get("controls")
        assert isinstance(controls, dict) and controls.get("positive_control") and controls.get("negative_control")
        assert record.get("precondition") is not None
        assert record.get("mutation")
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
            assert variant["claim"] and variant["source_reference"]
    generated = (REPO_ROOT / "src" / "oracles" / "generated_fips_specs.inc").read_text(encoding="utf-8")
    for oracle_id in FALCON_ORACLES:
        assert f'"{oracle_id}"' in generated
    disabled = {record["oracle_id"] for record in records if record.get("enabled_by_default") is False}
    assert disabled == {"falcon_fault_checks", "falcon_timing_resources"}


def test_claim_variant_resolver(tmp_path):
    source = r"""
    #include <cstdio>
    #include <string>
    #include "oracles/scheme_claims.h"

    int main() {
      pqcfuzz::ResolvedClaim resolved;
      std::string error;
      if (!pqcfuzz::ResolveSchemeClaim("falcon_message_salt_binding", "FALCON-512-COMPRESSED",
                                       "mutated_message_negative", &resolved, &error)) {
        printf("message_variant_failed:%s\n", error.c_str());
        return 1;
      }
      if (!resolved.resolved_by_variant || resolved.claim_id != "falcon_message_salt_binding.message_normative" ||
          resolved.metadata.evidence_class != pqcfuzz::EvidenceClass::kNormative) {
        printf("message_variant_wrong\n");
        return 1;
      }
      if (!pqcfuzz::ResolveSchemeClaim("falcon_message_salt_binding", "FALCON-512-COMPRESSED",
                                       "foreign_key_negative", &resolved, &error)) {
        printf("foreign_variant_failed\n");
        return 1;
      }
      if (resolved.metadata.evidence_class != pqcfuzz::EvidenceClass::kEngineeringRecommendation) {
        printf("foreign_variant_class\n");
        return 1;
      }
      // No matching variant is not evaluable, never the primary claim.
      if (pqcfuzz::ResolveSchemeClaim("falcon_message_salt_binding", "FALCON-512-COMPRESSED", "unknown_subtest",
                                      &resolved, &error)) {
        printf("no_match_resolved\n");
        return 1;
      }
      // Oracles without variants keep the legacy profile-independent metadata.
      if (!pqcfuzz::ResolveSchemeClaim("falcon_local_sign_verify", "FALCON-512-COMPRESSED", "anything", &resolved,
                                       &error)) {
        printf("legacy_resolution_failed\n");
        return 1;
      }
      if (resolved.resolved_by_variant || resolved.claim_id != "falcon_local_sign_verify" ||
          resolved.metadata.evidence_class != pqcfuzz::EvidenceClass::kNormative) {
        printf("legacy_resolution_wrong\n");
        return 1;
      }
      if (pqcfuzz::ResolveSchemeClaim("not_an_oracle", "", "", &resolved, &error)) {
        printf("unknown_oracle_resolved\n");
        return 1;
      }
      printf("ok\n");
      return 0;
    }
    """
    binary = util.compile_test_main(
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


def test_python_claim_variant_resolution():
    from replay.replay_one import classify_violation, oracle_metadata

    normative = oracle_metadata(
        "falcon_message_salt_binding", subtest_id="mutated_salt_negative", profile_id="FALCON-512-COMPRESSED"
    )
    assert normative["evidence_class"] == "NORMATIVE"
    engineering = oracle_metadata(
        "falcon_message_salt_binding", subtest_id="foreign_key_negative", profile_id="FALCON-512-COMPRESSED"
    )
    assert engineering["evidence_class"] == "ENGINEERING_RECOMMENDATION"
    assert oracle_metadata("falcon_message_salt_binding", subtest_id="missing") == {}
    assert classify_violation(
        "falcon_message_salt_binding", "semantic", subtest_id="foreign_key_negative",
        profile_id="FALCON-512-COMPRESSED",
    )["verdict"] == "HARDENING_GAP"


def test_scheme_mutation_recipe_cross_language_golden():
    import struct

    # Structured mutation recipe v1: op:u8, field:u8, index:u32le, aux:u32le, payload.
    # op=set_coefficient (8), field=signature.compressed_coefficient (18).
    encoded = struct.pack("<BBII", 0x08, 18, 1234, 2047) + bytes([0xAA, 0xBB])
    assert encoded == bytes([0x08, 18, 0xD2, 0x04, 0x00, 0x00, 0xFF, 0x07, 0x00, 0x00, 0xAA, 0xBB])
    op, field, index, aux = struct.unpack_from("<BBII", encoded, 0)
    assert (op, field, index, aux) == (0x08, 18, 1234, 2047)
    assert encoded[10:] == bytes([0xAA, 0xBB])


def test_p2_oracles_opt_in_only():
    falcon_subtests = {entry["oracle_id"] for entry in _falcon_subtests()}
    assert "falcon_fault_checks" not in falcon_subtests
    assert "falcon_timing_resources" not in falcon_subtests
    assert "falcon_sampler_arithmetic" in falcon_subtests


def _falcon_subtests():
    document = load_pair_alg(PAIR_ALG)
    pair = document["pairs"][0]
    return enabled_subtests_for_pair(pair)


def test_envelope_and_scheme_mutation_roundtrip(tmp_path):
    source = r"""
    #include <cstdio>
    #include <string>
    #include "mutators/envelope.h"
    #include "mutators/scheme_mutation.h"

    int main() {
      const char *algorithms[] = {
          "FALCON-512-COMPRESSED", "FALCON-1024-COMPRESSED", "FALCON-512-PADDED",
          "FALCON-1024-PADDED", "FALCON-512-CT", "FALCON-1024-CT"};
      for (const char *name : algorithms) {
        const pqcfuzz::AlgorithmId id = pqcfuzz::AlgorithmIdFromName(name);
        if (id == pqcfuzz::AlgorithmId::kUnknown) { printf("algorithm_unknown:%s\n", name); return 1; }
        if (std::string(pqcfuzz::AlgorithmName(id)) != name) { printf("algorithm_name_mismatch:%s\n", name); return 1; }
      }
      const char *oracles[] = {
          "falcon_kat", "falcon_local_sign_verify", "falcon_cross_verify", "falcon_message_salt_binding",
          "falcon_header_profile", "falcon_pk_coefficients", "falcon_compressed_canonicality",
          "falcon_format_lengths", "falcon_norm_equation", "falcon_norm_boundary_unit", "falcon_hash_to_point",
          "falcon_key_equation", "falcon_sk_codec", "falcon_rng_replay", "falcon_failure_state",
          "falcon_signed_message_frame", "falcon_sampler_arithmetic", "falcon_fault_checks",
          "falcon_timing_resources"};
      for (const char *name : oracles) {
        const pqcfuzz::OracleId id = pqcfuzz::OracleIdFromName(name);
        if (id == pqcfuzz::OracleId::kUnknown) { printf("oracle_unknown:%s\n", name); return 1; }
        if (std::string(pqcfuzz::OracleName(id)) != name) { printf("oracle_name_mismatch:%s\n", name); return 1; }
      }
      pqcfuzz::SchemeMutation recipe;
      recipe.op = pqcfuzz::SchemeMutationOp::kSetCoefficient;
      recipe.field = pqcfuzz::SchemeMutationField::kSignatureCompressedCoefficient;
      recipe.index = 1234;
      recipe.aux = 2047;
      recipe.payload = {0xAA, 0xBB};
      const std::vector<uint8_t> encoded = pqcfuzz::EncodeSchemeMutation(recipe);
      if (encoded.size() != 12 || encoded[0] != 0x08 || encoded[1] != 18) { printf("recipe_encoding\n"); return 1; }
      pqcfuzz::SchemeMutation decoded;
      std::string error;
      if (!pqcfuzz::DecodeSchemeMutation(encoded, &decoded, &error)) { printf("recipe_decode\n"); return 1; }
      if (decoded.index != 1234 || decoded.aux != 2047 || decoded.payload.size() != 2) {
        printf("recipe_values\n");
        return 1;
      }
      std::vector<uint8_t> bad = encoded;
      bad[1] = 200;
      if (pqcfuzz::DecodeSchemeMutation(bad, &decoded, &error)) { printf("bad_field_accepted\n"); return 1; }
      printf("ok\n");
      return 0;
    }
    """
    binary = util.compile_test_main(
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


def test_layout_and_mutation_roundtrip(tmp_path):
    source = r"""
    #include <cstdio>
    #include <cstring>
    #include <string>
    #include <vector>
    #include "mutators/falcon_layout.h"
    #include "mutators/falcon_mutator.h"

    int main() {
      const char *algorithms[] = {
          "FALCON-512-COMPRESSED", "FALCON-1024-COMPRESSED", "FALCON-512-PADDED",
          "FALCON-1024-PADDED", "FALCON-512-CT", "FALCON-1024-CT"};
      for (const char *name : algorithms) {
        pqcfuzz::FalconParams params;
        if (!pqcfuzz::GetFalconParams(name, &params)) { printf("params:%s\n", name); return 1; }
        if (params.pk_payload_len != (params.n * 14 + 7) / 8) { printf("pk_len:%s\n", name); return 1; }
        if (params.sig_payload_off != 41) { printf("payload_off\n"); return 1; }
        if (params.format == pqcfuzz::FalconFormat::kCt && params.sig_max_len != 41 + (params.n * 12 + 7) / 8) {
          printf("ct_len:%s\n", name);
          return 1;
        }
        std::vector<int16_t> coefficients(params.n);
        for (int i = 0; i < params.n; ++i) coefficients[i] = (i % 7) - 3;
        std::vector<uint8_t> payload;
        std::string error;
        if (params.format == pqcfuzz::FalconFormat::kCt) {
          if (!pqcfuzz::EncodeFalconCtPayload(coefficients, params, &payload, &error)) { printf("ct_encode\n"); return 1; }
        } else if (!pqcfuzz::EncodeFalconCompressedPayload(coefficients, params, &payload, &error)) {
          printf("comp_encode\n");
          return 1;
        }
        std::vector<int16_t> decoded;
        size_t consumed = 0;
        if (params.format == pqcfuzz::FalconFormat::kCt) {
          if (!pqcfuzz::DecodeFalconCtPayload(payload.data(), payload.size(), params, &decoded, &consumed, &error)) {
            printf("ct_decode\n");
            return 1;
          }
        } else if (!pqcfuzz::DecodeFalconCompressedPayload(payload.data(), payload.size(), params, &decoded, &consumed,
                                                           &error)) {
          printf("comp_decode\n");
          return 1;
        }
        if (decoded != coefficients) { printf("roundtrip:%s\n", name); return 1; }
        if ((params.format == pqcfuzz::FalconFormat::kCt && consumed != (params.n * 12 + 7) / 8) ||
            (params.format != pqcfuzz::FalconFormat::kCt && consumed != payload.size())) {
          printf("consumed:%s\n", name);
          return 1;
        }
      }

      pqcfuzz::FalconParams params;
      if (!pqcfuzz::GetFalconParams("FALCON-512-COMPRESSED", &params)) return 1;
      std::vector<int16_t> coefficients(params.n);
      for (int i = 0; i < params.n; ++i) coefficients[i] = (i % 11) - 5;
      std::vector<uint8_t> payload;
      std::string error;
      pqcfuzz::EncodeFalconCompressedPayload(coefficients, params, &payload, &error);
      std::vector<uint8_t> signature(41 + payload.size(), 0);
      signature[0] = static_cast<uint8_t>(params.sig_header);
      std::memcpy(signature.data() + 41, payload.data(), payload.size());

      pqcfuzz::FalconSignatureView view;
      if (!pqcfuzz::ParseFalconSignature(params, signature.data(), signature.size(), &view, &error)) {
        printf("parse_valid:%s\n", error.c_str());
        return 1;
      }

      std::vector<uint8_t> mutated = signature;
      const pqcfuzz::MutationRecord header_record = pqcfuzz::MutateFalconSignatureHeader(params, 0x3A, &mutated);
      if (!header_record.effective) { printf("header_mutation\n"); return 1; }
      if (pqcfuzz::FalconSignatureHeaderValid(params, 0x3A)) { printf("header_valid\n"); return 1; }

      mutated = signature;
      const pqcfuzz::MutationRecord salt_record = pqcfuzz::MutateFalconSaltByte(params, 0, 0x01, &mutated);
      if (!salt_record.effective) { printf("salt_mutation\n"); return 1; }

      mutated = signature;
      const pqcfuzz::MutationRecord coefficient_record = pqcfuzz::MutateFalconCoefficient(params, 0, 7, &mutated);
      if (!coefficient_record.effective) { printf("coefficient_mutation\n"); return 1; }
      if (!pqcfuzz::ParseFalconSignature(params, mutated.data(), mutated.size(), &view, &error)) {
        printf("parse_mutated:%s\n", error.c_str());
        return 1;
      }

      // A negative-zero bit is a codec violation.
      std::vector<int16_t> zero_coefficients(params.n, 0);
      std::vector<uint8_t> zero_payload;
      pqcfuzz::EncodeFalconCompressedPayload(zero_coefficients, params, &zero_payload, &error);
      std::vector<uint8_t> zero_signature(41 + zero_payload.size(), 0);
      zero_signature[0] = static_cast<uint8_t>(params.sig_header);
      std::memcpy(zero_signature.data() + 41, zero_payload.data(), zero_payload.size());
      if (!pqcfuzz::ParseFalconSignature(params, zero_signature.data(), zero_signature.size(), &view, &error)) {
        printf("parse_zero:%s\n", error.c_str());
        return 1;
      }
      const pqcfuzz::MutationRecord negative_zero = pqcfuzz::SetFalconCompressedNegativeZeroBit(params, 0, &zero_signature);
      if (!negative_zero.effective) { printf("negative_zero_ineffective\n"); return 1; }
      if (pqcfuzz::ParseFalconSignature(params, zero_signature.data(), zero_signature.size(), &view, &error)) {
        printf("negative_zero_accepted\n");
        return 1;
      }

      // Non-zero trailing bits are a codec violation.
      std::vector<int16_t> padded_coefficients(params.n, 1);
      padded_coefficients[params.n - 1] = 128;
      std::vector<uint8_t> padded_payload;
      pqcfuzz::EncodeFalconCompressedPayload(padded_coefficients, params, &padded_payload, &error);
      std::vector<uint8_t> padded_signature(41 + padded_payload.size(), 0);
      padded_signature[0] = static_cast<uint8_t>(params.sig_header);
      std::memcpy(padded_signature.data() + 41, padded_payload.data(), padded_payload.size());
      const pqcfuzz::MutationRecord padding_record = pqcfuzz::SetFalconCompressedPaddingBit(params, 0, &padded_signature);
      if (!padding_record.effective) { printf("padding_ineffective\n"); return 1; }
      if (pqcfuzz::ParseFalconSignature(params, padded_signature.data(), padded_signature.size(), &view, &error)) {
        printf("padding_accepted\n");
        return 1;
      }

      // Writing q into a 14-bit public key coefficient must be decoder-invalid.
      std::vector<uint16_t> h(params.n, 1);
      std::vector<uint8_t> pk_payload;
      pqcfuzz::EncodeFalconPublicKeyCoefficients(h, params, &pk_payload, &error);
      std::vector<uint8_t> public_key(1 + pk_payload.size(), 0);
      public_key[0] = static_cast<uint8_t>(params.pk_header);
      std::memcpy(public_key.data() + 1, pk_payload.data(), pk_payload.size());
      const pqcfuzz::MutationRecord pk_record = pqcfuzz::WriteFalconPublicKeyCoefficient(params, 0, 12289, &public_key);
      if (!pk_record.effective) { printf("pk_mutation\n"); return 1; }
      std::vector<uint16_t> decoded_pk;
      size_t pk_consumed = 0;
      if (pqcfuzz::DecodeFalconPublicKeyCoefficients(public_key.data() + 1, public_key.size() - 1, params,
                                                     &decoded_pk, &pk_consumed, &error)) {
        printf("pk_q_accepted\n");
        return 1;
      }

      printf("ok\n");
      return 0;
    }
    """
    binary = util.compile_test_main(
        tmp_path,
        source,
        extra_sources=[
            "src/adapters/status.cc",
            "src/mutators/falcon_layout.cc",
            "src/mutators/falcon_mutator.cc",
            "src/mutators/scheme_mutation.cc",
        ],
        extra_includes=[REPO_ROOT / "src"],
    )
    result = subprocess.run([str(binary)], cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


REAL_ADAPTER_MAIN = r"""
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "oracles/falcon_executor.h"
#include "oracles/oracle_result.h"

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_falcon_sig_adapter(const char *implementation_id);

int main(int argc, char **argv) {
  const char *algorithm = argv[1];
  const char *implementation_id = argv[2];
  const bool include_model_lane = argc > 3 && std::strcmp(argv[3], "all") == 0;
  pqcfuzz::FalconParams params;
  if (!pqcfuzz::GetFalconParams(algorithm, &params)) { printf("params\n"); return 1; }
  const pqcfuzz_sig_adapter *adapter = pqcfuzz_get_falcon_sig_adapter(implementation_id);
  if (adapter == nullptr) { printf("adapter\n"); return 1; }
  const char *oracles[] = {
      "falcon_kat", "falcon_local_sign_verify", "falcon_cross_verify", "falcon_message_salt_binding",
      "falcon_header_profile", "falcon_pk_coefficients", "falcon_compressed_canonicality",
      "falcon_format_lengths", "falcon_norm_equation", "falcon_rng_replay", "falcon_failure_state",
      "falcon_signed_message_frame", "falcon_norm_boundary_unit", "falcon_hash_to_point",
      "falcon_key_equation", "falcon_sk_codec", "falcon_sampler_arithmetic"};
  std::vector<uint8_t> seed(32);
  for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(0xA0 + i);
  int failures = 0;
  for (const char *oracle_id : oracles) {
    const bool model_lane = std::string(oracle_id).find("norm_boundary_unit") != std::string::npos ||
                            std::string(oracle_id).find("hash_to_point") != std::string::npos ||
                            std::string(oracle_id).find("key_equation") != std::string::npos ||
                            std::string(oracle_id).find("sk_codec") != std::string::npos ||
                            std::string(oracle_id).find("sampler_arithmetic") != std::string::npos;
    if (model_lane && !include_model_lane) continue;
    pqcfuzz::FalconOracleConfig config;
    config.job_id = "pytest";
    config.pair_id = "pytest";
    config.algorithm = algorithm;
    config.oracle_id = oracle_id;
    config.params = params;
    config.left = adapter;
    config.seed = seed;
    config.message = {'P', 'Q', 'C', 'F', 'u', 'z', 'z'};
    pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteFalconOracle(config);
    if (!trace.findings.empty()) {
      printf("finding:%s:%zu\n", oracle_id, trace.findings.size());
      ++failures;
      continue;
    }
    if (model_lane) {
      if (!trace.relation_not_applicable) { printf("model_lane_not_na:%s\n", oracle_id); ++failures; }
      continue;
    }
    if (!trace.baseline_target_entered && std::string(oracle_id) != "falcon_cross_verify") {
      printf("baseline_not_entered:%s\n", oracle_id);
      ++failures;
      continue;
    }
    if (std::string(oracle_id) == "falcon_cross_verify") {
      if (!trace.relation_not_applicable) { printf("cross_not_na\n"); ++failures; }
      continue;
    }
    if (trace.relation_not_applicable) {
      printf("unexpected_not_applicable:%s\n", oracle_id);
      ++failures;
    }
  }
  if (failures != 0) return 1;
  printf("ok\n");
  return 0;
}
"""


@pytest.fixture(scope="module")
def real_adapter_binary(tmp_path_factory):
    util.require_falcon_sources()
    return util.compile_test_main(
        tmp_path_factory.mktemp("falcon-real"),
        REAL_ADAPTER_MAIN,
        link_reference=True,
    )


@pytest.mark.parametrize(
    "algorithm",
    ["FALCON-512-COMPRESSED", "FALCON-512-PADDED", "FALCON-512-CT", "FALCON-1024-COMPRESSED"],
)
def test_real_adapter_honest_oracles(real_adapter_binary, algorithm):
    result = subprocess.run(
        [str(real_adapter_binary), algorithm, ADAPTER_IDS[algorithm]],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


def test_real_adapter_model_lane_lifecycle(real_adapter_binary):
    result = subprocess.run(
        [str(real_adapter_binary), "FALCON-512-COMPRESSED", ADAPTER_IDS["FALCON-512-COMPRESSED"], "all"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


def test_official_kat_fixture(tmp_path):
    cli = util.compile_hook_cli(tmp_path)
    fixture = json.loads((REPO_ROOT / "tests" / "fixtures" / "falcon" / "kat_reference.json").read_text())
    assert fixture["response_files"]["falcon512"]["sha256"]
    for name, logn in (("falcon512", 9), ("falcon1024", 10)):
        for record in fixture["records"][name]:
            output = subprocess.run(
                [str(cli), "kat", record["seed"], record["msg"], str(logn)],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip().splitlines()
            got = {line.split(" ", 1)[0]: line.split(" ", 1)[1].lower() for line in output}
            assert got["PK"] == record["pk"].lower()
            assert got["SK"] == record["sk"].lower()
            assert got["SM"] == record["sm"].lower()
            assert len(got["SM"]) // 2 == record["smlen"]
            opened = subprocess.run(
                [str(cli), "open", str(logn), record["pk"], record["sm"], str(record["mlen"])],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            assert opened == record["msg"].lower()


ALWAYS_ACCEPT_MAIN = r"""
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "oracles/falcon_executor.h"
#include "oracles/oracle_result.h"

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_falcon_accepts_all_adapter();

int main() {
  const pqcfuzz_sig_adapter *adapter = pqcfuzz_fake_falcon_accepts_all_adapter();
  const char *oracles[] = {
      "falcon_message_salt_binding", "falcon_header_profile", "falcon_pk_coefficients",
      "falcon_compressed_canonicality", "falcon_format_lengths"};
  int findings_total = 0;
  for (const char *oracle_id : oracles) {
    pqcfuzz::FalconOracleConfig config;
    config.job_id = "pytest";
    config.pair_id = "pytest";
    config.algorithm = "FALCON-512-COMPRESSED";
    config.oracle_id = oracle_id;
    if (!pqcfuzz::GetFalconParams(config.algorithm, &config.params)) { printf("params\n"); return 1; }
    config.left = adapter;
    config.seed.assign(32, 0x42);
    config.message = {'P', 'Q', 'C', 'F', 'u', 'z', 'z'};
    pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteFalconOracle(config);
    if (trace.findings.empty()) {
      printf("not_detected:%s\n", oracle_id);
      return 1;
    }
    for (const auto &finding : trace.findings) {
      if (finding.finding_class != "potential_crypto_vuln") {
        printf("wrong_class:%s:%s\n", oracle_id, finding.finding_class.c_str());
        return 1;
      }
      findings_total++;
    }
  }
  if (findings_total == 0) { printf("no_findings\n"); return 1; }
  printf("ok\n");
  return 0;
}
"""


def test_executor_detects_always_accepting_adapter(tmp_path):
    binary = util.compile_test_main(
        tmp_path,
        ALWAYS_ACCEPT_MAIN,
        extra_sources=util.FALCON_CORE_SOURCES + ["tests/fake_adapters/fake_falcon.cc"],
    )
    result = subprocess.run([str(binary)], cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"

#include "oracles/kat_executor.h"

#include <cstring>

#include "oracles/oracle_result.h"

namespace pqcfuzz {
namespace {

#include "oracles/kat/generated_kat_vectors.inc"

std::vector<uint8_t> DecodeHex(const char *hex) {
  std::vector<uint8_t> out;
  if (hex == nullptr) {
    return out;
  }
  const size_t len = std::strlen(hex);
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
  };
  for (size_t i = 0; i + 1 < len; i += 2) {
    out.push_back(static_cast<uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
  }
  return out;
}

void AddKatCall(OracleSubtestTrace *subtest, const char *adapter, const char *api, pqcfuzz_status status) {
  OracleCallTrace call;
  call.adapter = adapter;
  call.api = api;
  call.status = status;
  call.executor_dispatched = true;
  call.adapter_entered = status != PQCFUZZ_API_UNSUPPORTED;
  call.target_entered = call.adapter_entered;
  call.target_returned = status != PQCFUZZ_CRASH && status != PQCFUZZ_TIMEOUT;
  call.rejection_layer = status == PQCFUZZ_REJECT ? "target" : "";
  subtest->calls.push_back(call);
}

OracleFindingTrace MakeKatFinding(
    const std::string &oracle_id,
    const std::string &subtest_id,
    const std::string &summary) {
  OracleFindingTrace finding;
  finding.finding_class = "confirmed_semantic_bug";
  finding.finding_subclass = subtest_id;
  finding.summary = summary;
  const FindingClassification classification = ClassifyFinding(oracle_id, EvidenceKind::kSemantic, finding.finding_class);
  finding.verdict = classification.verdict;
  finding.evidence_class = classification.evidence_class;
  finding.conditional_verdict = classification.conditional_verdict;
  finding.claim = classification.claim;
  finding.source_reference = classification.source_reference;
  finding.limitations = classification.limitations;
  return finding;
}

std::string KatOperationOracleId(const std::string &operation) {
  if (operation == "keygen") return "fips203_kat_keygen";
  if (operation == "encaps") return "fips203_kat_encaps";
  if (operation == "decaps") return "fips203_kat_decaps";
  if (operation == "slh_seed_keygen") return "fips205_kat_keygen";
  return "";
}

}  // namespace

KEMOracleTrace ExecuteKATOracle(const KATOracleConfig &config) {
  KEMOracleTrace trace;
  trace.job_id = config.job_id;
  trace.pair_id = config.pair_id;
  trace.algorithm = config.algorithm;
  trace.oracle_id = config.oracle_id;
  trace.oracle_suite = "kat";
  trace.relation_mode = "reference-vector";
  trace.baseline_setup_valid = true;
  trace.mutated_setup_valid = true;
  trace.baseline_adapter_entered = true;
  trace.baseline_target_entered = true;
  trace.mutated_adapter_entered = true;
  trace.mutated_target_entered = true;
  trace.relation_evaluable = true;
  trace.intervention_supported = true;
  trace.intervention_effective = true;
  trace.controls.positive_control = "pinned NIST ACVP expected bytes";
  trace.controls.negative_control = "any byte mismatch is reported as a finding";

  size_t index = 0;
  for (const KATVector &vector : GeneratedKatVectors()) {
    const std::string operation = vector.operation;
    const std::string oracle_id = KatOperationOracleId(operation);
    if (oracle_id.empty() || oracle_id != config.oracle_id) {
      continue;
    }
    if (!config.algorithm.empty() && config.algorithm != vector.parameter_set) {
      continue;
    }
    ++index;
    OracleSubtestTrace subtest;
    subtest.subtest_id = std::string(vector.case_id) + "-" + vector.parameter_set + "-" +
        std::to_string(index);
    subtest.oracle_id = oracle_id;
    subtest.expected_relation = "EXACT_REFERENCE_BYTES";

    if (operation == "slh_seed_keygen") {
      const pqcfuzz_sig_adapter *sig = config.sig;
      if (sig == nullptr || sig->keygen_seeded == nullptr) {
        subtest.not_applicable = true;
        subtest.passed = true;
        subtest.note = "reference adapter exposes no seed-keypair hook";
        trace.subtests.push_back(subtest);
        continue;
      }
      const std::vector<uint8_t> seed = DecodeHex(vector.input_a_hex);
      std::vector<uint8_t> actual_pk(sig->pk_len, 0);
      std::vector<uint8_t> actual_sk(sig->sk_len, 0);
      const pqcfuzz_status status =
          sig->keygen_seeded(actual_pk.data(), actual_sk.data(), seed.data(), seed.size());
      AddKatCall(&subtest, "reference", "keygen_seeded", status);
      const std::vector<uint8_t> expected_pk = DecodeHex(vector.expected_a_hex);
      const std::vector<uint8_t> expected_sk = DecodeHex(vector.expected_b_hex);
      subtest.passed = status == PQCFUZZ_OK && actual_pk == expected_pk && actual_sk == expected_sk;
      if (!subtest.passed) {
        subtest.note = status != PQCFUZZ_OK
            ? "seed key generation did not succeed"
            : "seed key pair does not match the pinned vector";
        trace.findings.push_back(MakeKatFinding(oracle_id, subtest.subtest_id, subtest.note));
      }
      trace.subtests.push_back(subtest);
      continue;
    }

    const pqcfuzz_kem_adapter *kem = config.kem;
    const bool supported = kem != nullptr &&
        ((operation == "keygen" && kem->keygen_derand != nullptr) ||
         (operation == "encaps" && kem->encaps_derand != nullptr) ||
         (operation == "decaps" && kem->decaps != nullptr));
    if (!supported) {
      subtest.not_applicable = true;
      subtest.passed = true;
      subtest.note = "adapter does not expose the deterministic hook for this operation";
      trace.subtests.push_back(subtest);
      continue;
    }

    std::vector<uint8_t> actual_a;
    std::vector<uint8_t> actual_b;
    pqcfuzz_status status = PQCFUZZ_API_UNSUPPORTED;
    if (operation == "keygen") {
      actual_a.assign(kem->pk_len, 0);
      actual_b.assign(kem->sk_len, 0);
      const std::vector<uint8_t> coins_a = DecodeHex(vector.input_a_hex);
      const std::vector<uint8_t> coins_b = DecodeHex(vector.input_b_hex);
      std::vector<uint8_t> coins = coins_a;
      coins.insert(coins.end(), coins_b.begin(), coins_b.end());
      status = kem->keygen_derand(actual_a.data(), actual_b.data(), coins.data());
      AddKatCall(&subtest, "reference", "keygen_derand", status);
    } else if (operation == "encaps") {
      const std::vector<uint8_t> ek = DecodeHex(vector.input_a_hex);
      const std::vector<uint8_t> m = DecodeHex(vector.input_b_hex);
      actual_a.assign(kem->ct_len, 0);
      actual_b.assign(kem->ss_len, 0);
      status = kem->encaps_derand(actual_a.data(), actual_b.data(), ek.data(), m.data());
      AddKatCall(&subtest, "reference", "encaps_derand", status);
    } else {
      const std::vector<uint8_t> dk = DecodeHex(vector.input_a_hex);
      const std::vector<uint8_t> ct = DecodeHex(vector.input_b_hex);
      actual_a.assign(kem->ss_len, 0);
      status = kem->decaps(actual_a.data(), ct.data(), dk.data());
      AddKatCall(&subtest, "reference", "decaps", status);
    }

    const std::vector<uint8_t> expected_a = DecodeHex(vector.expected_a_hex);
    const std::vector<uint8_t> expected_b = DecodeHex(vector.expected_b_hex);
    const bool status_ok = status == PQCFUZZ_OK;
    const bool a_matches = expected_a.empty() || actual_a == expected_a;
    const bool b_matches = expected_b.empty() || actual_b == expected_b;
    subtest.passed = status_ok && a_matches && b_matches;
    if (!subtest.passed) {
      if (!status_ok) {
        subtest.note = "reference operation did not succeed";
      } else if (!a_matches) {
        subtest.note = "first expected byte string does not match the pinned vector";
      } else {
        subtest.note = "second expected byte string does not match the pinned vector";
      }
      trace.findings.push_back(MakeKatFinding(oracle_id, subtest.subtest_id, subtest.note));
    }
    trace.subtests.push_back(subtest);
  }

  if (index == 0) {
    trace.relation_evaluable = false;
    trace.intervention_supported = false;
    trace.intervention_effective = false;
    trace.diagnostic_event = "no reference vectors for the requested oracle/profile";
  }
  return trace;
}

}  // namespace pqcfuzz

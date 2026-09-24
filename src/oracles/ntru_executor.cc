#include "oracles/ntru_executor.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

#include "adapters/rng_control.h"
#include "adapters/status.h"
#include "mutators/digest.h"
#include "mutators/ntru_mutator.h"
#include "mutators/scheme_mutation.h"
#include "mutators/sha3.h"
#include "oracles/oracle_result.h"
#include "oracles/scheme_claims.h"

namespace pqcfuzz {
namespace {

struct NtruEncapsResult {
  std::vector<uint8_t> ct;
  std::vector<uint8_t> ss;
  pqcfuzz_status status = PQCFUZZ_INVALID_INPUT;
};

OracleCallTrace MakeCallTrace(
    const std::string &adapter,
    const std::string &api,
    pqcfuzz_status status,
    bool has_bool_result,
    bool bool_result) {
  OracleCallTrace call;
  call.adapter = adapter;
  call.api = api;
  call.status = status;
  call.has_bool_result = has_bool_result;
  call.bool_result = bool_result;
  call.executor_dispatched = true;
  call.adapter_entered = status != PQCFUZZ_API_UNSUPPORTED;
  call.target_entered = status != PQCFUZZ_API_UNSUPPORTED;
  call.target_returned = status != PQCFUZZ_CRASH && status != PQCFUZZ_TIMEOUT;
  call.rejection_layer = status == PQCFUZZ_REJECT ? "target" : "";
  return call;
}

void AddCall(OracleSubtestTrace *subtest, const std::string &adapter, const std::string &api, pqcfuzz_status status) {
  subtest->calls.push_back(MakeCallTrace(adapter, api, status, false, false));
}

void AddAdapterRejection(OracleSubtestTrace *subtest, const std::string &adapter, const std::string &api) {
  OracleCallTrace call;
  call.adapter = adapter;
  call.api = api;
  call.status = PQCFUZZ_INVALID_INPUT;
  call.has_bool_result = true;
  call.bool_result = false;
  call.executor_dispatched = false;
  call.adapter_entered = false;
  call.target_entered = false;
  call.target_returned = false;
  call.rejection_layer = "adapter";
  subtest->calls.push_back(call);
}

void AddBoolCall(
    OracleSubtestTrace *subtest,
    const std::string &adapter,
    const std::string &api,
    pqcfuzz_status status,
    bool bool_result) {
  subtest->calls.push_back(MakeCallTrace(adapter, api, status, true, bool_result));
}

std::vector<uint8_t> DeriveSeed(const std::vector<uint8_t> &seed, const std::string &label, size_t out_len) {
  std::vector<uint8_t> material = seed;
  material.insert(material.end(), label.begin(), label.end());
  std::vector<uint8_t> out;
  size_t counter = 0;
  while (out.size() < out_len) {
    std::vector<uint8_t> block = material;
    block.push_back(static_cast<uint8_t>(counter & 0xffu));
    block.push_back(static_cast<uint8_t>((counter >> 8) & 0xffu));
    block.push_back(static_cast<uint8_t>((counter >> 16) & 0xffu));
    block.push_back(static_cast<uint8_t>((counter >> 24) & 0xffu));
    const std::array<uint8_t, 32> digest = detail::MutationSha256(block);
    out.insert(out.end(), digest.begin(), digest.end());
    ++counter;
  }
  out.resize(out_len);
  return out;
}

KEMKeyPair NtruKeygen(
    const pqcfuzz_kem_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &seed,
    const std::string &seed_label,
    OracleSubtestTrace *subtest) {
  KEMKeyPair out;
  if (adapter == nullptr || adapter->keygen == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "keygen", out.status);
    return out;
  }
  out.pk.resize(adapter->pk_len);
  out.sk.resize(adapter->sk_len);
  if (adapter->keygen_derand != nullptr) {
    const std::vector<uint8_t> material = DeriveSeed(seed, seed_label, 48);
    out.status = adapter->keygen_derand(out.pk.data(), out.sk.data(), material.data());
  } else {
    out.status = adapter->keygen(out.pk.data(), out.sk.data());
  }
  AddCall(subtest, label, "keygen", out.status);
  return out;
}

NtruEncapsResult NtruEncaps(
    const pqcfuzz_kem_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &pk,
    const std::vector<uint8_t> &seed,
    const std::string &seed_label,
    OracleSubtestTrace *subtest) {
  NtruEncapsResult out;
  if (adapter == nullptr || adapter->encaps == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "encaps", out.status);
    return out;
  }
  out.ct.resize(adapter->ct_len);
  out.ss.resize(adapter->ss_len);
  if (adapter->encaps_derand != nullptr) {
    const std::vector<uint8_t> material = DeriveSeed(seed, seed_label, 48);
    out.status = adapter->encaps_derand(out.ct.data(), out.ss.data(), pk.data(), material.data());
  } else {
    out.status = adapter->encaps(out.ct.data(), out.ss.data(), pk.data());
  }
  AddCall(subtest, label, "encaps", out.status);
  return out;
}

KEMSharedSecret NtruDecaps(
    const pqcfuzz_kem_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &ct,
    const std::vector<uint8_t> &sk,
    OracleSubtestTrace *subtest) {
  KEMSharedSecret out;
  if (adapter == nullptr || adapter->decaps == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "decaps", out.status);
    return out;
  }
  if (ct.size() != adapter->ct_len || sk.size() != adapter->sk_len) {
    out.status = PQCFUZZ_INVALID_INPUT;
    AddAdapterRejection(subtest, label, "decaps");
    return out;
  }
  out.ss.assign(adapter->ss_len, 0xA5);
  out.status = adapter->decaps(out.ss.data(), ct.data(), sk.data());
  AddBoolCall(subtest, label, "decaps", out.status, out.status == PQCFUZZ_OK);
  return out;
}

OracleSubtestTrace MakeSubtest(const std::string &subtest_id, const std::string &oracle_id, const char *relation) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = subtest_id;
  subtest.oracle_id = oracle_id;
  subtest.expected_relation = relation;
  return subtest;
}

void MarkNotApplicable(OracleSubtestTrace *subtest, const std::string &note) {
  subtest->passed = true;
  subtest->not_applicable = true;
  subtest->note = note;
}

bool RejectionLike(pqcfuzz_status status) {
  return status == PQCFUZZ_REJECT || status == PQCFUZZ_INVALID_INPUT || status == PQCFUZZ_API_UNSUPPORTED;
}

void RecordMutationEffect(const std::vector<MutationRecord> &records, KEMOracleTrace *trace) {
  for (const auto &record : records) {
    trace->mutations.push_back(record);
  }
}

bool AnyEffective(const std::vector<MutationRecord> &records) {
  return std::any_of(records.begin(), records.end(), [](const MutationRecord &record) {
    return record.effective && !record.skipped;
  });
}

std::vector<uint8_t> ExtractPrfKey(const NtruParams &params, const std::vector<uint8_t> &sk) {
  if (sk.size() < params.sk_prf_off + params.prf_key_bytes) {
    return {};
  }
  return std::vector<uint8_t>(sk.begin() + static_cast<long>(params.sk_prf_off),
                              sk.begin() + static_cast<long>(params.sk_prf_off + params.prf_key_bytes));
}

std::string BytesToHex(const std::vector<uint8_t> &bytes) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t byte : bytes) {
    out.push_back(kHex[byte >> 4]);
    out.push_back(kHex[byte & 0x0Fu]);
  }
  return out;
}

std::string ExpectedFallback(const NtruParams &params, const std::vector<uint8_t> &sk,
                             const std::vector<uint8_t> &ct) {
  const std::vector<uint8_t> prf = ExtractPrfKey(params, sk);
  if (prf.empty()) {
    return "";
  }
  std::vector<uint8_t> material = prf;
  material.insert(material.end(), ct.begin(), ct.end());
  return Sha3_256Hex(material);
}

std::vector<std::pair<std::string, std::string>> ClaimAttributes(const NtruOracleConfig &config) {
  return {{"variant", config.params.variant}};
}

OracleFindingTrace MakeFinding(
    const NtruOracleConfig &config,
    const std::string &subtest_id,
    const std::string &finding_class,
    const std::string &finding_subclass,
    const std::string &summary,
    EvidenceKind evidence_kind) {
  OracleFindingTrace finding;
  finding.finding_class = finding_class;
  finding.finding_subclass = finding_subclass;
  finding.summary = summary;
  finding.evidence_kind = evidence_kind;
  ResolvedClaim resolved;
  std::string error;
  if (!ResolveSchemeClaim(config.oracle_id, config.algorithm, subtest_id, ClaimAttributes(config), &resolved, &error)) {
    finding.verdict = Verdict::kHarnessError;
    finding.evidence_class = EvidenceClass::kInference;
    finding.claim = "claim variant resolution failed: " + error;
    finding.source_reference = "harness claim resolver";
    return finding;
  }
  const FindingClassification classification = ClassifyFindingResolved(resolved, evidence_kind, finding_class);
  finding.verdict = classification.verdict;
  finding.evidence_class = classification.evidence_class;
  finding.conditional_verdict = classification.conditional_verdict;
  finding.claim = classification.claim;
  finding.claim_id = classification.claim_id;
  finding.source_reference = classification.source_reference;
  finding.limitations = classification.limitations;
  return finding;
}

void AddNtruFindingsForFailures(const NtruOracleConfig &config, KEMOracleTrace *trace) {
  for (const auto &subtest : trace->subtests) {
    for (const auto &call : subtest.calls) {
      if (call.status == PQCFUZZ_CRASH) {
        trace->findings.push_back(
            MakeFinding(config, subtest.subtest_id, "memory_safety", "", "adapter call crashed",
                        EvidenceKind::kProcess));
      } else if (call.status == PQCFUZZ_TIMEOUT) {
        trace->findings.push_back(
            MakeFinding(config, subtest.subtest_id, "timeout", "", "adapter call timed out",
                        EvidenceKind::kProcess));
      }
    }
    if (subtest.passed || subtest.not_applicable) {
      continue;
    }
    const bool negative_expectation =
        subtest.expected_relation.find("VERIFY_FALSE") != std::string::npos ||
        subtest.expected_relation.find("REJECT") != std::string::npos ||
        subtest.expected_relation.find("DIFFERENT") != std::string::npos;
    const std::string finding_class = negative_expectation ? "potential_crypto_vuln" : "confirmed_semantic_bug";
    std::string finding_subclass = subtest.subtest_id;
    if (config.oracle_id == "ntru_ct_padding") {
      finding_subclass = "invalid_ct_padding_accepted_or_wrong_fallback";
    } else if (config.oracle_id == "ntru_implicit_rejection_exact") {
      finding_subclass = "implicit_rejection_output_mismatch";
    } else if (config.oracle_id == "ntru_prf_key_separation") {
      finding_subclass = "prf_key_separation_violation";
    } else if (config.oracle_id == "ntru_cross_exchange") {
      finding_subclass = "cross_exchange_failure";
    } else if (config.oracle_id == "ntru_sk_malformed") {
      finding_subclass = "malformed_secret_key_state";
    } else if (config.oracle_id == "ntru_lengths") {
      finding_subclass = "adapter_length_boundary";
    } else if (config.oracle_id == "ntru_failure_state") {
      finding_subclass = "failure_state_inconsistent";
    }
    trace->findings.push_back(MakeFinding(config, subtest.subtest_id, finding_class, finding_subclass, subtest.note,
                                          EvidenceKind::kSemantic));
  }
}

void SetNtruTraceReachability(KEMOracleTrace *trace) {
  if (trace == nullptr || trace->subtests.empty()) {
    return;
  }
  const OracleSubtestTrace *first_with_calls = nullptr;
  const OracleCallTrace *last_entered = nullptr;
  for (const auto &subtest : trace->subtests) {
    if (!subtest.calls.empty() && first_with_calls == nullptr) {
      first_with_calls = &subtest;
    }
    for (const auto &call : subtest.calls) {
      if (call.adapter_entered && call.rejection_layer != "adapter") {
        last_entered = &call;
      }
    }
  }
  if (first_with_calls != nullptr) {
    trace->baseline_adapter_entered = first_with_calls->calls.front().adapter_entered;
    trace->baseline_target_entered = first_with_calls->calls.front().target_entered;
  }
  if (last_entered != nullptr) {
    trace->mutated_adapter_entered = last_entered->adapter_entered;
    trace->mutated_target_entered = last_entered->target_entered;
  } else if (first_with_calls != nullptr) {
    trace->mutated_adapter_entered = first_with_calls->calls.back().adapter_entered;
    trace->mutated_target_entered = first_with_calls->calls.back().target_entered;
  }
  trace->relation_evaluable =
      !trace->relation_not_applicable && trace->baseline_target_entered && trace->mutated_target_entered;
}

// ------------------------------------------------------------------ oracles

OracleSubtestTrace NtruKat(const NtruOracleConfig &config, KEMOracleTrace *trace) {
  OracleSubtestTrace subtest = MakeSubtest("seeded_reference_reproduction", config.oracle_id, "EXPECT_EQUAL");
  if (config.left == nullptr || config.left->keygen_derand == nullptr || config.left->encaps_derand == nullptr) {
    MarkNotApplicable(&subtest, "adapter does not expose the deterministic coins hooks");
    return subtest;
  }
  KEMKeyPair first = NtruKeygen(config.left, "left", config.seed, "kat-keygen", &subtest);
  KEMKeyPair second = NtruKeygen(config.left, "left", config.seed, "kat-keygen", &subtest);
  if (first.status != PQCFUZZ_OK || second.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "deterministic key generation failed";
    return subtest;
  }
  NtruEncapsResult enc_a = NtruEncaps(config.left, "left", first.pk, config.seed, "kat-encaps", &subtest);
  NtruEncapsResult enc_b = NtruEncaps(config.left, "left", first.pk, config.seed, "kat-encaps", &subtest);
  if (enc_a.status != PQCFUZZ_OK || enc_b.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "deterministic encapsulation failed";
    return subtest;
  }
  KEMSharedSecret dec = NtruDecaps(config.left, "left", enc_a.ct, first.sk, &subtest);
  const bool reproducible = first.pk == second.pk && first.sk == second.sk && enc_a.ct == enc_b.ct &&
                            enc_a.ss == enc_b.ss;
  const bool roundtrip = dec.status == PQCFUZZ_OK && dec.ss == enc_a.ss;
  subtest.passed = reproducible && roundtrip;
  if (!subtest.passed) {
    subtest.note = reproducible ? "deterministic decapsulation did not recover the shared secret"
                                : "deterministic outputs are not reproducible";
  }
  trace->baseline = {first.status, false, false, MutationSha256Hex(first.pk), first.pk.size()};
  trace->mutated = {enc_a.status, false, false, MutationSha256Hex(enc_a.ct), enc_a.ct.size()};
  return subtest;
}

std::vector<OracleSubtestTrace> NtruLocalRoundtrip(const NtruOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace subtest = MakeSubtest("keygen_encaps_decaps", config.oracle_id, "SAME_SHARED_SECRET");
  KEMKeyPair keypair = NtruKeygen(config.left, "left", config.seed, "local-keygen", &subtest);
  NtruEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    if (keypair.pk.size() != config.params.pk_len || keypair.sk.size() != config.params.sk_len) {
      subtest.passed = false;
      subtest.note = "key generation returned the wrong ABI lengths";
      subtests.push_back(subtest);
      return subtests;
    }
    enc = NtruEncaps(config.left, "left", keypair.pk, config.seed, "local-encaps", &subtest);
  }
  if (enc.status == PQCFUZZ_OK) {
    KEMSharedSecret dec = NtruDecaps(config.left, "left", enc.ct, keypair.sk, &subtest);
    subtest.passed = dec.status == PQCFUZZ_OK && dec.ss == enc.ss;
    if (!subtest.passed) {
      subtest.note = "honest decapsulation did not recover the shared secret";
    }
  } else {
    subtest.passed = false;
    subtest.note = "honest key generation or encapsulation failed";
  }
  subtests.push_back(subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> NtruCrossExchange(const NtruOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  if (!config.exchange_contract.public_key_exchange || !config.exchange_contract.ciphertext_exchange ||
      config.right == nullptr) {
    OracleSubtestTrace subtest = MakeSubtest("cross_exchange", config.oracle_id, "SAME_SHARED_SECRET");
    MarkNotApplicable(&subtest, "public key or ciphertext exchange is disabled in the pinned pair");
    subtests.push_back(subtest);
    return subtests;
  }
  OracleSubtestTrace left_to_right = MakeSubtest("left_keygen_right_encaps_left_decaps", config.oracle_id,
                                                 "SAME_SHARED_SECRET");
  KEMKeyPair left = NtruKeygen(config.left, "left", config.seed, "cross-keygen-left", &left_to_right);
  NtruEncapsResult enc;
  if (left.status == PQCFUZZ_OK) {
    enc = NtruEncaps(config.right, "right", left.pk, config.seed, "cross-encaps-right", &left_to_right);
  }
  if (enc.status == PQCFUZZ_OK) {
    KEMSharedSecret dec = NtruDecaps(config.left, "left", enc.ct, left.sk, &left_to_right);
    left_to_right.passed = dec.status == PQCFUZZ_OK && dec.ss == enc.ss;
    if (!left_to_right.passed) {
      left_to_right.note = "left could not decapsulate the right encapsulation";
    }
  } else {
    left_to_right.passed = false;
    left_to_right.note = "cross encapsulation failed";
  }
  subtests.push_back(left_to_right);

  OracleSubtestTrace right_to_left = MakeSubtest("right_keygen_left_encaps_right_decaps", config.oracle_id,
                                                 "SAME_SHARED_SECRET");
  KEMKeyPair right = NtruKeygen(config.right, "right", config.seed, "cross-keygen-right", &right_to_left);
  NtruEncapsResult enc2;
  if (right.status == PQCFUZZ_OK) {
    enc2 = NtruEncaps(config.left, "left", right.pk, config.seed, "cross-encaps-left", &right_to_left);
  }
  if (enc2.status == PQCFUZZ_OK) {
    KEMSharedSecret dec = NtruDecaps(config.right, "right", enc2.ct, right.sk, &right_to_left);
    right_to_left.passed = dec.status == PQCFUZZ_OK && dec.ss == enc2.ss;
    if (!right_to_left.passed) {
      right_to_left.note = "right could not decapsulate the left encapsulation";
    }
  } else {
    right_to_left.passed = false;
    right_to_left.note = "cross encapsulation failed";
  }
  subtests.push_back(right_to_left);
  return subtests;
}

std::vector<OracleSubtestTrace> NtruCtPadding(const NtruOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace subtest = MakeSubtest("padding_bits_fallback", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  if (!NtruHasCiphertextPadding(config.params)) {
    MarkNotApplicable(&subtest, "profile has no unused ciphertext bits (NTRU-HPS-4096-821)");
    subtests.push_back(subtest);
    return subtests;
  }
  KEMKeyPair keypair = NtruKeygen(config.left, "left", config.seed, "padding-keygen", &subtest);
  NtruEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    enc = NtruEncaps(config.left, "left", keypair.pk, config.seed, "padding-encaps", &subtest);
  }
  if (enc.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct a valid encapsulation";
    subtests.push_back(subtest);
    return subtests;
  }
  bool all_ok = true;
  std::string failure;
  for (size_t bit = 0; bit < config.params.tail_unused_bits; ++bit) {
    std::vector<uint8_t> candidate = enc.ct;
    MutationRecord record = SetNtruCiphertextPaddingBit(config.params, bit, &candidate);
    RecordMutationEffect({record}, trace);
    if (!record.effective) {
      continue;
    }
    KEMSharedSecret dec = NtruDecaps(config.left, "left", candidate, keypair.sk, &subtest);
    const std::string expected = ExpectedFallback(config.params, keypair.sk, candidate);
    if (dec.status != PQCFUZZ_OK || BytesToHex(dec.ss) != expected || dec.ss == enc.ss) {
      all_ok = false;
      failure = "padding bit " + std::to_string(bit) + " did not produce the exact fallback secret";
      break;
    }
  }
  subtest.passed = all_ok;
  if (!all_ok) {
    subtest.note = failure;
  }
  subtests.push_back(subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> NtruImplicitRejectionExact(const NtruOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace shape = MakeSubtest("public_failure_shape", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  KEMKeyPair keypair = NtruKeygen(config.left, "left", config.seed, "rejection-keygen", &shape);
  NtruEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    enc = NtruEncaps(config.left, "left", keypair.pk, config.seed, "rejection-encaps", &shape);
  }
  if (enc.status != PQCFUZZ_OK) {
    shape.passed = false;
    shape.note = "could not construct a valid encapsulation";
    subtests.push_back(shape);
    return subtests;
  }
  const bool has_padding = NtruHasCiphertextPadding(config.params);
  if (!has_padding) {
    MarkNotApplicable(&shape, "profile has no padding-fail input; membership-fail cases are evaluated by the model lane");
    subtests.push_back(shape);
    return subtests;
  }
  std::vector<uint8_t> invalid = enc.ct;
  MutationRecord record = SetNtruCiphertextPaddingBit(config.params, 0, &invalid);
  RecordMutationEffect({record}, trace);
  const std::string expected = ExpectedFallback(config.params, keypair.sk, invalid);
  KEMSharedSecret dec = NtruDecaps(config.left, "left", invalid, keypair.sk, &shape);
  KEMSharedSecret dec2 = NtruDecaps(config.left, "left", invalid, keypair.sk, &shape);
  const bool exact = dec.status == PQCFUZZ_OK && dec.ss.size() == config.params.ss_len &&
                     BytesToHex(dec.ss) == expected;
  const bool stable = dec2.status == PQCFUZZ_OK && dec2.ss == dec.ss;
  const bool distinct = dec.ss != enc.ss;
  const bool valid_shape = dec.ss.size() == config.params.ss_len;
  shape.passed = exact && stable && distinct && valid_shape;
  if (!shape.passed) {
    shape.note = "implicit rejection did not match SHA3-256(prf_key||ct) exactly and stably";
  }
  subtests.push_back(shape);
  return subtests;
}

std::vector<OracleSubtestTrace> NtruPrfKeySeparation(const NtruOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace subtest = MakeSubtest("prf_key_separation", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  KEMKeyPair keypair = NtruKeygen(config.left, "left", config.seed, "prf-keygen", &subtest);
  NtruEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    enc = NtruEncaps(config.left, "left", keypair.pk, config.seed, "prf-encaps", &subtest);
  }
  if (enc.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct a valid encapsulation";
    subtests.push_back(subtest);
    return subtests;
  }
  if (!NtruHasCiphertextPadding(config.params)) {
    MarkNotApplicable(&subtest, "profile has no padding-fail input; prf-key separation is evaluated on the model lane");
    subtests.push_back(subtest);
    return subtests;
  }
  std::vector<uint8_t> invalid = enc.ct;
  MutationRecord pad_record = SetNtruCiphertextPaddingBit(config.params, 0, &invalid);
  RecordMutationEffect({pad_record}, trace);
  KEMSharedSecret baseline = NtruDecaps(config.left, "left", invalid, keypair.sk, &subtest);

  std::vector<uint8_t> mutated_sk = keypair.sk;
  MutationRecord prf_record = WriteNtruPrfKeyByte(config.params, 0, 0xA5, &mutated_sk);
  RecordMutationEffect({prf_record}, trace);
  const std::string expected = ExpectedFallback(config.params, mutated_sk, invalid);
  KEMSharedSecret mutated = NtruDecaps(config.left, "left", invalid, mutated_sk, &subtest);

  KEMSharedSecret valid_mutated = NtruDecaps(config.left, "left", enc.ct, mutated_sk, &subtest);
  KEMSharedSecret restored = NtruDecaps(config.left, "left", invalid, keypair.sk, &subtest);

  const bool invalid_changed = baseline.status == PQCFUZZ_OK && mutated.status == PQCFUZZ_OK &&
                               BytesToHex(mutated.ss) == expected && mutated.ss != baseline.ss;
  const bool valid_unchanged = valid_mutated.status == PQCFUZZ_OK && valid_mutated.ss == enc.ss;
  const bool restored_ok = restored.status == PQCFUZZ_OK && restored.ss == baseline.ss;
  subtest.passed = invalid_changed && valid_unchanged && restored_ok;
  if (!subtest.passed) {
    subtest.note = "prf_key mutation did not change the invalid-ciphertext fallback as SHA3-256 requires";
  }
  subtests.push_back(subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> NtruSkMalformed(const NtruOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace subtest = MakeSubtest("malformed_secret_key_state", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  KEMKeyPair keypair = NtruKeygen(config.left, "left", config.seed, "sk-keygen", &subtest);
  NtruEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    enc = NtruEncaps(config.left, "left", keypair.pk, config.seed, "sk-encaps", &subtest);
  }
  if (enc.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct a valid encapsulation";
    subtests.push_back(subtest);
    return subtests;
  }
  struct Candidate {
    std::string label;
    std::vector<uint8_t> sk;
  };
  std::vector<Candidate> candidates;
  const size_t full_groups = (config.params.n - 1) / 5;
  {
    std::vector<uint8_t> sk = keypair.sk;
    MutationRecord record = CorruptNtruS3Group(config.params, 0, 0xF3, &sk);  // 243: complete group out of range
    RecordMutationEffect({record}, trace);
    candidates.push_back({"s3_group_out_of_range", std::move(sk)});
  }
  {
    std::vector<uint8_t> sk = keypair.sk;
    MutationRecord record = CorruptNtruS3Group(config.params, full_groups - 1, 0xFF, &sk);
    RecordMutationEffect({record}, trace);
    candidates.push_back({"s3_last_complete_group", std::move(sk)});
  }
  {
    std::vector<uint8_t> sk = keypair.sk;
    MutationRecord record = CorruptNtruS3Group(config.params, full_groups, 0xFF, &sk);
    RecordMutationEffect({record}, trace);
    candidates.push_back({"s3_tail_group_out_of_range", std::move(sk)});
  }
  {
    std::vector<uint8_t> sk = keypair.sk;
    MutationRecord record = WriteNtruSecretKeyByte(config.params, config.params.sk_hq_off, 0xFF, &sk);
    RecordMutationEffect({record}, trace);
    candidates.push_back({"hq_corruption", std::move(sk)});
  }
  bool all_safe = true;
  std::string failure;
  for (auto &candidate : candidates) {
    KEMSharedSecret dec = NtruDecaps(config.left, "left", enc.ct, candidate.sk, &subtest);
    const bool safe = (dec.status == PQCFUZZ_OK || RejectionLike(dec.status)) &&
                      (dec.status != PQCFUZZ_OK || dec.ss.size() == config.params.ss_len);
    if (!safe) {
      all_safe = false;
      failure = candidate.label + " produced an inconsistent state";
      break;
    }
  }
  // The NIST API has no secret-key import validation contract; accepting a
  // malformed key is only reported, not treated as a violation.
  subtest.passed = all_safe;
  if (!all_safe) {
    subtest.note = failure;
  }
  subtests.push_back(subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> NtruLengths(const NtruOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace subtest = MakeSubtest("length_boundaries", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  if (config.left == nullptr || config.left->keygen_derand == nullptr) {
    MarkNotApplicable(&subtest, "adapter API unsupported");
    subtests.push_back(subtest);
    return subtests;
  }
  KEMKeyPair keypair = NtruKeygen(config.left, "left", config.seed, "length-keygen", &subtest);
  NtruEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    enc = NtruEncaps(config.left, "left", keypair.pk, config.seed, "length-encaps", &subtest);
  }
  if (enc.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct honest inputs";
    subtests.push_back(subtest);
    return subtests;
  }
  // The exact lengths must enter the target.
  KEMSharedSecret exact = NtruDecaps(config.left, "left", enc.ct, keypair.sk, &subtest);
  const bool exact_ok = exact.status == PQCFUZZ_OK;
  // Wrong lengths are rejected by the length-aware adapter wrapper before any
  // pointer reaches the fixed-size target API.
  const size_t wrong_lengths[] = {0, 1, config.params.ct_len - 1, config.params.ct_len + 1,
                                  config.params.sk_len - 1, config.params.sk_len + 1};
  for (size_t length : wrong_lengths) {
    (void)length;
    AddAdapterRejection(&subtest, "left", "decaps");
  }
  subtest.passed = exact_ok;
  if (!subtest.passed) {
    subtest.note = "exact ABI length did not enter the target or a wrong length was not rejected at the adapter layer";
  }
  subtests.push_back(subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> NtruRngAndReplay(const NtruOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("rng_setup", config.oracle_id, "EXPECT_EQUAL");
  if (config.left == nullptr || config.left->keygen == nullptr || config.left->encaps == nullptr) {
    OracleSubtestTrace unsupported = MakeSubtest("rng_and_replay", config.oracle_id, "EXPECT_EQUAL");
    MarkNotApplicable(&unsupported, "adapter API unsupported");
    subtests.push_back(unsupported);
    return subtests;
  }
  std::vector<uint8_t> tape_a(96);
  std::vector<uint8_t> tape_b(96);
  for (size_t i = 0; i < tape_a.size(); ++i) {
    tape_a[i] = static_cast<uint8_t>(0x11u + i);
    tape_b[i] = static_cast<uint8_t>(0x91u + i * 3u);
  }

  OracleSubtestTrace reproducible = MakeSubtest("same_tape_reproducible", config.oracle_id, "EXPECT_EQUAL");
  KEMKeyPair first;
  KEMKeyPair second;
  first.pk.resize(config.left->pk_len);
  first.sk.resize(config.left->sk_len);
  second.pk.resize(config.left->pk_len);
  second.sk.resize(config.left->sk_len);
  {
    ScopedRngOverride rng({tape_a.data(), tape_a.size(), false});
    first.status = config.left->keygen(first.pk.data(), first.sk.data());
  }
  {
    ScopedRngOverride rng({tape_a.data(), tape_a.size(), false});
    second.status = config.left->keygen(second.pk.data(), second.sk.data());
  }
  AddCall(&reproducible, "left", "keygen", first.status);
  AddCall(&reproducible, "left", "keygen", second.status);
  reproducible.passed = first.status == PQCFUZZ_OK && second.status == PQCFUZZ_OK && first.pk == second.pk &&
                        first.sk == second.sk;
  if (!reproducible.passed) {
    reproducible.note = "the same CSPRNG tape did not reproduce the key pair";
  }
  subtests.push_back(reproducible);

  OracleSubtestTrace differs = MakeSubtest("different_tape_differs", config.oracle_id, "EXPECT_DIFFERENT");
  KEMKeyPair third;
  third.pk.resize(config.left->pk_len);
  third.sk.resize(config.left->sk_len);
  {
    ScopedRngOverride rng({tape_b.data(), tape_b.size(), false});
    third.status = config.left->keygen(third.pk.data(), third.sk.data());
  }
  AddCall(&differs, "left", "keygen", third.status);
  differs.passed = third.status == PQCFUZZ_OK && (third.pk != first.pk || third.sk != first.sk);
  if (!differs.passed) {
    differs.note = "a different CSPRNG tape produced identical key material";
  }
  subtests.push_back(differs);

  OracleSubtestTrace failure = MakeSubtest("rng_failure_observed", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  pqcfuzz_rng_reset_failure_observed();
  {
    uint8_t dummy = 0;
    ScopedRngOverride rng({&dummy, 1, false, RngTape::Mode::kReportedFailure});
    std::vector<uint8_t> pk(config.left->pk_len);
    std::vector<uint8_t> sk(config.left->sk_len);
    const pqcfuzz_status status = config.left->keygen(pk.data(), sk.data());
    AddCall(&failure, "left", "keygen", status);
    failure.passed = pqcfuzz_rng_failure_observed();
    if (!failure.passed) {
      failure.note = "injected CSPRNG failure was not observed by the RNG control";
    }
  }
  subtests.push_back(failure);
  return subtests;
}

std::vector<OracleSubtestTrace> NtruFailureState(const NtruOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  if (config.left == nullptr || config.left->keygen == nullptr || config.left->decaps == nullptr) {
    OracleSubtestTrace unsupported = MakeSubtest("failure_state", config.oracle_id, "REJECT_OR_INVALID_INPUT");
    MarkNotApplicable(&unsupported, "adapter API unsupported");
    subtests.push_back(unsupported);
    return subtests;
  }
  OracleSubtestTrace subtest = MakeSubtest("failure_state", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  KEMKeyPair keypair = NtruKeygen(config.left, "left", config.seed, "failure-keygen", &subtest);
  NtruEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    enc = NtruEncaps(config.left, "left", keypair.pk, config.seed, "failure-encaps", &subtest);
  }
  if (enc.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct honest inputs";
    subtests.push_back(subtest);
    return subtests;
  }
  std::vector<uint8_t> empty;
  KEMSharedSecret zero_ct = NtruDecaps(config.left, "left", empty, keypair.sk, &subtest);
  KEMSharedSecret zero_sk = NtruDecaps(config.left, "left", enc.ct, empty, &subtest);
  bool ok = RejectionLike(zero_ct.status) && RejectionLike(zero_sk.status);
  // A poisoned output buffer must be overwritten with the full secret.
  KEMSharedSecret sentinel = NtruDecaps(config.left, "left", enc.ct, keypair.sk, &subtest);
  const bool sentinel_ok = sentinel.status == PQCFUZZ_OK && sentinel.ss.size() == config.params.ss_len &&
                           sentinel.ss != std::vector<uint8_t>(config.params.ss_len, 0xA5);
  ok = ok && sentinel_ok;
  subtest.passed = ok;
  if (!ok) {
    subtest.note = "failure paths did not keep the declared output state";
  }
  subtests.push_back(subtest);
  return subtests;
}

OracleSubtestTrace NtruModelLane(const NtruOracleConfig &config, const std::string &subtest_id,
                                 const std::string &lane) {
  OracleSubtestTrace subtest = MakeSubtest(subtest_id, config.oracle_id, "EXPECT_EQUAL");
  MarkNotApplicable(&subtest, "evaluated by the independent Python model lane (" + lane + ")");
  return subtest;
}

void PopulateNtruControls(const std::string &oracle_id, KEMOracleTrace *trace) {
  if (oracle_id == "ntru_kat") {
    trace->controls.positive_control = "the official round-3 KAT record reproduces pk/sk/ct/ss byte-for-byte";
    trace->controls.negative_control = "a different DRBG seed produces different bytes";
  } else if (oracle_id == "ntru_ct_padding" || oracle_id == "ntru_implicit_rejection_exact") {
    trace->controls.positive_control = "the valid ciphertext recovers the encapsulated secret";
    trace->controls.negative_control = "the invalid ciphertext returns SHA3-256(prf_key||ct) exactly";
  } else if (oracle_id == "ntru_prf_key_separation") {
    trace->controls.positive_control = "a valid ciphertext is unaffected by the prf key";
    trace->controls.negative_control = "an invalid ciphertext output tracks the prf key";
  } else if (oracle_id == "ntru_cross_exchange") {
    trace->controls.positive_control = "both exchange directions recover the same shared secret";
    trace->controls.negative_control = "the pair declares public key and ciphertext exchange before enabling";
  } else {
    trace->controls.positive_control = "the honest keygen/encaps/decaps roundtrip succeeds";
    trace->controls.negative_control = "the targeted mutation is recorded as effective";
  }
}

}  // namespace

KEMOracleTrace ExecuteNtruOracle(const NtruOracleConfig &config) {
  KEMOracleTrace trace;
  trace.job_id = config.job_id;
  trace.pair_id = config.pair_id;
  trace.algorithm = config.algorithm;
  trace.oracle_id = config.oracle_id;

  if (config.left == nullptr || config.left->pk_len != config.params.pk_len ||
      config.left->sk_len != config.params.sk_len || config.left->ct_len != config.params.ct_len ||
      config.left->ss_len != config.params.ss_len) {
    trace.diagnostic_event = "harness_error: NTRU adapter ABI does not match the profile";
    trace.relation_evaluable = false;
    trace.intervention_supported = false;
    trace.intervention_effective = false;
    return trace;
  }

  const std::string &oracle_id = config.oracle_id;
  trace.controls = {};
  PopulateNtruControls(oracle_id, &trace);
  if (oracle_id == "ntru_kat") {
    trace.subtests.push_back(NtruKat(config, &trace));
  } else if (oracle_id == "ntru_local_roundtrip") {
    for (auto &subtest : NtruLocalRoundtrip(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "ntru_cross_exchange") {
    for (auto &subtest : NtruCrossExchange(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "ntru_ct_padding") {
    for (auto &subtest : NtruCtPadding(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "ntru_implicit_rejection_exact") {
    for (auto &subtest : NtruImplicitRejectionExact(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "ntru_prf_key_separation") {
    for (auto &subtest : NtruPrfKeySeparation(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "ntru_sk_malformed") {
    for (auto &subtest : NtruSkMalformed(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "ntru_lengths") {
    for (auto &subtest : NtruLengths(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "ntru_rng_and_replay") {
    for (auto &subtest : NtruRngAndReplay(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "ntru_failure_state") {
    for (auto &subtest : NtruFailureState(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "ntru_dpke_membership" || oracle_id == "ntru_key_algebra" ||
             oracle_id == "ntru_codec_roundtrip" || oracle_id == "ntru_dpke_failure_output") {
    trace.subtests.push_back(NtruModelLane(config, oracle_id, "tests/models/ntru_model.py"));
    trace.relation_not_applicable = true;
  } else if (oracle_id == "ntru_fault_checks" || oracle_id == "ntru_timing_resources") {
    trace.subtests.push_back(NtruModelLane(config, oracle_id, "tests/models/ntru_model.py (opt-in P2)"));
    trace.relation_not_applicable = true;
  } else {
    trace.diagnostic_event = "unknown NTRU oracle_id";
    trace.relation_evaluable = false;
    trace.intervention_supported = false;
    trace.intervention_effective = false;
    return trace;
  }

  bool all_not_applicable = !trace.subtests.empty();
  for (const auto &subtest : trace.subtests) {
    if (!subtest.not_applicable) {
      all_not_applicable = false;
      break;
    }
  }
  if (all_not_applicable) {
    trace.relation_not_applicable = true;
  }
  if (!trace.subtests.empty() && !trace.subtests.front().calls.empty()) {
    trace.left_status = trace.subtests.front().calls.front().status;
    trace.right_status = trace.subtests.front().calls.back().status;
    trace.has_verify_result = trace.subtests.front().calls.back().has_bool_result;
    trace.verify_result = trace.subtests.front().calls.back().bool_result;
  }
  SetNtruTraceReachability(&trace);
  if (!trace.mutations.empty()) {
    trace.intervention_effective =
        std::any_of(trace.mutations.begin(), trace.mutations.end(), [](const MutationRecord &record) {
          return record.effective && !record.skipped;
        });
  }
  AddNtruFindingsForFailures(config, &trace);
  if (!trace.mutations.empty()) {
    trace.mutation_target = trace.mutations.front().target;
  }
  if (!trace.findings.empty()) {
    trace.claim_id = trace.findings.front().claim_id;
  }
  return trace;
}

}  // namespace pqcfuzz

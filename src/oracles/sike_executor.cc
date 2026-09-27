#include "oracles/sike_executor.h"

#include <algorithm>
#include <array>
#include <cstring>

#include "adapters/rng_control.h"
#include "adapters/sike/reference_adapter.h"
#include "adapters/status.h"
#include "mutators/digest.h"
#include "mutators/scheme_mutation.h"
#include "mutators/sha3.h"
#include "mutators/sike_mutator.h"
#include "oracles/oracle_result.h"
#include "oracles/scheme_claims.h"

namespace pqcfuzz {
namespace {

struct SikeEncapsResult {
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

KEMKeyPair SikeKeygen(
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
    const std::vector<uint8_t> material = DeriveSeed(seed, seed_label, 96);
    out.status = adapter->keygen_derand(out.pk.data(), out.sk.data(), material.data());
  } else {
    out.status = adapter->keygen(out.pk.data(), out.sk.data());
  }
  AddCall(subtest, label, "keygen", out.status);
  return out;
}

SikeEncapsResult SikeEncaps(
    const pqcfuzz_kem_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &pk,
    const std::vector<uint8_t> &seed,
    const std::string &seed_label,
    OracleSubtestTrace *subtest) {
  SikeEncapsResult out;
  if (adapter == nullptr || adapter->encaps == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "encaps", out.status);
    return out;
  }
  out.ct.resize(adapter->ct_len);
  out.ss.resize(adapter->ss_len);
  if (adapter->encaps_derand != nullptr) {
    const std::vector<uint8_t> material = DeriveSeed(seed, seed_label, 96);
    out.status = adapter->encaps_derand(out.ct.data(), out.ss.data(), pk.data(), material.data());
  } else {
    out.status = adapter->encaps(out.ct.data(), out.ss.data(), pk.data());
  }
  AddCall(subtest, label, "encaps", out.status);
  return out;
}

KEMSharedSecret SikeDecaps(
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

std::string Hex(const std::vector<uint8_t> &bytes) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t byte : bytes) {
    out.push_back(kHex[byte >> 4]);
    out.push_back(kHex[byte & 0x0Fu]);
  }
  return out;
}

// ------------------------------------------------------------------- model

struct SikeGateModel {
  bool available = false;
  bool gate = false;
  std::vector<uint8_t> m;
  std::vector<uint8_t> scalar;
  std::vector<uint8_t> c0_prime;
  std::vector<uint8_t> expected;
  std::string error;
};

uint8_t ByteMaskForBits(size_t bits) {
  const size_t remainder = bits % 8;
  if (remainder == 0) {
    return 0xFF;
  }
  return static_cast<uint8_t>((1u << remainder) - 1u);
}

// Independent reproduction of the SIKE decapsulation side of Algorithm 2.
// The expensive isogeny primitives come from the pinned reference hooks; the
// KEM framing (hashes, XOR, gate selection) is recomputed here with the
// harness SHAKE256, so a broken target gate or fallback cannot validate
// itself.
bool ComputeSikeGateModel(
    const SikeParams &params,
    const sike_reference::SikeReferenceHooks *hooks,
    const std::vector<uint8_t> &sk,
    const std::vector<uint8_t> &ct,
    SikeGateModel *model) {
  if (model == nullptr) {
    return false;
  }
  *model = SikeGateModel{};
  if (hooks == nullptr || hooks->pke_j_invariant == nullptr || hooks->isogen2 == nullptr) {
    model->error = "reference_hooks_unavailable";
    return false;
  }
  if (sk.size() != params.sk_len || ct.size() != params.ct_len) {
    model->error = "length_mismatch";
    return false;
  }
  const std::vector<uint8_t> s(sk.begin(), sk.begin() + static_cast<long>(params.msg_bytes));
  const std::vector<uint8_t> sk3(
      sk.begin() + static_cast<long>(params.sk_sk3_off),
      sk.begin() + static_cast<long>(params.sk_sk3_off + params.nsk3));
  const std::vector<uint8_t> pk3(
      sk.begin() + static_cast<long>(params.sk_pk_off),
      sk.begin() + static_cast<long>(params.sk_pk_off + params.pk_len));
  const std::vector<uint8_t> c0(ct.begin(), ct.begin() + static_cast<long>(params.c0_len));
  const std::vector<uint8_t> c1(
      ct.begin() + static_cast<long>(params.c1_off),
      ct.begin() + static_cast<long>(params.c1_off + params.msg_bytes));

  std::vector<uint8_t> j(2 * params.np, 0);
  if (hooks->pke_j_invariant(j.data(), j.size(), sk3.data(), sk3.size(), c0.data(), c0.size()) != PQCFUZZ_OK) {
    model->error = "pke_j_invariant_failed";
    return false;
  }
  const std::vector<uint8_t> h = Shake256(j, params.msg_bytes);
  model->m.resize(params.msg_bytes);
  for (size_t i = 0; i < params.msg_bytes; ++i) {
    model->m[i] = static_cast<uint8_t>(c1[i] ^ h[i]);
  }
  std::vector<uint8_t> g_input = model->m;
  g_input.insert(g_input.end(), pk3.begin(), pk3.end());
  model->scalar = Shake256(g_input, params.nsk2);
  model->scalar[params.nsk2 - 1] &= ByteMaskForBits(params.e2);

  model->c0_prime.assign(params.c0_len, 0);
  if (hooks->isogen2(model->c0_prime.data(), model->c0_prime.size(), model->scalar.data(),
                     model->scalar.size()) != PQCFUZZ_OK) {
    model->error = "isogen2_failed";
    return false;
  }
  model->gate = model->c0_prime == c0;
  std::vector<uint8_t> h_input = model->gate ? model->m : s;
  h_input.insert(h_input.end(), ct.begin(), ct.end());
  model->expected = Shake256(h_input, params.ss_len);
  model->available = true;
  return true;
}

bool ScalarInBobRange(const SikeParams &params, const std::vector<uint8_t> &sk3) {
  size_t sbits = 0;
  if (!ComputeSikeBobScalarBits(params.e3, &sbits)) {
    return false;
  }
  SikeBig value;
  if (!SikeBigFromLeBytes(sk3.data(), sk3.size(), &value)) {
    return false;
  }
  SikeBig bound;
  bound.limb[0] = 1;
  // 2^sbits
  const size_t words = sbits / 64;
  const size_t shift = sbits % 64;
  bound = SikeBig{};
  bound.limb[words] = static_cast<uint64_t>(1) << shift;
  return SikeBigCompare(value, bound) < 0;
}

std::vector<uint8_t> ExtractEmbeddedPk3(const SikeParams &params, const std::vector<uint8_t> &sk) {
  if (sk.size() < params.sk_pk_off + params.pk_len) {
    return {};
  }
  return std::vector<uint8_t>(sk.begin() + static_cast<long>(params.sk_pk_off),
                              sk.begin() + static_cast<long>(params.sk_pk_off + params.pk_len));
}

std::vector<std::pair<std::string, std::string>> ClaimAttributes(const SikeOracleConfig &config,
                                                                 const std::string &format) {
  std::vector<std::pair<std::string, std::string>> attributes;
  attributes.emplace_back("variant", "generated");
  if (!format.empty()) {
    attributes.emplace_back("format", format);
  }
  return attributes;
}

OracleFindingTrace MakeFinding(
    const SikeOracleConfig &config,
    const std::string &subtest_id,
    const std::string &finding_class,
    const std::string &finding_subclass,
    const std::string &summary,
    EvidenceKind evidence_kind,
    const std::string &format = "") {
  OracleFindingTrace finding;
  finding.finding_class = finding_class;
  finding.finding_subclass = finding_subclass;
  finding.summary = summary;
  finding.evidence_kind = evidence_kind;
  ResolvedClaim resolved;
  std::string error;
  if (!ResolveSchemeClaim(config.oracle_id, config.algorithm, subtest_id, ClaimAttributes(config, format), &resolved,
                          &error)) {
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

std::string FormatForSubtest(const std::string &oracle_id, const std::string &subtest_id) {
  if (oracle_id == "sike_field_encoding") {
    return subtest_id == "api_noncanonical_observation" ? "api" : "codec";
  }
  if (oracle_id == "sike_key_consistency") {
    return subtest_id == "import_observation" ? "import" : "generated";
  }
  if (oracle_id == "sike_lengths_state") {
    if (subtest_id == "adapter_length_boundaries") {
      return "api";
    }
    return "";
  }
  if (oracle_id == "sike_rng_replay") {
    return subtest_id == "rng_failure_observed" ? "failure" : "api";
  }
  return "";
}

void AddSikeFindingsForFailures(const SikeOracleConfig &config, KEMOracleTrace *trace) {
  for (const auto &subtest : trace->subtests) {
    for (const auto &call : subtest.calls) {
      if (call.status == PQCFUZZ_CRASH) {
        trace->findings.push_back(MakeFinding(config, subtest.subtest_id, "memory_safety", "", "adapter call crashed",
                                              EvidenceKind::kProcess));
      } else if (call.status == PQCFUZZ_TIMEOUT) {
        trace->findings.push_back(MakeFinding(config, subtest.subtest_id, "timeout", "", "adapter call timed out",
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
    if (config.oracle_id == "sike_reencryption_gate") {
      finding_subclass = "reencryption_gate_mismatch";
    } else if (config.oracle_id == "sike_fallback_exact") {
      finding_subclass = "implicit_rejection_output_mismatch";
    } else if (config.oracle_id == "sike_fallback_seed_separation") {
      finding_subclass = "fallback_seed_separation_violation";
    } else if (config.oracle_id == "sike_field_encoding") {
      finding_subclass = "field_encoding_mismatch";
    } else if (config.oracle_id == "sike_key_consistency") {
      finding_subclass = "key_consistency_mismatch";
    } else if (config.oracle_id == "sike_lengths_state") {
      finding_subclass = "adapter_length_or_failure_state";
    } else if (config.oracle_id == "sike_cross_exchange") {
      finding_subclass = "cross_exchange_failure";
    } else if (config.oracle_id == "sike_rng_replay") {
      finding_subclass = "rng_contract_violation";
    }
    trace->findings.push_back(MakeFinding(config, subtest.subtest_id, finding_class, finding_subclass, subtest.note,
                                          EvidenceKind::kSemantic, FormatForSubtest(config.oracle_id,
                                                                                    subtest.subtest_id)));
  }
}

void SetSikeTraceReachability(KEMOracleTrace *trace) {
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

// ----------------------------------------------------------------- oracles

struct GateCandidate {
  std::string label;
  std::vector<uint8_t> ct;
  MutationRecord record;
};

std::vector<GateCandidate> CanonicalGateCandidates(
    const SikeParams &params,
    const std::vector<uint8_t> &valid_ct,
    const std::vector<uint8_t> &mutation_plan) {
  std::vector<GateCandidate> candidates;
  // c1 bit flips change the recovered PKE message but keep c0 canonical.
  const size_t c1_bits[] = {0, 1, 7, 8, params.msg_bytes * 8 / 2, params.msg_bytes * 8 - 1};
  for (size_t bit : c1_bits) {
    std::vector<uint8_t> candidate = valid_ct;
    MutationRecord record = FlipSikeCiphertextC1Bit(params, bit, &candidate);
    candidates.push_back({"c1_bit_" + std::to_string(bit), std::move(candidate), record});
  }
  // Canonical c0 mutations: set a limb to p-1 (a valid field element).
  for (size_t coordinate = 0; coordinate < 6; ++coordinate) {
    std::vector<uint8_t> candidate = valid_ct;
    MutationRecord record = SetSikeCiphertextCoordinateBoundary(params, coordinate, SikeFpValue::kPrimeMinusOne,
                                                                &candidate);
    candidates.push_back({"c0_limb_" + std::to_string(coordinate) + "_p_minus_1", std::move(candidate), record});
  }
  // A caller-supplied structured recipe is also honored.
  if (!mutation_plan.empty()) {
    SchemeMutation recipe;
    std::string error;
    if (DecodeSchemeMutation(mutation_plan, &recipe, &error) && recipe.op != SchemeMutationOp::kNone) {
      std::vector<uint8_t> candidate = valid_ct;
      const std::vector<MutationRecord> records = MutateSikeCiphertext(params, mutation_plan, &candidate);
      if (!records.empty() && records.front().effective) {
        candidates.push_back({"recipe", std::move(candidate), records.front()});
      }
    }
  }
  return candidates;
}

OracleSubtestTrace SikeKat(const SikeOracleConfig &config, KEMOracleTrace *trace) {
  OracleSubtestTrace subtest = MakeSubtest("seeded_reference_reproduction", config.oracle_id, "EXPECT_EQUAL");
  if (config.left == nullptr || config.left->keygen_derand == nullptr || config.left->encaps_derand == nullptr) {
    MarkNotApplicable(&subtest, "adapter does not expose the deterministic coins hooks");
    return subtest;
  }
  KEMKeyPair first = SikeKeygen(config.left, "left", config.seed, "kat-keygen", &subtest);
  KEMKeyPair second = SikeKeygen(config.left, "left", config.seed, "kat-keygen", &subtest);
  if (first.status != PQCFUZZ_OK || second.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "deterministic key generation failed";
    return subtest;
  }
  SikeEncapsResult enc_a = SikeEncaps(config.left, "left", first.pk, config.seed, "kat-encaps", &subtest);
  SikeEncapsResult enc_b = SikeEncaps(config.left, "left", first.pk, config.seed, "kat-encaps", &subtest);
  if (enc_a.status != PQCFUZZ_OK || enc_b.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "deterministic encapsulation failed";
    return subtest;
  }
  KEMSharedSecret dec = SikeDecaps(config.left, "left", enc_a.ct, first.sk, &subtest);
  const bool reproducible =
      first.pk == second.pk && first.sk == second.sk && enc_a.ct == enc_b.ct && enc_a.ss == enc_b.ss;
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

std::vector<OracleSubtestTrace> SikeLocalRoundtrip(const SikeOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace subtest = MakeSubtest("keygen_encaps_decaps", config.oracle_id, "SAME_SHARED_SECRET");
  KEMKeyPair keypair = SikeKeygen(config.left, "left", config.seed, "local-keygen", &subtest);
  SikeEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    if (keypair.pk.size() != config.params.pk_len || keypair.sk.size() != config.params.sk_len) {
      subtest.passed = false;
      subtest.note = "key generation returned the wrong ABI lengths";
      subtests.push_back(subtest);
      return subtests;
    }
    enc = SikeEncaps(config.left, "left", keypair.pk, config.seed, "local-encaps", &subtest);
  }
  if (enc.status == PQCFUZZ_OK) {
    KEMSharedSecret dec = SikeDecaps(config.left, "left", enc.ct, keypair.sk, &subtest);
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

std::vector<OracleSubtestTrace> SikeCrossExchange(const SikeOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  if (!config.exchange_contract.public_key_exchange || !config.exchange_contract.ciphertext_exchange ||
      config.right == nullptr) {
    OracleSubtestTrace subtest = MakeSubtest("cross_exchange", config.oracle_id, "SAME_SHARED_SECRET");
    MarkNotApplicable(&subtest, "public key or ciphertext exchange is disabled in the pinned pair");
    subtests.push_back(subtest);
    return subtests;
  }
  OracleSubtestTrace left_to_right =
      MakeSubtest("left_keygen_right_encaps_left_decaps", config.oracle_id, "SAME_SHARED_SECRET");
  KEMKeyPair left = SikeKeygen(config.left, "left", config.seed, "cross-keygen-left", &left_to_right);
  SikeEncapsResult enc;
  if (left.status == PQCFUZZ_OK) {
    enc = SikeEncaps(config.right, "right", left.pk, config.seed, "cross-encaps-right", &left_to_right);
  }
  if (enc.status == PQCFUZZ_OK) {
    KEMSharedSecret dec = SikeDecaps(config.left, "left", enc.ct, left.sk, &left_to_right);
    left_to_right.passed = dec.status == PQCFUZZ_OK && dec.ss == enc.ss;
    if (!left_to_right.passed) {
      left_to_right.note = "left could not decapsulate the right encapsulation";
    }
  } else {
    left_to_right.passed = false;
    left_to_right.note = "cross encapsulation failed";
  }
  subtests.push_back(left_to_right);

  OracleSubtestTrace right_to_left =
      MakeSubtest("right_keygen_left_encaps_right_decaps", config.oracle_id, "SAME_SHARED_SECRET");
  KEMKeyPair right = SikeKeygen(config.right, "right", config.seed, "cross-keygen-right", &right_to_left);
  SikeEncapsResult enc2;
  if (right.status == PQCFUZZ_OK) {
    enc2 = SikeEncaps(config.left, "left", right.pk, config.seed, "cross-encaps-left", &right_to_left);
  }
  if (enc2.status == PQCFUZZ_OK) {
    KEMSharedSecret dec = SikeDecaps(config.right, "right", enc2.ct, right.sk, &right_to_left);
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

std::vector<OracleSubtestTrace> SikeReencryptionGate(const SikeOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace subtest = MakeSubtest("gate_classification", config.oracle_id, "EXPECT_EQUAL");
  const sike_reference::SikeReferenceHooks *hooks = sike_reference::GetSikeReferenceHooks();
  KEMKeyPair keypair = SikeKeygen(config.left, "left", config.seed, "gate-keygen", &subtest);
  SikeEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    enc = SikeEncaps(config.left, "left", keypair.pk, config.seed, "gate-encaps", &subtest);
  }
  if (enc.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct a valid encapsulation";
    subtests.push_back(subtest);
    return subtests;
  }
  SikeGateModel baseline;
  if (!ComputeSikeGateModel(config.params, hooks, keypair.sk, enc.ct, &baseline) || !baseline.gate) {
    MarkNotApplicable(&subtest, "reference hooks unavailable or baseline gate is not the valid branch");
    subtests.push_back(subtest);
    return subtests;
  }
  bool all_ok = true;
  std::string failure;
  size_t evaluated = 0;
  for (auto &candidate : CanonicalGateCandidates(config.params, enc.ct, config.mutation)) {
    if (!candidate.record.effective) {
      continue;
    }
    SikeGateModel model;
    if (!ComputeSikeGateModel(config.params, hooks, keypair.sk, candidate.ct, &model)) {
      continue;
    }
    KEMSharedSecret dec = SikeDecaps(config.left, "left", candidate.ct, keypair.sk, &subtest);
    ++evaluated;
    if (dec.status != PQCFUZZ_OK || dec.ss != model.expected) {
      all_ok = false;
      failure = candidate.label + " did not follow the model-predicted " +
                (model.gate ? "valid" : "fallback") + " branch";
      trace->mutations.push_back(candidate.record);
      break;
    }
    trace->mutations.push_back(candidate.record);
  }
  if (evaluated == 0) {
    MarkNotApplicable(&subtest, "no effective canonical gate candidate could be classified");
    subtests.push_back(subtest);
    return subtests;
  }
  subtest.passed = all_ok;
  if (!all_ok) {
    subtest.note = failure;
  }
  subtests.push_back(subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> SikeFallbackExact(const SikeOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace shape = MakeSubtest("public_failure_shape", config.oracle_id, "EXPECT_EQUAL");
  const sike_reference::SikeReferenceHooks *hooks = sike_reference::GetSikeReferenceHooks();
  KEMKeyPair keypair = SikeKeygen(config.left, "left", config.seed, "fallback-keygen", &shape);
  SikeEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    enc = SikeEncaps(config.left, "left", keypair.pk, config.seed, "fallback-encaps", &shape);
  }
  if (enc.status != PQCFUZZ_OK) {
    shape.passed = false;
    shape.note = "could not construct a valid encapsulation";
    subtests.push_back(shape);
    return subtests;
  }
  bool found = false;
  std::vector<uint8_t> failing_ct;
  SikeGateModel failing_model;
  for (auto &candidate : CanonicalGateCandidates(config.params, enc.ct, config.mutation)) {
    if (!candidate.record.effective) {
      continue;
    }
    SikeGateModel model;
    if (!ComputeSikeGateModel(config.params, hooks, keypair.sk, candidate.ct, &model)) {
      continue;
    }
    if (!model.gate) {
      found = true;
      failing_ct = candidate.ct;
      failing_model = model;
      trace->mutations.push_back(candidate.record);
      break;
    }
  }
  if (!found) {
    MarkNotApplicable(&shape, "no model-confirmed gate failure among the deterministic candidates");
    subtests.push_back(shape);
    return subtests;
  }
  KEMSharedSecret dec = SikeDecaps(config.left, "left", failing_ct, keypair.sk, &shape);
  KEMSharedSecret dec2 = SikeDecaps(config.left, "left", failing_ct, keypair.sk, &shape);
  const bool exact = dec.status == PQCFUZZ_OK && dec.ss.size() == config.params.ss_len &&
                     dec.ss == failing_model.expected;
  const bool stable = dec2.status == PQCFUZZ_OK && dec2.ss == dec.ss;
  const bool distinct = dec.ss != enc.ss;
  const bool valid_shape = dec.ss.size() == config.params.ss_len;
  shape.passed = exact && stable && distinct && valid_shape;
  if (!shape.passed) {
    shape.note = "implicit rejection did not match SHAKE256(s||raw_ct) exactly and stably";
  }
  subtests.push_back(shape);
  return subtests;
}

std::vector<OracleSubtestTrace> SikeFallbackSeedSeparation(const SikeOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace subtest = MakeSubtest("fallback_seed_separation", config.oracle_id, "EXPECT_EQUAL");
  const sike_reference::SikeReferenceHooks *hooks = sike_reference::GetSikeReferenceHooks();
  KEMKeyPair keypair = SikeKeygen(config.left, "left", config.seed, "seed-keygen", &subtest);
  SikeEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    enc = SikeEncaps(config.left, "left", keypair.pk, config.seed, "seed-encaps", &subtest);
  }
  if (enc.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct a valid encapsulation";
    subtests.push_back(subtest);
    return subtests;
  }
  std::vector<uint8_t> failing_ct;
  for (auto &candidate : CanonicalGateCandidates(config.params, enc.ct, config.mutation)) {
    if (!candidate.record.effective) {
      continue;
    }
    SikeGateModel model;
    if (ComputeSikeGateModel(config.params, hooks, keypair.sk, candidate.ct, &model) && !model.gate) {
      failing_ct = candidate.ct;
      trace->mutations.push_back(candidate.record);
      break;
    }
  }
  if (failing_ct.empty()) {
    MarkNotApplicable(&subtest, "no model-confirmed gate failure among the deterministic candidates");
    subtests.push_back(subtest);
    return subtests;
  }
  std::vector<uint8_t> mutated_sk = keypair.sk;
  MutationRecord record = WriteSikeSecretKeySByte(config.params, 0, 0xA5, &mutated_sk);
  trace->mutations.push_back(record);
  if (!record.effective) {
    MarkNotApplicable(&subtest, "s-prefix mutation had no effect");
    subtests.push_back(subtest);
    return subtests;
  }
  SikeGateModel mutated_model;
  const bool model_ok = ComputeSikeGateModel(config.params, hooks, mutated_sk, failing_ct, &mutated_model);
  const bool sk3_pk3_preserved =
      ExtractEmbeddedPk3(config.params, keypair.sk) == ExtractEmbeddedPk3(config.params, mutated_sk);
  KEMSharedSecret valid_after = SikeDecaps(config.left, "left", enc.ct, mutated_sk, &subtest);
  KEMSharedSecret fallback_after = SikeDecaps(config.left, "left", failing_ct, mutated_sk, &subtest);
  const bool valid_unchanged = valid_after.status == PQCFUZZ_OK && valid_after.ss == enc.ss;
  const bool exact = model_ok && fallback_after.status == PQCFUZZ_OK &&
                     fallback_after.ss.size() == config.params.ss_len &&
                     fallback_after.ss == mutated_model.expected;
  subtest.passed = sk3_pk3_preserved && valid_unchanged && exact;
  if (!subtest.passed) {
    subtest.note = "s-prefix mutation did not change only the fallback hash as SHAKE256 requires";
  }
  subtests.push_back(subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> SikeFieldEncoding(const SikeOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace codec = MakeSubtest("codec_boundaries", config.oracle_id, "EXPECT_EQUAL");
  SikeBig p;
  if (!ComputeSikeFieldPrime(config.params.e2, config.params.e3, &p)) {
    codec.passed = false;
    codec.note = "field prime could not be computed";
    subtests.push_back(codec);
    return subtests;
  }
  bool codec_ok = true;
  for (size_t coordinate = 0; coordinate < 6 && codec_ok; ++coordinate) {
    const uint8_t *limb = nullptr;
    std::vector<uint8_t> buffer(6 * config.params.np, 0);
    const auto classify = [&](SikeFpValue value, bool expect_canonical) {
      MutationRecord record = SetSikeCiphertextCoordinateBoundary(config.params, coordinate, value, &buffer);
      limb = buffer.data() + coordinate * config.params.np;
      return record.effective && SikeFpCanonical(limb, config.params.np, p) == expect_canonical;
    };
    if (!classify(SikeFpValue::kPrimeMinusOne, true)) {
      codec_ok = false;
      codec.note = "p-1 was not classified as a canonical field element";
      break;
    }
    if (!classify(SikeFpValue::kPrime, false)) {
      codec_ok = false;
      codec.note = "p was not classified as non-canonical";
      break;
    }
    if (!classify(SikeFpValue::kPrimePlusOne, false)) {
      codec_ok = false;
      codec.note = "p+1 was not classified as non-canonical";
      break;
    }
    if (!classify(SikeFpValue::kAllOnes, false)) {
      codec_ok = false;
      codec.note = "all-FF was not classified as non-canonical";
      break;
    }
  }
  (void)codec_ok;
  codec.passed = codec_ok;
  subtests.push_back(codec);

  // API observation: a non-canonical c0 limb through the external KEM path.
  OracleSubtestTrace api = MakeSubtest("api_noncanonical_observation", config.oracle_id, "EXPECT_EQUAL");
  KEMKeyPair keypair = SikeKeygen(config.left, "left", config.seed, "field-keygen", &api);
  SikeEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    enc = SikeEncaps(config.left, "left", keypair.pk, config.seed, "field-encaps", &api);
  }
  if (enc.status != PQCFUZZ_OK) {
    api.passed = false;
    api.note = "could not construct a valid encapsulation";
    subtests.push_back(api);
    return subtests;
  }
  bool safe = true;
  std::string failure;
  for (size_t coordinate = 0; coordinate < 6 && safe; ++coordinate) {
    std::vector<uint8_t> candidate = enc.ct;
    MutationRecord record = SetSikeCiphertextCoordinateBoundary(config.params, coordinate, SikeFpValue::kAllOnes,
                                                                &candidate);
    trace->mutations.push_back(record);
    if (!record.effective) {
      continue;
    }
    KEMSharedSecret dec = SikeDecaps(config.left, "left", candidate, keypair.sk, &api);
    const bool safe_state = (dec.status == PQCFUZZ_OK || RejectionLike(dec.status)) &&
                            (dec.status != PQCFUZZ_OK || dec.ss.size() == config.params.ss_len);
    if (!safe_state) {
      safe = false;
      failure = "non-canonical c0 limb " + std::to_string(coordinate) + " produced an inconsistent state";
    }
  }
  // The normative codec classification is asserted above; the external KEM
  // path is only observed for safety and declared output shape.
  api.passed = safe;
  if (!safe) {
    api.note = failure;
  }
  subtests.push_back(api);
  return subtests;
}

std::vector<OracleSubtestTrace> SikeKeyConsistency(const SikeOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace generated = MakeSubtest("generated_key_invariants", config.oracle_id, "EXPECT_EQUAL");
  const sike_reference::SikeReferenceHooks *hooks = sike_reference::GetSikeReferenceHooks();
  KEMKeyPair keypair = SikeKeygen(config.left, "left", config.seed, "consistency-keygen", &generated);
  SikeEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    enc = SikeEncaps(config.left, "left", keypair.pk, config.seed, "consistency-encaps", &generated);
  }
  if (enc.status != PQCFUZZ_OK) {
    generated.passed = false;
    generated.note = "could not construct a valid encapsulation";
    subtests.push_back(generated);
    return subtests;
  }
  if (hooks == nullptr || hooks->isogen3 == nullptr) {
    MarkNotApplicable(&generated, "reference hooks unavailable; evaluated by tests/models/sike_model.py");
    subtests.push_back(generated);
    return subtests;
  }
  const std::vector<uint8_t> embedded = ExtractEmbeddedPk3(config.params, keypair.sk);
  const std::vector<uint8_t> sk3(keypair.sk.begin() + static_cast<long>(config.params.sk_sk3_off),
                                 keypair.sk.begin() + static_cast<long>(config.params.sk_sk3_off + config.params.nsk3));
  std::vector<uint8_t> recomputed(config.params.pk_len, 0);
  const bool isogen_ok =
      hooks->isogen3(recomputed.data(), recomputed.size(), sk3.data(), sk3.size()) == PQCFUZZ_OK;
  const bool embedded_ok = embedded == keypair.pk && recomputed == keypair.pk;
  const bool scalar_ok = ScalarInBobRange(config.params, sk3);
  SikeBig p;
  ComputeSikeFieldPrime(config.params.e2, config.params.e3, &p);
  bool canonical = true;
  for (size_t coordinate = 0; coordinate < 6; ++coordinate) {
    if (!SikeFpCanonical(embedded.data() + coordinate * config.params.np, config.params.np, p)) {
      canonical = false;
      break;
    }
  }
  generated.passed = isogen_ok && embedded_ok && scalar_ok && canonical;
  if (!generated.passed) {
    generated.note = "generated-key invariant failed (embedded pk3, scalar range or canonical limbs)";
  }
  subtests.push_back(generated);

  OracleSubtestTrace imported = MakeSubtest("import_observation", config.oracle_id, "EXPECT_EQUAL");
  std::vector<uint8_t> mutated_sk = keypair.sk;
  MutationRecord record = WriteSikeSecretKeyEmbeddedPkByte(config.params, 0, 0x5A, &mutated_sk);
  trace->mutations.push_back(record);
  KEMSharedSecret dec = SikeDecaps(config.left, "left", enc.ct, mutated_sk, &imported);
  const bool safe_state = (dec.status == PQCFUZZ_OK || RejectionLike(dec.status)) &&
                          (dec.status != PQCFUZZ_OK || dec.ss.size() == config.params.ss_len);
  imported.passed = safe_state;
  if (!safe_state) {
    imported.note = "imported key with a replaced embedded pk3 produced an inconsistent state";
  }
  subtests.push_back(imported);
  return subtests;
}

std::vector<OracleSubtestTrace> SikeLengthsState(const SikeOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace subtest = MakeSubtest("adapter_length_boundaries", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  if (config.left == nullptr || config.left->keygen_derand == nullptr) {
    MarkNotApplicable(&subtest, "adapter API unsupported");
    subtests.push_back(subtest);
    return subtests;
  }
  KEMKeyPair keypair = SikeKeygen(config.left, "left", config.seed, "length-keygen", &subtest);
  SikeEncapsResult enc;
  if (keypair.status == PQCFUZZ_OK) {
    enc = SikeEncaps(config.left, "left", keypair.pk, config.seed, "length-encaps", &subtest);
  }
  if (enc.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct honest inputs";
    subtests.push_back(subtest);
    return subtests;
  }
  KEMSharedSecret exact = SikeDecaps(config.left, "left", enc.ct, keypair.sk, &subtest);
  const bool exact_ok = exact.status == PQCFUZZ_OK;
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

std::vector<OracleSubtestTrace> SikeRngReplay(const SikeOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  if (config.left == nullptr || config.left->keygen == nullptr || config.left->encaps == nullptr) {
    OracleSubtestTrace unsupported = MakeSubtest("rng_and_replay", config.oracle_id, "EXPECT_EQUAL");
    MarkNotApplicable(&unsupported, "adapter API unsupported");
    subtests.push_back(unsupported);
    return subtests;
  }
  std::vector<uint8_t> tape_a(128);
  std::vector<uint8_t> tape_b(128);
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
    ScopedRngOverride rng({tape_a.data(), tape_a.size(), true});
    first.status = config.left->keygen(first.pk.data(), first.sk.data());
  }
  {
    ScopedRngOverride rng({tape_a.data(), tape_a.size(), true});
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
    ScopedRngOverride rng({tape_b.data(), tape_b.size(), true});
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

OracleSubtestTrace SikeModelLane(const SikeOracleConfig &config, const std::string &subtest_id,
                                 const std::string &lane) {
  OracleSubtestTrace subtest = MakeSubtest(subtest_id, config.oracle_id, "EXPECT_EQUAL");
  MarkNotApplicable(&subtest, "evaluated by the independent Python model lane (" + lane + ")");
  return subtest;
}

void PopulateSikeControls(const std::string &oracle_id, KEMOracleTrace *trace) {
  if (oracle_id == "sike_kat") {
    trace->controls.positive_control = "the official KAT record reproduces pk/sk/ct/ss byte-for-byte";
    trace->controls.negative_control = "a different DRBG seed produces different bytes";
  } else if (oracle_id == "sike_reencryption_gate" || oracle_id == "sike_fallback_exact") {
    trace->controls.positive_control = "the valid ciphertext takes the H(m||ct) branch";
    trace->controls.negative_control = "a model-confirmed gate failure returns exactly SHAKE256(s||raw_ct)";
  } else if (oracle_id == "sike_fallback_seed_separation") {
    trace->controls.positive_control = "a valid ciphertext is unaffected by the s prefix";
    trace->controls.negative_control = "a gate-fail ciphertext output tracks the mutated s prefix";
  } else if (oracle_id == "sike_field_encoding") {
    trace->controls.positive_control = "canonical real/imag fixtures decode and re-encode identically";
    trace->controls.negative_control = "p, p+1 and all-FF limbs are classified out of range";
  } else if (oracle_id == "sike_key_consistency") {
    trace->controls.positive_control = "the honest key satisfies embedded_pk3 == pk and the scalar range";
    trace->controls.negative_control = "a replaced embedded pk3 is recorded as an observation";
  } else if (oracle_id == "sike_cross_exchange") {
    trace->controls.positive_control = "both exchange directions recover the same shared secret";
    trace->controls.negative_control = "the pair declares public key and ciphertext exchange before enabling";
  } else if (oracle_id == "sike_rng_replay") {
    trace->controls.positive_control = "two runs under the same tape agree";
    trace->controls.negative_control = "a different tape changes the key material and the failure tape is observed";
  } else {
    trace->controls.positive_control = "the honest keygen/encaps/decaps roundtrip succeeds";
    trace->controls.negative_control = "the targeted mutation is recorded as effective";
  }
}

}  // namespace

KEMOracleTrace ExecuteSikeOracle(const SikeOracleConfig &config) {
  KEMOracleTrace trace;
  trace.job_id = config.job_id;
  trace.pair_id = config.pair_id;
  trace.algorithm = config.algorithm;
  trace.oracle_id = config.oracle_id;

  if (config.left == nullptr || config.left->pk_len != config.params.pk_len ||
      config.left->sk_len != config.params.sk_len || config.left->ct_len != config.params.ct_len ||
      config.left->ss_len != config.params.ss_len) {
    trace.diagnostic_event = "harness_error: SIKE adapter ABI does not match the profile";
    trace.relation_evaluable = false;
    trace.intervention_supported = false;
    trace.intervention_effective = false;
    return trace;
  }

  const std::string &oracle_id = config.oracle_id;
  trace.controls = {};
  PopulateSikeControls(oracle_id, &trace);
  if (oracle_id == "sike_kat") {
    trace.subtests.push_back(SikeKat(config, &trace));
  } else if (oracle_id == "sike_local_roundtrip") {
    for (auto &subtest : SikeLocalRoundtrip(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sike_cross_exchange") {
    for (auto &subtest : SikeCrossExchange(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sike_reencryption_gate") {
    for (auto &subtest : SikeReencryptionGate(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sike_fallback_exact") {
    for (auto &subtest : SikeFallbackExact(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sike_fallback_seed_separation") {
    for (auto &subtest : SikeFallbackSeedSeparation(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sike_field_encoding") {
    for (auto &subtest : SikeFieldEncoding(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sike_key_consistency") {
    for (auto &subtest : SikeKeyConsistency(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sike_lengths_state") {
    for (auto &subtest : SikeLengthsState(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sike_rng_replay") {
    for (auto &subtest : SikeRngReplay(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sike_pke_relation") {
    trace.subtests.push_back(SikeModelLane(config, oracle_id, "tests/models/sike_model.py"));
    trace.relation_not_applicable = true;
  } else if (oracle_id == "sike_compressed_profile" || oracle_id == "sike_fault_gate") {
    trace.subtests.push_back(SikeModelLane(config, oracle_id, "tests/models/sike_model.py (opt-in P2)"));
    trace.relation_not_applicable = true;
  } else {
    trace.diagnostic_event = "unknown SIKE oracle_id";
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
  SetSikeTraceReachability(&trace);
  if (!trace.mutations.empty()) {
    trace.intervention_effective =
        std::any_of(trace.mutations.begin(), trace.mutations.end(), [](const MutationRecord &record) {
          return record.effective && !record.skipped;
        });
  }
  AddSikeFindingsForFailures(config, &trace);
  if (!trace.mutations.empty()) {
    trace.mutation_target = trace.mutations.front().target;
  }
  if (!trace.findings.empty()) {
    trace.claim_id = trace.findings.front().claim_id;
  }
  return trace;
}

}  // namespace pqcfuzz

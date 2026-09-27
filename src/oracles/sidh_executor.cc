#include "oracles/sidh_executor.h"

#include <algorithm>
#include <array>
#include <cstring>

#include "adapters/rng_control.h"
#include "adapters/status.h"
#include "mutators/digest.h"
#include "mutators/sha3.h"
#include "mutators/sike_mutator.h"
#include "oracles/oracle_result.h"
#include "oracles/scheme_claims.h"

namespace pqcfuzz {
namespace {

struct SidhKeyPair {
  std::vector<uint8_t> pk;
  KexRoleKey sk;
  pqcfuzz_status status = PQCFUZZ_INVALID_INPUT;
};

struct SidhShared {
  std::vector<uint8_t> bytes;
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

SidhKeyPair SidhKeygen(
    const pqcfuzz_kex_adapter *adapter,
    KexRole role,
    const std::string &label,
    const std::vector<uint8_t> &seed,
    const std::string &seed_label,
    OracleSubtestTrace *subtest) {
  SidhKeyPair out;
  out.sk.role = role;
  if (adapter == nullptr ||
      (role == KexRole::kAlice ? adapter->keygen_a == nullptr : adapter->keygen_b == nullptr)) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, role == KexRole::kAlice ? "keygen_a" : "keygen_b", out.status);
    return out;
  }
  out.pk.resize(adapter->pk_len);
  out.sk.bytes.resize(KexRolePrivateKeyLength(*adapter, role));
  const std::vector<uint8_t> tape = DeriveSeed(seed, seed_label, 128);
  ScopedRngOverride rng({tape.data(), tape.size(), false});
  out.status = role == KexRole::kAlice ? adapter->keygen_a(out.pk.data(), out.sk.bytes.data())
                                       : adapter->keygen_b(out.pk.data(), out.sk.bytes.data());
  AddCall(subtest, label, role == KexRole::kAlice ? "keygen_a" : "keygen_b", out.status);
  return out;
}

SidhShared SidhDerive(
    const pqcfuzz_kex_adapter *adapter,
    KexRole role,
    const std::string &label,
    const std::vector<uint8_t> &peer_pk,
    const KexRoleKey &own_sk,
    OracleSubtestTrace *subtest) {
  SidhShared out;
  const char *api = role == KexRole::kAlice ? "derive_a" : "derive_b";
  if (adapter == nullptr || (role == KexRole::kAlice ? adapter->derive_a == nullptr : adapter->derive_b == nullptr)) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, api, out.status);
    return out;
  }
  if (peer_pk.size() != adapter->pk_len || own_sk.bytes.size() != KexRolePrivateKeyLength(*adapter, own_sk.role) ||
      own_sk.role != role) {
    out.status = PQCFUZZ_INVALID_INPUT;
    AddAdapterRejection(subtest, label, api);
    return out;
  }
  out.bytes.assign(adapter->shared_len, 0xA5);
  out.status = role == KexRole::kAlice ? adapter->derive_a(out.bytes.data(), peer_pk.data(), own_sk.bytes.data())
                                       : adapter->derive_b(out.bytes.data(), peer_pk.data(), own_sk.bytes.data());
  AddCall(subtest, label, api, out.status);
  return out;
}

bool ScalarLessThanPower2(const std::vector<uint8_t> &scalar, size_t bits) {
  SikeBig value;
  if (!SikeBigFromLeBytes(scalar.data(), scalar.size(), &value)) {
    return false;
  }
  SikeBig bound;
  const size_t words = bits / 64;
  const size_t shift = bits % 64;
  if (words >= SikeBig::kLimbs) {
    return true;
  }
  bound.limb[words] = static_cast<uint64_t>(1) << shift;
  return SikeBigCompare(value, bound) < 0;
}

std::vector<uint8_t> ScalarAllOnes(size_t len, size_t bits) {
  std::vector<uint8_t> scalar(len, 0xFF);
  if (bits == 0) {
    return scalar;
  }
  const size_t remainder = bits % 8;
  scalar[len - 1] = remainder == 0 ? 0xFF : static_cast<uint8_t>((1u << remainder) - 1u);
  return scalar;
}

std::vector<std::pair<std::string, std::string>> ClaimAttributes(const std::string &format) {
  std::vector<std::pair<std::string, std::string>> attributes;
  if (!format.empty()) {
    attributes.emplace_back("format", format);
  }
  return attributes;
}

OracleFindingTrace MakeFinding(
    const SidhOracleConfig &config,
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
  if (!ResolveSchemeClaim(config.oracle_id, config.algorithm, subtest_id, ClaimAttributes(format), &resolved,
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
  if (oracle_id == "sidh_field_curve_checks") {
    return subtest_id == "api_observation" ? "api" : "hook";
  }
  if (oracle_id == "sidh_resources_rng") {
    return subtest_id == "rng_failure_observed" ? "failure" : "api";
  }
  return "";
}

void AddSidhFindingsForFailures(const SidhOracleConfig &config, KEMOracleTrace *trace) {
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
    if (config.oracle_id == "sidh_agreement") {
      finding_subclass = "agreement_mismatch";
    } else if (config.oracle_id == "sidh_cross_agreement") {
      finding_subclass = "cross_agreement_mismatch";
    } else if (config.oracle_id == "sidh_field_curve_checks") {
      finding_subclass = "field_curve_check_mismatch";
    } else if (config.oracle_id == "sidh_role_scalar_profile") {
      finding_subclass = "role_scalar_profile_mismatch";
    } else if (config.oracle_id == "sidh_resources_rng") {
      finding_subclass = "rng_or_state_contract_violation";
    }
    trace->findings.push_back(MakeFinding(config, subtest.subtest_id, finding_class, finding_subclass, subtest.note,
                                          EvidenceKind::kSemantic,
                                          FormatForSubtest(config.oracle_id, subtest.subtest_id)));
  }
}

void SetSidhTraceReachability(KEMOracleTrace *trace) {
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

bool BothRolesAgree(const SidhParams &params, const SidhShared &a, const SidhShared &b) {
  return a.status == PQCFUZZ_OK && b.status == PQCFUZZ_OK && a.bytes.size() == params.shared_len &&
         a.bytes == b.bytes;
}

std::vector<OracleSubtestTrace> SidhAgreement(const SidhOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace subtest = MakeSubtest("honest_agreement", config.oracle_id, "SAME_SHARED_SECRET");
  SidhKeyPair alice = SidhKeygen(config.left, KexRole::kAlice, "left", config.seed, "agreement-a", &subtest);
  SidhKeyPair bob = SidhKeygen(config.left, KexRole::kBob, "left", config.seed, "agreement-b", &subtest);
  if (alice.status != PQCFUZZ_OK || bob.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "honest role key generation failed";
    subtests.push_back(subtest);
    return subtests;
  }
  if (alice.pk.size() != config.params.pk_len || bob.pk.size() != config.params.pk_len ||
      alice.sk.bytes.size() != config.params.sk_a_len || bob.sk.bytes.size() != config.params.sk_b_len) {
    subtest.passed = false;
    subtest.note = "role key generation returned the wrong ABI lengths";
    subtests.push_back(subtest);
    return subtests;
  }
  SidhShared shared_a = SidhDerive(config.left, KexRole::kAlice, "left", bob.pk, alice.sk, &subtest);
  SidhShared shared_b = SidhDerive(config.left, KexRole::kBob, "left", alice.pk, bob.sk, &subtest);
  subtest.passed = BothRolesAgree(config.params, shared_a, shared_b);
  if (!subtest.passed) {
    subtest.note = "the two roles did not derive the same 2*Np-byte shared value";
  }
  trace->baseline = {shared_a.status, false, false, MutationSha256Hex(shared_a.bytes), shared_a.bytes.size()};

  // Deterministic scalar positives: zero, one, all bits set (legal maximum).
  if (config.left != nullptr && config.left->keygen_a_scalar != nullptr && config.left->keygen_b_scalar != nullptr) {
    OracleSubtestTrace scalars = MakeSubtest("scalar_boundaries", config.oracle_id, "SAME_SHARED_SECRET");
    SidhKeyPair bob_ref = SidhKeygen(config.left, KexRole::kBob, "left", config.seed, "scalar-b-ref", &scalars);
    std::vector<uint8_t> zero_a(config.params.sk_a_len, 0);
    std::vector<uint8_t> one_a(config.params.sk_a_len, 0);
    one_a[0] = 1;
    std::vector<uint8_t> max_a = ScalarAllOnes(config.params.sk_a_len, config.params.e2);
    std::vector<uint8_t> zero_b(config.params.sk_b_len, 0);
    std::vector<uint8_t> one_b(config.params.sk_b_len, 0);
    one_b[0] = 1;
    size_t bbits = 0;
    ComputeSikeBobScalarBits(config.params.e3, &bbits);
    std::vector<uint8_t> max_b = ScalarAllOnes(config.params.sk_b_len, bbits);
    bool scalar_ok = bob_ref.status == PQCFUZZ_OK;
    for (const auto &pair : {std::make_pair(&zero_a, "zero"), std::make_pair(&one_a, "one"),
                             std::make_pair(&max_a, "max")}) {
      SidhKeyPair a;
      a.sk.role = KexRole::kAlice;
      a.sk.bytes = *pair.first;
      a.pk.assign(config.params.pk_len, 0);
      a.status = config.left->keygen_a_scalar(a.pk.data(), a.sk.bytes.data());
      AddCall(&scalars, "left", "keygen_a_scalar", a.status);
      if (a.status != PQCFUZZ_OK) {
        scalar_ok = false;
        break;
      }
      SidhShared shared = SidhDerive(config.left, KexRole::kBob, "left", a.pk, bob_ref.sk, &scalars);
      SidhShared own = SidhDerive(config.left, KexRole::kAlice, "left", bob_ref.pk, a.sk, &scalars);
      if (!BothRolesAgree(config.params, shared, own)) {
        scalar_ok = false;
        scalars.note = std::string("scalar ") + pair.second + " did not agree between roles";
        break;
      }
    }
    if (scalar_ok) {
      SidhKeyPair alice_ref = SidhKeygen(config.left, KexRole::kAlice, "left", config.seed, "scalar-a-ref", &scalars);
      scalar_ok = alice_ref.status == PQCFUZZ_OK;
      for (const auto &pair : {std::make_pair(&zero_b, "zero"), std::make_pair(&one_b, "one"),
                               std::make_pair(&max_b, "max")}) {
        SidhKeyPair b;
        b.sk.role = KexRole::kBob;
        b.sk.bytes = *pair.first;
        b.pk.assign(config.params.pk_len, 0);
        b.status = config.left->keygen_b_scalar(b.pk.data(), b.sk.bytes.data());
        AddCall(&scalars, "left", "keygen_b_scalar", b.status);
        if (b.status != PQCFUZZ_OK) {
          scalar_ok = false;
          break;
        }
        SidhShared shared = SidhDerive(config.left, KexRole::kAlice, "left", b.pk, alice_ref.sk, &scalars);
        SidhShared own = SidhDerive(config.left, KexRole::kBob, "left", alice_ref.pk, b.sk, &scalars);
        if (!BothRolesAgree(config.params, shared, own)) {
          scalar_ok = false;
          scalars.note = std::string("bob scalar ") + pair.second + " did not agree between roles";
          break;
        }
      }
    }
    scalars.passed = scalar_ok;
    if (!scalar_ok && scalars.note.empty()) {
      scalars.note = "scalar boundary agreement failed";
    }
    subtests.push_back(scalars);
  } else {
    OracleSubtestTrace scalars = MakeSubtest("scalar_boundaries", config.oracle_id, "SAME_SHARED_SECRET");
    MarkNotApplicable(&scalars, "adapter does not expose the scalar hooks");
    subtests.push_back(scalars);
  }
  subtests.insert(subtests.begin(), subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> SidhCrossAgreement(const SidhOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  if (!config.exchange_contract.public_key_exchange || !config.exchange_contract.peer_key_exchange ||
      config.right == nullptr) {
    OracleSubtestTrace subtest = MakeSubtest("cross_agreement", config.oracle_id, "SAME_SHARED_SECRET");
    MarkNotApplicable(&subtest, "peer public key exchange is disabled or the right implementation is absent");
    subtests.push_back(subtest);
    return subtests;
  }
  OracleSubtestTrace subtest = MakeSubtest("left_and_right_agree", config.oracle_id, "SAME_SHARED_SECRET");
  SidhKeyPair left = SidhKeygen(config.left, KexRole::kAlice, "left", config.seed, "cross-a", &subtest);
  SidhKeyPair right = SidhKeygen(config.right, KexRole::kBob, "right", config.seed, "cross-b", &subtest);
  if (left.status != PQCFUZZ_OK || right.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "cross role key generation failed";
    subtests.push_back(subtest);
    return subtests;
  }
  SidhShared shared_left = SidhDerive(config.left, KexRole::kAlice, "left", right.pk, left.sk, &subtest);
  SidhShared shared_right = SidhDerive(config.right, KexRole::kBob, "right", left.pk, right.sk, &subtest);
  subtest.passed = BothRolesAgree(config.params, shared_left, shared_right);
  if (!subtest.passed) {
    subtest.note = "the left and right builds did not derive the same shared value";
  }
  trace->mutations.clear();
  subtests.push_back(subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> SidhFieldCurveChecks(const SidhOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace hook = MakeSubtest("coordinate_boundaries", config.oracle_id, "EXPECT_EQUAL");
  SikeBig p;
  if (!ComputeSikeFieldPrime(config.params.e2, config.params.e3, &p)) {
    hook.passed = false;
    hook.note = "field prime could not be computed";
    subtests.push_back(hook);
    return subtests;
  }
  bool hook_ok = true;
  for (size_t coordinate = 0; coordinate < 6 && hook_ok; ++coordinate) {
    std::vector<uint8_t> public_key(config.params.pk_len, 0);
    const auto classify = [&](SikeFpValue value, bool expect_canonical) {
      MutationRecord record = SetSikePublicKeyCoordinateBoundary(config.params, coordinate, value, &public_key);
      const bool canonical = SikeFpCanonical(public_key.data() + coordinate * config.params.np, config.params.np, p);
      return record.effective && canonical == expect_canonical;
    };
    if (!classify(SikeFpValue::kPrimeMinusOne, true) || !classify(SikeFpValue::kPrime, false) ||
        !classify(SikeFpValue::kPrimePlusOne, false) || !classify(SikeFpValue::kAllOnes, false)) {
      hook_ok = false;
      hook.note = "coordinate " + std::to_string(coordinate) + " was misclassified";
    }
  }
  hook.passed = hook_ok;
  subtests.push_back(hook);

  OracleSubtestTrace api = MakeSubtest("api_observation", config.oracle_id, "EXPECT_EQUAL");
  SidhKeyPair alice = SidhKeygen(config.left, KexRole::kAlice, "left", config.seed, "field-a", &api);
  if (alice.status != PQCFUZZ_OK) {
    api.passed = false;
    api.note = "could not construct an honest Alice key";
    subtests.push_back(api);
    return subtests;
  }
  bool safe = true;
  std::string failure;
  for (size_t coordinate = 0; coordinate < 6 && safe; ++coordinate) {
    for (SikeFpValue value : {SikeFpValue::kPrime, SikeFpValue::kAllOnes}) {
      std::vector<uint8_t> peer = alice.pk;
      MutationRecord record = SetSikePublicKeyCoordinateBoundary(config.params, coordinate, value, &peer);
      trace->mutations.push_back(record);
      if (!record.effective) {
        continue;
      }
      SidhShared shared = SidhDerive(config.left, KexRole::kBob, "left", peer, alice.sk, &api);
      const bool safe_state = (shared.status == PQCFUZZ_OK || RejectionLike(shared.status)) &&
                              (shared.status != PQCFUZZ_OK || shared.bytes.size() == config.params.shared_len);
      if (!safe_state) {
        safe = false;
        failure = "malformed peer key produced an inconsistent state";
        break;
      }
    }
  }
  api.passed = safe;
  if (!safe) {
    api.note = failure;
  }
  subtests.push_back(api);
  return subtests;
}

std::vector<OracleSubtestTrace> SidhRoleScalarProfile(const SidhOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace model = MakeSubtest("scalar_range_model", config.oracle_id, "EXPECT_EQUAL");
  SidhKeyPair alice = SidhKeygen(config.left, KexRole::kAlice, "left", config.seed, "role-a", &model);
  SidhKeyPair bob = SidhKeygen(config.left, KexRole::kBob, "left", config.seed, "role-b", &model);
  if (alice.status != PQCFUZZ_OK || bob.status != PQCFUZZ_OK) {
    model.passed = false;
    model.note = "honest role key generation failed";
    subtests.push_back(model);
    return subtests;
  }
  size_t bbits = 0;
  ComputeSikeBobScalarBits(config.params.e3, &bbits);
  const bool a_in_range = ScalarLessThanPower2(alice.sk.bytes, config.params.e2) &&
                          alice.sk.bytes.size() == config.params.sk_a_len;
  const bool b_in_range = ScalarLessThanPower2(bob.sk.bytes, bbits) &&
                          bob.sk.bytes.size() == config.params.sk_b_len;
  // When e2 (resp. sbits) is a multiple of eight every Nsk-byte value is in
  // range; otherwise the all-ones tail byte is the canonical out-of-range
  // boundary.  The model must follow the bit length, not the byte length.
  const std::vector<uint8_t> boundary_a(config.params.sk_a_len, 0xFF);
  const std::vector<uint8_t> boundary_b(config.params.sk_b_len, 0xFF);
  const bool border_a_ok = config.params.e2 % 8 == 0
                               ? ScalarLessThanPower2(boundary_a, config.params.e2)
                               : !ScalarLessThanPower2(boundary_a, config.params.e2);
  const bool border_b_ok = bbits % 8 == 0 ? ScalarLessThanPower2(boundary_b, bbits)
                                          : !ScalarLessThanPower2(boundary_b, bbits);
  model.passed = a_in_range && b_in_range && border_a_ok && border_b_ok;
  if (!model.passed) {
    model.note = "role scalar range model did not classify the honest and boundary scalars as expected";
  }
  subtests.push_back(model);

  OracleSubtestTrace routing = MakeSubtest("role_routing", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  const pqcfuzz_kex_adapter *adapter = config.left;
  if (adapter == nullptr) {
    MarkNotApplicable(&routing, "adapter unavailable");
    subtests.push_back(routing);
    return subtests;
  }
  // Passing the A key where B is expected must be refused before the target
  // whenever the role storage formats are distinguishable.  When both roles
  // use the same length, a structural wrapper cannot tell them apart; that is
  // recorded as an observation instead of inventing a rejection contract.
  const bool roles_distinguishable = adapter->sk_a_len != adapter->sk_b_len;
  KexRoleKey swapped = alice.sk;
  swapped.role = KexRole::kBob;
  std::vector<uint8_t> shared(adapter->shared_len, 0);
  const pqcfuzz_status swapped_status =
      KexDeriveTyped(adapter, KexRole::kBob, shared.data(), alice.pk.data(), swapped);
  bool swapped_rejected = true;
  if (roles_distinguishable) {
    AddAdapterRejection(&routing, "left", "derive_b");
    swapped_rejected = swapped_status == PQCFUZZ_INVALID_INPUT;
  } else {
    AddCall(&routing, "left", "derive_b", swapped_status);
    swapped_rejected = swapped_status == PQCFUZZ_OK || swapped_status == PQCFUZZ_INVALID_INPUT;
  }
  // A structurally correct role key enters the target.
  const pqcfuzz_status typed_status =
      KexDeriveTyped(adapter, KexRole::kBob, shared.data(), alice.pk.data(), bob.sk);
  AddCall(&routing, "left", "derive_b", typed_status);
  routing.passed = swapped_rejected && typed_status == PQCFUZZ_OK;
  if (!routing.passed) {
    routing.note = "role-swapped key was not refused at the typed wrapper";
  } else if (!roles_distinguishable) {
    routing.note = "both roles share a private-key length; role separation is length-only by construction";
  }
  subtests.push_back(routing);
  return subtests;
}

std::vector<OracleSubtestTrace> SidhResourcesRng(const SidhOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  if (config.left == nullptr || config.left->keygen_a == nullptr || config.left->keygen_b == nullptr) {
    OracleSubtestTrace unsupported = MakeSubtest("resources_rng", config.oracle_id, "EXPECT_EQUAL");
    MarkNotApplicable(&unsupported, "adapter API unsupported");
    subtests.push_back(unsupported);
    return subtests;
  }
  std::vector<uint8_t> tape_a(128);
  std::vector<uint8_t> tape_b(128);
  for (size_t i = 0; i < tape_a.size(); ++i) {
    tape_a[i] = static_cast<uint8_t>(0x23u + i);
    tape_b[i] = static_cast<uint8_t>(0xA7u + i * 5u);
  }
  OracleSubtestTrace reproducible = MakeSubtest("same_tape_reproducible", config.oracle_id, "EXPECT_EQUAL");
  for (KexRole role : {KexRole::kAlice, KexRole::kBob}) {
    std::vector<uint8_t> pk1(config.left->pk_len, 0);
    std::vector<uint8_t> pk2(config.left->pk_len, 0);
    std::vector<uint8_t> sk1(KexRolePrivateKeyLength(*config.left, role), 0);
    std::vector<uint8_t> sk2(KexRolePrivateKeyLength(*config.left, role), 0);
    pqcfuzz_status status1;
    pqcfuzz_status status2;
    {
      ScopedRngOverride rng({tape_a.data(), tape_a.size(), true});
      status1 = role == KexRole::kAlice ? config.left->keygen_a(pk1.data(), sk1.data())
                                        : config.left->keygen_b(pk1.data(), sk1.data());
    }
    {
      ScopedRngOverride rng({tape_a.data(), tape_a.size(), true});
      status2 = role == KexRole::kAlice ? config.left->keygen_a(pk2.data(), sk2.data())
                                        : config.left->keygen_b(pk2.data(), sk2.data());
    }
    AddCall(&reproducible, "left", role == KexRole::kAlice ? "keygen_a" : "keygen_b", status1);
    if (status1 != PQCFUZZ_OK || status2 != PQCFUZZ_OK || pk1 != pk2 || sk1 != sk2) {
      reproducible.passed = false;
      reproducible.note = "the same CSPRNG tape did not reproduce the role key";
      subtests.push_back(reproducible);
      return subtests;
    }
  }
  subtests.push_back(reproducible);

  OracleSubtestTrace differs = MakeSubtest("different_tape_differs", config.oracle_id, "EXPECT_DIFFERENT");
  {
    std::vector<uint8_t> pk1(config.left->pk_len, 0);
    std::vector<uint8_t> pk2(config.left->pk_len, 0);
    std::vector<uint8_t> sk1(config.left->sk_a_len, 0);
    std::vector<uint8_t> sk2(config.left->sk_a_len, 0);
    {
      ScopedRngOverride rng({tape_a.data(), tape_a.size(), true});
      config.left->keygen_a(pk1.data(), sk1.data());
    }
    {
      ScopedRngOverride rng({tape_b.data(), tape_b.size(), true});
      config.left->keygen_a(pk2.data(), sk2.data());
    }
    differs.passed = pk1 != pk2 || sk1 != sk2;
    if (!differs.passed) {
      differs.note = "a different CSPRNG tape produced identical key material";
    }
  }
  subtests.push_back(differs);

  OracleSubtestTrace failure = MakeSubtest("rng_failure_observed", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  pqcfuzz_rng_reset_failure_observed();
  {
    uint8_t dummy = 0;
    ScopedRngOverride rng({&dummy, 1, false, RngTape::Mode::kReportedFailure});
    std::vector<uint8_t> pk(config.left->pk_len);
    std::vector<uint8_t> sk(config.left->sk_a_len);
    const pqcfuzz_status status = config.left->keygen_a(pk.data(), sk.data());
    AddCall(&failure, "left", "keygen_a", status);
    failure.passed = pqcfuzz_rng_failure_observed();
    if (!failure.passed) {
      failure.note = "injected CSPRNG failure was not observed by the RNG control";
    }
  }
  subtests.push_back(failure);

  OracleSubtestTrace shape = MakeSubtest("output_shape", config.oracle_id, "EXPECT_EQUAL");
  SidhKeyPair alice = SidhKeygen(config.left, KexRole::kAlice, "left", std::vector<uint8_t>(32, 0x5A), "shape-a", &shape);
  SidhKeyPair bob = SidhKeygen(config.left, KexRole::kBob, "left", std::vector<uint8_t>(32, 0x5A), "shape-b", &shape);
  if (alice.status == PQCFUZZ_OK && bob.status == PQCFUZZ_OK) {
    SidhShared shared = SidhDerive(config.left, KexRole::kAlice, "left", bob.pk, alice.sk, &shape);
    const bool full_length = shared.status == PQCFUZZ_OK && shared.bytes.size() == config.params.shared_len;
    const bool not_sentinel = shared.bytes != std::vector<uint8_t>(config.params.shared_len, 0xA5);
    shape.passed = full_length && not_sentinel;
    if (!shape.passed) {
      shape.note = "shared output did not fill the declared 2*Np length";
    }
  } else {
    shape.passed = false;
    shape.note = "honest key generation failed";
  }
  subtests.push_back(shape);
  return subtests;
}

OracleSubtestTrace SidhModelLane(const SidhOracleConfig &config, const std::string &subtest_id,
                                 const std::string &lane) {
  OracleSubtestTrace subtest = MakeSubtest(subtest_id, config.oracle_id, "EXPECT_EQUAL");
  MarkNotApplicable(&subtest, "evaluated by the independent Python model lane (" + lane + ")");
  return subtest;
}

void PopulateSidhControls(const std::string &oracle_id, KEMOracleTrace *trace) {
  if (oracle_id == "sidh_agreement") {
    trace->controls.positive_control = "both roles derive the same 2*Np-byte shared value";
    trace->controls.negative_control = "the SIKE ss_len is never used as the expected SIDH length";
  } else if (oracle_id == "sidh_field_curve_checks") {
    trace->controls.positive_control = "canonical coordinates are classified in range";
    trace->controls.negative_control = "p, p+1 and all-FF coordinates are classified out of range";
  } else if (oracle_id == "sidh_role_scalar_profile") {
    trace->controls.positive_control = "honest scalars are in the role space and the typed wrapper routes them";
    trace->controls.negative_control = "a role-swapped key is refused before the target";
  } else if (oracle_id == "sidh_resources_rng") {
    trace->controls.positive_control = "same tape reproduces the role key and the shared output is full length";
    trace->controls.negative_control = "a different tape changes the key and the failure tape is observed";
  } else {
    trace->controls.positive_control = "the honest keygen/derive paths succeed";
    trace->controls.negative_control = "the targeted mutation is recorded as effective";
  }
}

}  // namespace

KEMOracleTrace ExecuteSidhOracle(const SidhOracleConfig &config) {
  KEMOracleTrace trace;
  trace.job_id = config.job_id;
  trace.pair_id = config.pair_id;
  trace.algorithm = config.algorithm;
  trace.oracle_id = config.oracle_id;

  if (config.left == nullptr || config.left->pk_len != config.params.pk_len ||
      config.left->sk_a_len != config.params.sk_a_len || config.left->sk_b_len != config.params.sk_b_len ||
      config.left->shared_len != config.params.shared_len) {
    trace.diagnostic_event = "harness_error: SIDH adapter ABI does not match the profile";
    trace.relation_evaluable = false;
    trace.intervention_supported = false;
    trace.intervention_effective = false;
    return trace;
  }

  const std::string &oracle_id = config.oracle_id;
  trace.controls = {};
  PopulateSidhControls(oracle_id, &trace);
  if (oracle_id == "sidh_agreement") {
    for (auto &subtest : SidhAgreement(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sidh_cross_agreement") {
    for (auto &subtest : SidhCrossAgreement(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sidh_field_curve_checks") {
    for (auto &subtest : SidhFieldCurveChecks(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sidh_role_scalar_profile") {
    for (auto &subtest : SidhRoleScalarProfile(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sidh_resources_rng") {
    for (auto &subtest : SidhResourcesRng(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "sidh_isogeny_math") {
    trace.subtests.push_back(SidhModelLane(config, oracle_id, "tests/models/sidh_model.py"));
    trace.relation_not_applicable = true;
  } else if (oracle_id == "sike_sidh_timing") {
    trace.subtests.push_back(SidhModelLane(config, oracle_id, "tests/models/sidh_model.py (opt-in P2)"));
    trace.relation_not_applicable = true;
  } else {
    trace.diagnostic_event = "unknown SIDH oracle_id";
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
  SetSidhTraceReachability(&trace);
  if (!trace.mutations.empty()) {
    trace.intervention_effective =
        std::any_of(trace.mutations.begin(), trace.mutations.end(), [](const MutationRecord &record) {
          return record.effective && !record.skipped;
        });
  }
  AddSidhFindingsForFailures(config, &trace);
  if (!trace.mutations.empty()) {
    trace.mutation_target = trace.mutations.front().target;
  }
  if (!trace.findings.empty()) {
    trace.claim_id = trace.findings.front().claim_id;
  }
  return trace;
}

}  // namespace pqcfuzz

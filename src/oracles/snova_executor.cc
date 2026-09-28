#include "oracles/snova_executor.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <utility>
#include <vector>

#include "adapters/rng_control.h"
#include "adapters/status.h"
#include "mutators/digest.h"
#include "mutators/scheme_mutation.h"
#include "mutators/sha3.h"
#include "mutators/snova_mutator.h"
#include "oracles/oracle_result.h"
#include "oracles/snova_public_map.h"

namespace pqcfuzz {
namespace {

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

void AddExecutorRejection(
    OracleSubtestTrace *subtest,
    const std::string &adapter,
    const std::string &api,
    pqcfuzz_status status) {
  OracleCallTrace call;
  call.adapter = adapter;
  call.api = api;
  call.status = status;
  call.executor_dispatched = false;
  call.adapter_entered = false;
  call.target_entered = false;
  call.target_returned = false;
  call.rejection_layer = "executor";
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
  return status == PQCFUZZ_REJECT || status == PQCFUZZ_INVALID_INPUT;
}

void RecordMutationEffect(const std::vector<MutationRecord> &records, KEMOracleTrace *trace) {
  for (const auto &record : records) {
    trace->mutations.push_back(record);
    if (!record.effective) {
      trace->intervention_effective = false;
    }
  }
  if (records.empty()) {
    trace->intervention_effective = false;
  }
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

SIGKeyPair SnovaKeygen(
    const pqcfuzz_sig_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &seed,
    const std::string &seed_label,
    OracleSubtestTrace *subtest) {
  SIGKeyPair out;
  if (adapter == nullptr || adapter->keygen == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "keygen", out.status);
    return out;
  }
  out.pk.resize(adapter->pk_len);
  out.sk.resize(adapter->sk_len);
  if (adapter->keygen_seeded != nullptr) {
    const std::vector<uint8_t> material = DeriveSeed(seed, seed_label, 48);
    out.status = adapter->keygen_seeded(out.pk.data(), out.sk.data(), material.data(), material.size());
  } else {
    out.status = adapter->keygen(out.pk.data(), out.sk.data());
  }
  AddCall(subtest, label, "keygen", out.status);
  return out;
}

SIGKeyPair SnovaKeygenFromTape(
    const pqcfuzz_sig_adapter *adapter,
    const std::string &label,
    const RngTape &tape,
    OracleSubtestTrace *subtest) {
  SIGKeyPair out;
  if (adapter == nullptr || adapter->keygen == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "keygen", out.status);
    return out;
  }
  out.pk.resize(adapter->pk_len);
  out.sk.resize(adapter->sk_len);
  {
    ScopedRngOverride scope(tape);
    out.status = adapter->keygen(out.pk.data(), out.sk.data());
  }
  AddCall(subtest, label, "keygen", out.status);
  return out;
}

SIGSignature SnovaSign(
    const pqcfuzz_sig_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &sk,
    const std::vector<uint8_t> &seed,
    const std::string &seed_label,
    OracleSubtestTrace *subtest) {
  SIGSignature out;
  if (adapter == nullptr || adapter->sign_seeded == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "sign", out.status);
    return out;
  }
  out.sig.resize(adapter->sig_max_len);
  size_t sig_len = adapter->sig_max_len;
  const std::vector<uint8_t> material = DeriveSeed(seed, seed_label, 16);
  out.status = adapter->sign_seeded(out.sig.data(), &sig_len, message.data(), message.size(), sk.data(), nullptr, 0,
                                    material.data(), material.size());
  if (out.status == PQCFUZZ_OK && sig_len <= adapter->sig_max_len) {
    out.sig.resize(sig_len);
  } else if (out.status == PQCFUZZ_OK) {
    out.status = PQCFUZZ_INVALID_INPUT;
    out.sig.clear();
  }
  AddCall(subtest, label, "sign", out.status);
  return out;
}

SIGSignature SnovaSignFromTape(
    const pqcfuzz_sig_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &sk,
    const RngTape &tape,
    OracleSubtestTrace *subtest) {
  SIGSignature out;
  if (adapter == nullptr || adapter->sign == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "sign", out.status);
    return out;
  }
  out.sig.resize(adapter->sig_max_len);
  size_t sig_len = adapter->sig_max_len;
  {
    ScopedRngOverride scope(tape);
    out.status = adapter->sign(out.sig.data(), &sig_len, message.data(), message.size(), sk.data(), nullptr, 0);
  }
  if (out.status == PQCFUZZ_OK && sig_len <= adapter->sig_max_len) {
    out.sig.resize(sig_len);
  } else if (out.status == PQCFUZZ_OK) {
    out.status = PQCFUZZ_INVALID_INPUT;
    out.sig.clear();
  }
  AddCall(subtest, label, "sign", out.status);
  return out;
}

SIGSignature SnovaSignDigest(
    const pqcfuzz_snova_api *api,
    const std::string &label,
    const std::vector<uint8_t> &digest,
    const std::vector<uint8_t> &sk,
    const std::vector<uint8_t> &salt,
    OracleSubtestTrace *subtest) {
  SIGSignature out;
  if (api == nullptr || api->sign_digest == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "sign_digest", out.status);
    return out;
  }
  out.sig.resize(api->sig_max_len);
  size_t sig_len = api->sig_max_len;
  out.status = api->sign_digest(out.sig.data(), &sig_len, digest.data(), digest.size(), sk.data(), salt.data());
  if (out.status == PQCFUZZ_OK && sig_len <= api->sig_max_len) {
    out.sig.resize(sig_len);
  } else if (out.status == PQCFUZZ_OK) {
    out.status = PQCFUZZ_INVALID_INPUT;
    out.sig.clear();
  }
  AddCall(subtest, label, "sign_digest", out.status);
  return out;
}

SIGVerifyResult SnovaVerify(
    const pqcfuzz_sig_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &signature,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &pk,
    OracleSubtestTrace *subtest) {
  SIGVerifyResult out;
  if (adapter == nullptr || adapter->verify == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "verify", out.status);
    return out;
  }
  if (pk.size() != adapter->pk_len) {
    out.status = PQCFUZZ_INVALID_INPUT;
    AddExecutorRejection(subtest, label, "verify", out.status);
    return out;
  }
  out.status = adapter->verify(signature.data(), signature.size(), message.data(), message.size(), pk.data(), nullptr, 0);
  out.accepted = out.status == PQCFUZZ_OK;
  AddBoolCall(subtest, label, "verify", out.status, out.accepted);
  return out;
}

SIGVerifyResult SnovaVerifyDigest(
    const pqcfuzz_snova_api *api,
    const std::string &label,
    const std::vector<uint8_t> &signature,
    const std::vector<uint8_t> &digest,
    const std::vector<uint8_t> &pk,
    OracleSubtestTrace *subtest) {
  SIGVerifyResult out;
  if (api == nullptr || api->verify_digest == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "verify_digest", out.status);
    return out;
  }
  if (pk.size() != api->pk_len) {
    out.status = PQCFUZZ_INVALID_INPUT;
    AddExecutorRejection(subtest, label, "verify_digest", out.status);
    return out;
  }
  out.status = api->verify_digest(signature.data(), signature.size(), digest.data(), digest.size(), pk.data());
  out.accepted = out.status == PQCFUZZ_OK;
  AddBoolCall(subtest, label, "verify_digest", out.status, out.accepted);
  return out;
}

struct SnovaSetup {
  SIGKeyPair keypair;
  SIGSignature signature;
  bool ok() const {
    return keypair.status == PQCFUZZ_OK && signature.status == PQCFUZZ_OK && !signature.sig.empty();
  }
};

SnovaSetup SetupHonestSignature(
    const SnovaOracleConfig &config,
    OracleSubtestTrace *subtest,
    const std::vector<uint8_t> &message,
    const std::string &seed_label) {
  SnovaSetup setup;
  setup.keypair = SnovaKeygen(config.left, "left", config.seed, seed_label, subtest);
  if (setup.keypair.status == PQCFUZZ_OK) {
    setup.signature =
        SnovaSign(config.left, "left", message, setup.keypair.sk, config.seed, seed_label + "-sign", subtest);
  }
  return setup;
}

std::vector<std::pair<std::string, std::string>> ClaimAttributes(const SnovaOracleConfig &config) {
  std::vector<std::pair<std::string, std::string>> attributes;
  if (config.left_api != nullptr) {
    attributes.emplace_back("format", config.left_api->backend);
    attributes.emplace_back("variant", config.left_api->sk_format);
  }
  return attributes;
}

OracleFindingTrace MakeFinding(
    const SnovaOracleConfig &config,
    const std::string &subtest_id,
    const std::string &finding_class,
    const std::string &finding_subclass,
    const std::string &summary,
    EvidenceKind evidence_kind,
    std::vector<OracleDiagnosticTrace> *diagnostics) {
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
    if (diagnostics != nullptr) {
      diagnostics->push_back({"claim_resolution", "classify", error});
    }
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

void AddSnovaFindingsForFailures(const SnovaOracleConfig &config, KEMOracleTrace *trace) {
  for (const auto &subtest : trace->subtests) {
    for (const auto &call : subtest.calls) {
      if (call.status == PQCFUZZ_CRASH) {
        trace->findings.push_back(MakeFinding(config, subtest.subtest_id, "memory_safety", "", "adapter call crashed",
                                              EvidenceKind::kProcess, &trace->diagnostics));
      } else if (call.status == PQCFUZZ_TIMEOUT) {
        trace->findings.push_back(MakeFinding(config, subtest.subtest_id, "timeout", "", "adapter call timed out",
                                              EvidenceKind::kProcess, &trace->diagnostics));
      }
    }
    if (subtest.passed || subtest.not_applicable) {
      continue;
    }
    const bool negative_expectation =
        subtest.expected_relation.find("VERIFY_FALSE") != std::string::npos ||
        subtest.expected_relation.find("REJECT") != std::string::npos ||
        subtest.expected_relation.find("DIFFERENT") != std::string::npos ||
        subtest.expected_relation.find("DECODE_REJECT") != std::string::npos;
    const std::string finding_class = negative_expectation ? "potential_crypto_vuln" : "confirmed_semantic_bug";
    std::string finding_subclass = subtest.subtest_id;
    if (config.oracle_id == "snova_exact_lengths" && subtest.subtest_id == "appended_signature_negative") {
      finding_subclass = "appended_signature_bytes_accepted";
    } else if (config.oracle_id == "snova_public_seed_binding") {
      finding_subclass = "public_key_seed_mutation_accepted";
    } else if (config.oracle_id == "snova_message_salt_binding") {
      finding_subclass = subtest.subtest_id + "_accepted";
    }
    trace->findings.push_back(MakeFinding(config, subtest.subtest_id, finding_class, finding_subclass, subtest.note,
                                          EvidenceKind::kSemantic, &trace->diagnostics));
  }
}

void SetSnovaTraceReachability(KEMOracleTrace *trace) {
  if (trace == nullptr || trace->subtests.empty()) {
    return;
  }
  const OracleSubtestTrace *first_with_calls = nullptr;
  const OracleSubtestTrace *last_with_calls = nullptr;
  for (const auto &subtest : trace->subtests) {
    if (subtest.calls.empty()) {
      continue;
    }
    if (first_with_calls == nullptr) {
      first_with_calls = &subtest;
    }
    last_with_calls = &subtest;
  }
  if (first_with_calls != nullptr) {
    trace->baseline_adapter_entered = first_with_calls->calls.front().adapter_entered;
    trace->baseline_target_entered = first_with_calls->calls.front().target_entered;
  }
  if (last_with_calls != nullptr) {
    trace->mutated_adapter_entered = last_with_calls->calls.back().adapter_entered;
    trace->mutated_target_entered = last_with_calls->calls.back().target_entered;
  }
  trace->relation_evaluable =
      !trace->relation_not_applicable && trace->baseline_target_entered && trace->mutated_target_entered;
}

void PopulateSnovaControls(const std::string &oracle_id, KEMOracleTrace *trace) {
  if (oracle_id == "snova_kat") {
    trace->controls.positive_control = "fixed seeds reproduce the pinned round-2 key and signature bytes";
    trace->controls.negative_control = "a different seed produces different signature bytes";
  } else if (oracle_id == "snova_rng_replay") {
    trace->controls.positive_control = "two runs under the same tape agree";
    trace->controls.negative_control = "a different tape changes the salt bytes";
  } else if (oracle_id == "snova_public_map") {
    trace->controls.positive_control = "the independent direct map reproduces the accepted signature";
    trace->controls.negative_control = "a mutation that changes the direct map is rejected by the target";
  } else if (oracle_id == "snova_fixed_abq") {
    trace->controls.positive_control = "expanding the same key twice reproduces the ABQ block";
    trace->controls.negative_control = "a seed-dependent profile is not asserted to share ABQ";
  } else if (oracle_id == "snova_nibble_encoding") {
    trace->controls.positive_control = "generated output padding is zero and encode/decode round-trips";
    trace->controls.negative_control = "the salt byte is hashed and cannot act as padding";
  } else if (oracle_id == "snova_backend_profile_gate") {
    trace->controls.positive_control = "the compiled adapter backend/sk format matches the profile";
    trace->controls.negative_control = "a mismatched backend or ABI is reported as a harness error";
  } else {
    trace->controls.positive_control = "the unmodified signature verifies";
    trace->controls.negative_control = "the targeted mutation is recorded as effective and rejected";
  }
}

std::vector<uint8_t> MessageDigest(const SnovaOracleConfig &config, const std::vector<uint8_t> &message) {
  (void)config;
  return Shake256(message, 64);
}

bool SnovaModelMap(
    const SnovaOracleConfig &config,
    const std::vector<uint8_t> &pk,
    const std::vector<uint8_t> &signature,
    std::vector<uint8_t> *map) {
  if (config.left_api == nullptr || config.left_api->expand_public == nullptr || map == nullptr) {
    return false;
  }
  if (pk.size() != config.params.pk_len || signature.size() < config.params.sig_max_len) {
    return false;
  }
  std::vector<uint8_t> expanded(config.params.expanded_pk_len);
  config.left_api->expand_public(expanded.data(), pk.data());
  return SnovaEvaluateExpandedPk(config.params, expanded, signature, map);
}

bool SnovaTargetHash(
    const SnovaOracleConfig &config,
    const std::vector<uint8_t> &pk,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &signature,
    std::vector<uint8_t> *target) {
  if (pk.size() != config.params.pk_len || signature.size() < config.params.sig_max_len || target == nullptr) {
    return false;
  }
  const std::vector<uint8_t> digest = MessageDigest(config, message);
  return SnovaTargetHashBytes(config.params, pk.data(), config.params.public_seed_bytes, digest.data(), digest.size(),
                              signature.data() + config.params.salt_off, config.params.salt_bytes, target);
}

// --------------------------------------------------------------------------
// Oracle 140: snova_kat
// --------------------------------------------------------------------------
OracleSubtestTrace SnovaKat(const SnovaOracleConfig &config, KEMOracleTrace *trace) {
  OracleSubtestTrace subtest = MakeSubtest("seeded_reference_reproduction", config.oracle_id, "EXPECT_EQUAL");
  OracleSubtestTrace setup = MakeSubtest("setup", config.oracle_id, "EXPECT_EQUAL");
  SIGKeyPair first = SnovaKeygen(config.left, "left", config.seed, "kat-keygen", &setup);
  SIGKeyPair second = SnovaKeygen(config.left, "left", config.seed, "kat-keygen", &setup);
  if (first.status != PQCFUZZ_OK || second.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "seeded key generation failed";
    subtest.calls = setup.calls;
    return subtest;
  }
  if (first.pk != second.pk || first.sk != second.sk) {
    subtest.passed = false;
    subtest.note = "seeded key generation is not reproducible";
    subtest.calls = setup.calls;
    return subtest;
  }
  SIGSignature sig_a = SnovaSign(config.left, "left", config.message, first.sk, config.seed, "kat-sign", &setup);
  SIGSignature sig_b = SnovaSign(config.left, "left", config.message, first.sk, config.seed, "kat-sign", &setup);
  if (sig_a.status != PQCFUZZ_OK || sig_b.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "seeded signing failed";
    subtest.calls = setup.calls;
    return subtest;
  }
  if (sig_a.sig != sig_b.sig) {
    subtest.passed = false;
    subtest.note = "seeded signing is not reproducible";
    subtest.calls = setup.calls;
    return subtest;
  }
  SIGVerifyResult verified = SnovaVerify(config.left, "left", sig_a.sig, config.message, first.pk, &subtest);
  subtest.passed = verified.status == PQCFUZZ_OK;
  if (!subtest.passed) {
    subtest.note = "seeded reference signature does not verify";
  }
  if (!setup.calls.empty()) {
    trace->baseline.output_size = sig_a.sig.size();
    trace->baseline.output_sha256 = MutationSha256Hex(sig_a.sig);
    trace->mutated = trace->baseline;
  }
  return subtest;
}

// --------------------------------------------------------------------------
// Oracle 141: snova_local_sign_verify
// --------------------------------------------------------------------------
std::vector<OracleSubtestTrace> SnovaLocalSignVerify(const SnovaOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  const std::vector<std::vector<uint8_t>> messages = {
      {}, {'P', 'Q', 'C', 'F', 'u', 'z', 'z'}, {0x00, 0xFF, 0x10, 0x00, 0x7F}};
  const char *names[] = {"empty_message_roundtrip", "binary_message_roundtrip", "mixed_message_roundtrip"};
  for (size_t index = 0; index < messages.size(); ++index) {
    OracleSubtestTrace subtest = MakeSubtest(names[index], config.oracle_id, "VERIFY_TRUE");
    SnovaSetup setup = SetupHonestSignature(config, &subtest, messages[index], "local");
    if (!setup.ok()) {
      subtest.passed = false;
      subtest.note = "honest key generation or signing failed";
      subtests.push_back(std::move(subtest));
      continue;
    }
    SIGVerifyResult verified = SnovaVerify(config.left, "left", setup.signature.sig, messages[index], setup.keypair.pk, &subtest);
    subtest.passed = verified.status == PQCFUZZ_OK;
    if (!subtest.passed) {
      subtest.note = "honest signature does not verify";
    }
    subtests.push_back(std::move(subtest));
  }
  OracleSubtestTrace digest_subtest = MakeSubtest("digest_api_roundtrip", config.oracle_id, "VERIFY_TRUE");
  if (config.left_api == nullptr || config.left_api->sign_digest == nullptr || config.left_api->verify_digest == nullptr) {
    MarkNotApplicable(&digest_subtest, "digest API not available in the compiled adapter");
  } else {
    OracleSubtestTrace setup_trace = MakeSubtest("digest_setup", config.oracle_id, "VERIFY_TRUE");
    SIGKeyPair keypair = SnovaKeygen(config.left, "left", config.seed, "digest-keygen", &setup_trace);
    std::vector<uint8_t> digest = Shake256(config.message, 64);
    std::vector<uint8_t> salt = DeriveSeed(config.seed, "digest-salt", config.params.salt_bytes);
    SIGSignature signature = SnovaSignDigest(config.left_api, "left", digest, keypair.sk, salt, &setup_trace);
    digest_subtest.calls = setup_trace.calls;
    if (keypair.status != PQCFUZZ_OK || signature.status != PQCFUZZ_OK) {
      digest_subtest.passed = false;
      digest_subtest.note = "digest setup failed";
    } else {
      SIGVerifyResult verified = SnovaVerifyDigest(config.left_api, "left", signature.sig, digest, keypair.pk, &digest_subtest);
      digest_subtest.passed = verified.status == PQCFUZZ_OK;
      if (!digest_subtest.passed) {
        digest_subtest.note = "digest signature does not verify";
      }
    }
  }
  subtests.push_back(std::move(digest_subtest));
  return subtests;
}

// --------------------------------------------------------------------------
// Oracle 142: snova_cross_verify
// --------------------------------------------------------------------------
OracleSubtestTrace SnovaCrossVerify(const SnovaOracleConfig &config) {
  OracleSubtestTrace subtest = MakeSubtest("left_sign_right_verify", config.oracle_id, "VERIFY_TRUE");
  if (config.right == nullptr || config.right->verify == nullptr) {
    MarkNotApplicable(&subtest, "no right implementation supplied");
    return subtest;
  }
  if (!config.signature_exchange) {
    MarkNotApplicable(&subtest, "signature_exchange is disabled for this pair");
    return subtest;
  }
  SnovaSetup setup = SetupHonestSignature(config, &subtest, config.message, "cross-left");
  if (!setup.ok()) {
    subtest.passed = false;
    subtest.note = "left honest setup failed";
    return subtest;
  }
  SIGVerifyResult right_verify = SnovaVerify(config.right, "right", setup.signature.sig, config.message, setup.keypair.pk, &subtest);
  if (right_verify.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "right implementation rejected the left signature";
    return subtest;
  }
  SIGKeyPair right_key = SnovaKeygen(config.right, "right", config.seed, "cross-right", &subtest);
  if (right_key.status != PQCFUZZ_OK || config.left->sign_seeded == nullptr) {
    subtest.passed = false;
    subtest.note = "right key generation failed";
    return subtest;
  }
  SIGSignature right_sig = SnovaSign(config.right, "right", config.message, right_key.sk, config.seed, "cross-right-sign", &subtest);
  if (right_sig.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "right signing failed";
    return subtest;
  }
  SIGVerifyResult left_verify = SnovaVerify(config.left, "left", right_sig.sig, config.message, right_key.pk, &subtest);
  subtest.passed = left_verify.status == PQCFUZZ_OK;
  if (!subtest.passed) {
    subtest.note = "left implementation rejected the right signature";
  }
  return subtest;
}

// --------------------------------------------------------------------------
// Oracle 143: snova_message_salt_binding
// --------------------------------------------------------------------------
std::vector<OracleSubtestTrace> SnovaMessageSaltBinding(const SnovaOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup_trace = MakeSubtest("setup", config.oracle_id, "VERIFY_TRUE");
  SnovaSetup setup = SetupHonestSignature(config, &setup_trace, config.message, "binding");
  if (!setup.ok()) {
    OracleSubtestTrace failed = MakeSubtest("honest_setup", config.oracle_id, "VERIFY_TRUE");
    failed.passed = false;
    failed.note = "honest setup failed";
    failed.calls = setup_trace.calls;
    subtests.push_back(std::move(failed));
    return subtests;
  }

  {
    OracleSubtestTrace subtest = MakeSubtest("mutated_message_negative", config.oracle_id, "VERIFY_FALSE");
    subtest.calls = setup_trace.calls;
    std::vector<uint8_t> mutated_message = config.message;
    if (mutated_message.empty()) {
      mutated_message.push_back(0x01);
    } else {
      mutated_message[0] ^= 0x01;
    }
    SIGVerifyResult verified = SnovaVerify(config.left, "left", setup.signature.sig, mutated_message, setup.keypair.pk, &subtest);
    subtest.passed = RejectionLike(verified.status) || verified.status == PQCFUZZ_API_UNSUPPORTED;
    if (!subtest.passed) {
      subtest.note = "mutated message accepted";
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("mutated_salt_negative", config.oracle_id, "VERIFY_FALSE");
    subtest.calls = setup_trace.calls;
    std::vector<uint8_t> mutated = setup.signature.sig;
    SchemeMutation plan;
    plan.op = SchemeMutationOp::kXorByte;
    plan.field = SchemeMutationField::kSnovaSignatureSalt;
    plan.index = 0;
    plan.payload = {0x01};
    std::vector<MutationRecord> records = MutateSnovaSignature(config.params, EncodeSchemeMutation(plan), &mutated);
    RecordMutationEffect(records, trace);
    const bool effective = std::any_of(records.begin(), records.end(),
                                       [](const MutationRecord &record) { return record.effective && !record.skipped; });
    if (!effective) {
      MarkNotApplicable(&subtest, "salt mutation had no effect");
      subtests.push_back(std::move(subtest));
    } else {
      SIGVerifyResult verified = SnovaVerify(config.left, "left", mutated, config.message, setup.keypair.pk, &subtest);
      subtest.passed = RejectionLike(verified.status) || verified.status == PQCFUZZ_API_UNSUPPORTED;
      if (!subtest.passed) {
        subtest.note = "mutated salt accepted";
      }
      subtests.push_back(std::move(subtest));
    }
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("foreign_key_negative", config.oracle_id, "VERIFY_FALSE");
    subtest.calls = setup_trace.calls;
    SIGKeyPair foreign = SnovaKeygen(config.left, "left", config.seed, "binding-foreign", &subtest);
    if (foreign.status != PQCFUZZ_OK) {
      MarkNotApplicable(&subtest, "foreign key generation failed");
      subtests.push_back(std::move(subtest));
    } else if (foreign.pk == setup.keypair.pk) {
      MarkNotApplicable(&subtest, "derived foreign key matched the honest key");
      subtests.push_back(std::move(subtest));
    } else {
      SIGVerifyResult verified = SnovaVerify(config.left, "left", setup.signature.sig, config.message, foreign.pk, &subtest);
      subtest.passed = RejectionLike(verified.status) || verified.status == PQCFUZZ_API_UNSUPPORTED;
      if (!subtest.passed) {
        subtest.note = "signature accepted under a foreign key";
      }
      subtests.push_back(std::move(subtest));
    }
  }
  return subtests;
}

// --------------------------------------------------------------------------
// Oracle 144: snova_public_seed_binding
// --------------------------------------------------------------------------
std::vector<OracleSubtestTrace> SnovaPublicSeedBinding(const SnovaOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup_trace = MakeSubtest("setup", config.oracle_id, "VERIFY_TRUE");
  SnovaSetup setup = SetupHonestSignature(config, &setup_trace, config.message, "pk-binding");
  if (!setup.ok()) {
    OracleSubtestTrace failed = MakeSubtest("honest_setup", config.oracle_id, "VERIFY_TRUE");
    failed.passed = false;
    failed.note = "honest setup failed";
    failed.calls = setup_trace.calls;
    subtests.push_back(std::move(failed));
    return subtests;
  }
  const auto run_negative = [&](const std::string &subtest_id, std::vector<uint8_t> mutated_pk,
                                const std::vector<MutationRecord> &records) {
    OracleSubtestTrace subtest = MakeSubtest(subtest_id, config.oracle_id, "VERIFY_FALSE");
    subtest.calls = setup_trace.calls;
    RecordMutationEffect(records, trace);
    const bool effective = std::any_of(records.begin(), records.end(),
                                       [](const MutationRecord &record) { return record.effective && !record.skipped; });
    if (!effective) {
      MarkNotApplicable(&subtest, "public key mutation had no effect");
      return subtest;
    }
    SIGVerifyResult verified = SnovaVerify(config.left, "left", setup.signature.sig, config.message, mutated_pk, &subtest);
    subtest.passed = RejectionLike(verified.status) || verified.status == PQCFUZZ_API_UNSUPPORTED;
    if (!subtest.passed) {
      subtest.note = "mutated public key accepted";
    }
    return subtest;
  };
  {
    std::vector<uint8_t> mutated_pk = setup.keypair.pk;
    SchemeMutation plan;
    plan.op = SchemeMutationOp::kXorByte;
    plan.field = SchemeMutationField::kSnovaPublicKeySpublic;
    plan.index = 3;
    plan.payload = {0x40};
    std::vector<MutationRecord> records = MutateSnovaPublicKey(config.params, EncodeSchemeMutation(plan), &mutated_pk);
    subtests.push_back(run_negative("spublic_mutation_negative", std::move(mutated_pk), records));
  }
  {
    std::vector<uint8_t> mutated_pk = setup.keypair.pk;
    SchemeMutation plan;
    plan.op = SchemeMutationOp::kSetCoefficient;
    plan.field = SchemeMutationField::kSnovaPublicKeyP22Nibble;
    plan.index = 0;
    plan.aux = 7;
    std::vector<MutationRecord> records = MutateSnovaPublicKey(config.params, EncodeSchemeMutation(plan), &mutated_pk);
    subtests.push_back(run_negative("p22_nibble_mutation_negative", std::move(mutated_pk), records));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("foreign_honest_pk_negative", config.oracle_id, "VERIFY_FALSE");
    subtest.calls = setup_trace.calls;
    SIGKeyPair foreign = SnovaKeygen(config.left, "left", config.seed, "pk-binding-foreign", &subtest);
    if (foreign.status != PQCFUZZ_OK || foreign.pk == setup.keypair.pk) {
      MarkNotApplicable(&subtest, "no independent honest public key available");
      subtests.push_back(std::move(subtest));
    } else {
      SIGVerifyResult verified = SnovaVerify(config.left, "left", setup.signature.sig, config.message, foreign.pk, &subtest);
      subtest.passed = RejectionLike(verified.status) || verified.status == PQCFUZZ_API_UNSUPPORTED;
      if (!subtest.passed) {
        subtest.note = "signature accepted under a different honest public key";
      }
      subtests.push_back(std::move(subtest));
    }
  }
  return subtests;
}

// --------------------------------------------------------------------------
// Oracle 145: snova_exact_lengths
// --------------------------------------------------------------------------
std::vector<OracleSubtestTrace> SnovaExactLengths(const SnovaOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup_trace = MakeSubtest("setup", config.oracle_id, "VERIFY_TRUE");
  SnovaSetup setup = SetupHonestSignature(config, &setup_trace, config.message, "lengths");
  if (!setup.ok()) {
    OracleSubtestTrace failed = MakeSubtest("honest_setup", config.oracle_id, "VERIFY_TRUE");
    failed.passed = false;
    failed.note = "honest setup failed";
    failed.calls = setup_trace.calls;
    subtests.push_back(std::move(failed));
    return subtests;
  }
  const size_t exact = config.left->sig_max_len;
  {
    OracleSubtestTrace subtest = MakeSubtest("baseline_exact_length", config.oracle_id, "VERIFY_TRUE");
    subtest.calls = setup_trace.calls;
    SIGVerifyResult verified = SnovaVerify(config.left, "left", setup.signature.sig, config.message, setup.keypair.pk, &subtest);
    subtest.passed = verified.status == PQCFUZZ_OK && setup.signature.sig.size() == exact;
    if (!subtest.passed) {
      subtest.note = "baseline signature does not verify at the exact profile length";
    }
    subtests.push_back(std::move(subtest));
  }
  const auto run_length_negative = [&](const std::string &subtest_id, std::vector<uint8_t> candidate) {
    OracleSubtestTrace subtest = MakeSubtest(subtest_id, config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    subtest.calls = setup_trace.calls;
    SIGVerifyResult verified = SnovaVerify(config.left, "left", candidate, config.message, setup.keypair.pk, &subtest);
    subtest.passed = RejectionLike(verified.status) || verified.status == PQCFUZZ_API_UNSUPPORTED;
    if (!subtest.passed) {
      subtest.note = "adapter length gate accepted a non-canonical signature length";
    }
    return subtest;
  };
  subtests.push_back(run_length_negative("empty_signature_negative", {}));
  subtests.push_back(run_length_negative("one_byte_signature_negative", std::vector<uint8_t>(1, 0x00)));
  {
    std::vector<uint8_t> truncated = setup.signature.sig;
    truncated.pop_back();
    subtests.push_back(run_length_negative("truncated_signature_negative", std::move(truncated)));
  }
  {
    std::vector<uint8_t> appended = setup.signature.sig;
    appended.push_back(0x00);
    subtests.push_back(run_length_negative("appended_signature_negative", std::move(appended)));
  }
  return subtests;
}

// --------------------------------------------------------------------------
// Oracle 146: snova_nibble_encoding
// --------------------------------------------------------------------------
std::vector<OracleSubtestTrace> SnovaNibbleEncoding(const SnovaOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup_trace = MakeSubtest("setup", config.oracle_id, "VERIFY_TRUE");
  SnovaSetup setup = SetupHonestSignature(config, &setup_trace, config.message, "nibble");
  if (!setup.ok()) {
    OracleSubtestTrace failed = MakeSubtest("honest_setup", config.oracle_id, "VERIFY_TRUE");
    failed.passed = false;
    failed.note = "honest setup failed";
    failed.calls = setup_trace.calls;
    subtests.push_back(std::move(failed));
    return subtests;
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("output_padding_zero", config.oracle_id, "EXPECT_EQUAL");
    subtest.calls = setup_trace.calls;
    if (!SnovaSignatureUsesPadding(config.params)) {
      MarkNotApplicable(&subtest, "n*l^2 is even, the signature has no padding nibble");
    } else {
      const size_t nibbles = config.params.n_matrices * config.params.sq_rank;
      const size_t offset = SnovaSignatureNibbleOffset(config.params, nibbles);
      const uint8_t high = static_cast<uint8_t>((setup.signature.sig[offset] >> 4) & 0x0F);
      subtest.passed = high == 0;
      if (!subtest.passed) {
        subtest.note = "generated signature has a nonzero padding nibble";
      }
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("encode_decode_roundtrip", config.oracle_id, "EXPECT_EQUAL");
    subtest.calls = setup_trace.calls;
    std::vector<uint8_t> roundtrip = setup.signature.sig;
    const size_t total = config.params.n_matrices * config.params.sq_rank;
    bool ok = true;
    for (size_t index = 0; index < total; ++index) {
      uint8_t value = 0;
      if (!SnovaDecodeSignatureNibble(config.params, setup.signature.sig, index, &value) ||
          !SnovaEncodeSignatureNibble(config.params, &roundtrip, index, value)) {
        ok = false;
        break;
      }
    }
    subtest.passed = ok && roundtrip == setup.signature.sig;
    if (!subtest.passed) {
      subtest.note = "nibble encode/decode is not a roundtrip";
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("salt_byte_hashed_negative", config.oracle_id, "VERIFY_FALSE");
    subtest.calls = setup_trace.calls;
    std::vector<uint8_t> mutated = setup.signature.sig;
    // The last signature byte is salt, never padding.
    mutated[config.params.sig_max_len - 1] ^= 0x01;
    MutationRecord record;
    record.operation = "xor_byte";
    record.target = "signature.salt_last_byte";
    record.offset = config.params.sig_max_len - 1;
    record.length = 1;
    RecordMutationEffect(&record, setup.signature.sig, mutated);
    trace->mutations.push_back(record);
    SIGVerifyResult verified = SnovaVerify(config.left, "left", mutated, config.message, setup.keypair.pk, &subtest);
    subtest.passed = RejectionLike(verified.status) || verified.status == PQCFUZZ_API_UNSUPPORTED;
    if (!subtest.passed) {
      subtest.note = "mutated final salt byte accepted";
    }
    subtests.push_back(std::move(subtest));
  }
  if (SnovaSignatureUsesPadding(config.params)) {
    OracleSubtestTrace subtest = MakeSubtest("input_padding_alias_observation", config.oracle_id, "VERIFY_FALSE");
    subtest.calls = setup_trace.calls;
    std::vector<uint8_t> mutated = setup.signature.sig;
    std::vector<MutationRecord> records = MutateSnovaSignaturePadding(config.params, 0x0F, &mutated);
    RecordMutationEffect(records, trace);
    SIGVerifyResult verified = SnovaVerify(config.left, "left", mutated, config.message, setup.keypair.pk, &subtest);
    subtest.passed = true;  // Recorded as an observation: accept or reject are both informative.
    if (verified.status == PQCFUZZ_OK) {
      subtest.note = "nonzero unused high nibble accepted as a byte alias; not an EUF forgery";
    } else {
      subtest.note = "verifier rejects a nonzero unused high nibble (strict policy)";
    }
    subtests.push_back(std::move(subtest));
  }
  return subtests;
}

// --------------------------------------------------------------------------
// Oracle 148: snova_public_map
// --------------------------------------------------------------------------
std::vector<OracleSubtestTrace> SnovaPublicMap(const SnovaOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  if (config.left_api == nullptr || config.left_api->expand_public == nullptr) {
    OracleSubtestTrace subtest = MakeSubtest("direct_map_matches_target", config.oracle_id, "EXPECT_EQUAL");
    MarkNotApplicable(&subtest, "expanded public key hook unavailable");
    subtests.push_back(std::move(subtest));
    return subtests;
  }
  OracleSubtestTrace setup_trace = MakeSubtest("setup", config.oracle_id, "VERIFY_TRUE");
  SnovaSetup setup = SetupHonestSignature(config, &setup_trace, config.message, "public-map");
  if (!setup.ok()) {
    OracleSubtestTrace failed = MakeSubtest("honest_setup", config.oracle_id, "VERIFY_TRUE");
    failed.passed = false;
    failed.note = "honest setup failed";
    failed.calls = setup_trace.calls;
    subtests.push_back(std::move(failed));
    return subtests;
  }
  std::vector<uint8_t> baseline_map;
  std::vector<uint8_t> target_hash;
  const bool model_ok = SnovaModelMap(config, setup.keypair.pk, setup.signature.sig, &baseline_map);
  const bool target_ok = SnovaTargetHash(config, setup.keypair.pk, config.message, setup.signature.sig, &target_hash);
  {
    OracleSubtestTrace subtest = MakeSubtest("direct_map_matches_target_hash", config.oracle_id, "EXPECT_EQUAL");
    subtest.calls = setup_trace.calls;
    if (!model_ok || !target_ok) {
      subtest.passed = false;
      subtest.note = "independent map evaluation failed";
    } else {
      const bool agrees = SnovaMapBytesEqual(config.params, baseline_map, target_hash);
      subtest.passed = agrees;
      if (!agrees) {
        subtest.note = "independent Ptilde(U) disagrees with SHAKE256(spublic||digest||salt)";
      }
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("direct_map_matches_target_accept", config.oracle_id, "VERIFY_TRUE");
    subtest.calls = setup_trace.calls;
    SIGVerifyResult verified = SnovaVerify(config.left, "left", setup.signature.sig, config.message, setup.keypair.pk, &subtest);
    subtest.passed = verified.status == PQCFUZZ_OK && model_ok;
    if (!subtest.passed) {
      subtest.note = "target rejected an honest signature or the map model failed";
    }
    subtests.push_back(std::move(subtest));
  }
  if (model_ok && target_ok) {
    const size_t nibbles = config.params.n_matrices * config.params.sq_rank;
    bool found = false;
    std::vector<uint8_t> mutated_sig;
    std::vector<uint8_t> mutated_map;
    size_t mutated_index = 0;
    for (size_t attempt = 0; attempt < 32 && attempt < nibbles; ++attempt) {
      const size_t index = attempt;
      mutated_sig = setup.signature.sig;
      uint8_t current = 0;
      SnovaDecodeSignatureNibble(config.params, mutated_sig, index, &current);
      MutateSnovaSignatureNibble(config.params, index, static_cast<uint8_t>(current ^ 0x01), &mutated_sig);
      if (!SnovaModelMap(config, setup.keypair.pk, mutated_sig, &mutated_map)) {
        continue;
      }
      if (mutated_map != baseline_map) {
        found = true;
        mutated_index = index;
        break;
      }
    }
    OracleSubtestTrace subtest = MakeSubtest("mutated_u_nibble_negative", config.oracle_id, "VERIFY_FALSE");
    subtest.calls = setup_trace.calls;
    if (!found) {
      MarkNotApplicable(&subtest, "no single-nibble mutation changed the direct map in the probe window");
    } else {
      SIGVerifyResult verified = SnovaVerify(config.left, "left", mutated_sig, config.message, setup.keypair.pk, &subtest);
      subtest.passed = RejectionLike(verified.status);
      if (!subtest.passed) {
        subtest.note = "target accepted a signature whose independent map changed";
      } else {
        subtest.note = "nibble " + std::to_string(mutated_index) + " changed the map and was rejected";
      }
    }
    subtests.push_back(std::move(subtest));
  }
  {
    std::vector<uint8_t> original_map = baseline_map;
    std::vector<uint8_t> mutated_pk = setup.keypair.pk;
    uint8_t current = 0;
    SnovaDecodeP22Nibble(config.params, mutated_pk, 0, &current);
    std::vector<MutationRecord> records =
        MutateSnovaP22Nibble(config.params, 0, static_cast<uint8_t>(current ^ 0x01), &mutated_pk);
    RecordMutationEffect(records, trace);
    OracleSubtestTrace subtest = MakeSubtest("mutated_p22_nibble_negative", config.oracle_id, "VERIFY_FALSE");
    subtest.calls = setup_trace.calls;
    std::vector<uint8_t> mutated_map;
    if (model_ok && !original_map.empty() && SnovaModelMap(config, mutated_pk, setup.signature.sig, &mutated_map) &&
        mutated_map != original_map) {
      SIGVerifyResult verified = SnovaVerify(config.left, "left", setup.signature.sig, config.message, mutated_pk, &subtest);
      subtest.passed = RejectionLike(verified.status);
      if (!subtest.passed) {
        subtest.note = "target accepted a signature under a mutated P22";
      }
    } else {
      MarkNotApplicable(&subtest, "P22 mutation did not change the independent map");
    }
    subtests.push_back(std::move(subtest));
  }
  return subtests;
}

// --------------------------------------------------------------------------
// Oracle 152: snova_fixed_abq
// --------------------------------------------------------------------------
std::vector<OracleSubtestTrace> SnovaFixedAbq(const SnovaOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  if (config.left_api == nullptr || config.left_api->expand_public == nullptr) {
    OracleSubtestTrace subtest = MakeSubtest("fixed_abq_shared_across_keys", config.oracle_id, "EXPECT_EQUAL");
    MarkNotApplicable(&subtest, "expanded public key hook unavailable");
    subtests.push_back(std::move(subtest));
    return subtests;
  }
  OracleSubtestTrace setup_trace = MakeSubtest("setup", config.oracle_id, "EXPECT_EQUAL");
  SIGKeyPair first = SnovaKeygen(config.left, "left", config.seed, "abq-a", &setup_trace);
  SIGKeyPair second = SnovaKeygen(config.left, "left", config.seed, "abq-b", &setup_trace);
  if (first.status != PQCFUZZ_OK || second.status != PQCFUZZ_OK) {
    OracleSubtestTrace failed = MakeSubtest("honest_setup", config.oracle_id, "EXPECT_EQUAL");
    failed.passed = false;
    failed.note = "honest setup failed";
    failed.calls = setup_trace.calls;
    subtests.push_back(std::move(failed));
    return subtests;
  }
  const size_t abq_begin = config.params.expand_a_nibble_off;
  const size_t abq_end = config.params.expand_q2_nibble_off +
                         config.params.m_matrices * config.params.alpha_terms * config.params.sq_rank;
  const auto expand = [&](const SIGKeyPair &keypair) {
    std::vector<uint8_t> expanded(config.params.expanded_pk_len);
    config.left_api->expand_public(expanded.data(), keypair.pk.data());
    return expanded;
  };
  {
    OracleSubtestTrace subtest = MakeSubtest("expansion_reproducible", config.oracle_id, "EXPECT_EQUAL");
    subtest.calls = setup_trace.calls;
    subtest.passed = expand(first) == expand(first);
    if (!subtest.passed) {
      subtest.note = "expanding the same key twice diverged";
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("fixed_abq_shared_across_keys", config.oracle_id, "EXPECT_EQUAL");
    subtest.calls = setup_trace.calls;
    if (!config.params.fixed_abq) {
      MarkNotApplicable(&subtest, "l > 3 profile expands ABQ from the public seed");
    } else if (first.pk == second.pk) {
      MarkNotApplicable(&subtest, "derived keys did not differ");
    } else {
      std::vector<uint8_t> first_expanded = expand(first);
      std::vector<uint8_t> second_expanded = expand(second);
      bool equal = true;
      for (size_t nibble = abq_begin; nibble < abq_end; ++nibble) {
        const uint8_t a = (first_expanded[config.params.public_seed_bytes + nibble / 2] >> ((nibble % 2) * 4)) & 0x0F;
        const uint8_t b = (second_expanded[config.params.public_seed_bytes + nibble / 2] >> ((nibble % 2) * 4)) & 0x0F;
        if (a != b) {
          equal = false;
          break;
        }
      }
      subtest.passed = equal;
      if (!equal) {
        subtest.note = "l <= 3 profiles must use the fixed SNOVA ABQ block";
      }
    }
    subtests.push_back(std::move(subtest));
  }
  return subtests;
}

// --------------------------------------------------------------------------
// Oracle 153: snova_ssk_esk_equivalence
// --------------------------------------------------------------------------
std::vector<OracleSubtestTrace> SnovaSskEskEquivalence(const SnovaOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  const bool formats_differ = config.right_api != nullptr && config.left_api != nullptr &&
                              std::strcmp(config.left_api->sk_format, config.right_api->sk_format) != 0;
  {
    OracleSubtestTrace subtest = MakeSubtest("seeded_pk_equivalence", config.oracle_id, "EXPECT_EQUAL");
    if (!formats_differ) {
      MarkNotApplicable(&subtest, "pair does not expose two private-key storage formats");
      subtests.push_back(std::move(subtest));
    } else {
      SIGKeyPair left = SnovaKeygen(config.left, "left", config.seed, "formats", &subtest);
      SIGKeyPair right = SnovaKeygen(config.right, "right", config.seed, "formats", &subtest);
      if (left.status != PQCFUZZ_OK || right.status != PQCFUZZ_OK) {
        subtest.passed = false;
        subtest.note = "key generation failed for one storage format";
      } else {
        subtest.passed = left.pk == right.pk;
        if (!subtest.passed) {
          subtest.note = "SSK/ESK key generation produced different public keys";
        }
      }
      subtests.push_back(std::move(subtest));
    }
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("seeded_signature_equivalence", config.oracle_id, "EXPECT_EQUAL");
    if (!formats_differ) {
      MarkNotApplicable(&subtest, "pair does not expose two private-key storage formats");
      subtests.push_back(std::move(subtest));
    } else {
      SIGKeyPair left = SnovaKeygen(config.left, "left", config.seed, "formats", &subtest);
      SIGKeyPair right = SnovaKeygen(config.right, "right", config.seed, "formats", &subtest);
      SIGSignature left_sig = SnovaSign(config.left, "left", config.message, left.sk, config.seed, "formats-sign", &subtest);
      SIGSignature right_sig = SnovaSign(config.right, "right", config.message, right.sk, config.seed, "formats-sign", &subtest);
      if (left.status != PQCFUZZ_OK || right.status != PQCFUZZ_OK || left_sig.status != PQCFUZZ_OK ||
          right_sig.status != PQCFUZZ_OK) {
        subtest.passed = false;
        subtest.note = "signing failed for one storage format";
      } else {
        subtest.passed = left_sig.sig == right_sig.sig;
        if (!subtest.passed) {
          subtest.note = "same seeds/salt produced different signature bytes for SSK and ESK";
        }
      }
      subtests.push_back(std::move(subtest));
    }
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("keygen_from_sk_equivalence", config.oracle_id, "EXPECT_EQUAL");
    if (!formats_differ || config.left_api == nullptr || config.left_api->keygen_from_sk == nullptr ||
        config.right_api == nullptr || config.right_api->keygen_from_sk == nullptr) {
      MarkNotApplicable(&subtest, "keygen-from-sk hook unavailable for one storage format");
      subtests.push_back(std::move(subtest));
    } else {
      SIGKeyPair left = SnovaKeygen(config.left, "left", config.seed, "formats", &subtest);
      SIGKeyPair right = SnovaKeygen(config.right, "right", config.seed, "formats", &subtest);
      std::vector<uint8_t> left_pk(config.left->pk_len);
      std::vector<uint8_t> right_pk(config.right->pk_len);
      const pqcfuzz_status left_status = config.left_api->keygen_from_sk(left_pk.data(), left.sk.data(), left.sk.size());
      const pqcfuzz_status right_status =
          config.right_api->keygen_from_sk(right_pk.data(), right.sk.data(), right.sk.size());
      if (left_status != PQCFUZZ_OK || right_status != PQCFUZZ_OK) {
        subtest.passed = false;
        subtest.note = "keygen_from_sk failed for one storage format";
      } else {
        subtest.passed = left_pk == right_pk && left_pk == left.pk;
        if (!subtest.passed) {
          subtest.note = "recomputed public keys differ between storage formats";
        }
      }
      subtests.push_back(std::move(subtest));
    }
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("cross_format_signature_roundtrip", config.oracle_id, "VERIFY_TRUE");
    if (!formats_differ) {
      MarkNotApplicable(&subtest, "pair does not expose two private-key storage formats");
      subtests.push_back(std::move(subtest));
    } else {
      SIGKeyPair left = SnovaKeygen(config.left, "left", config.seed, "formats", &subtest);
      SIGSignature signature = SnovaSign(config.left, "left", config.message, left.sk, config.seed, "formats-sign", &subtest);
      if (signature.status != PQCFUZZ_OK) {
        subtest.passed = false;
        subtest.note = "left signing failed";
      } else {
        SIGVerifyResult verified = SnovaVerify(config.right, "right", signature.sig, config.message, left.pk, &subtest);
        subtest.passed = verified.status == PQCFUZZ_OK;
        if (!subtest.passed) {
          subtest.note = "right storage format rejected the left signature";
        }
      }
      subtests.push_back(std::move(subtest));
    }
  }
  return subtests;
}

// --------------------------------------------------------------------------
// Oracle 155: snova_rng_replay
// --------------------------------------------------------------------------
std::vector<OracleSubtestTrace> SnovaRngReplay(const SnovaOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  std::vector<uint8_t> tape_a(64);
  std::vector<uint8_t> tape_b(64);
  for (size_t i = 0; i < tape_a.size(); ++i) {
    tape_a[i] = static_cast<uint8_t>(0x11u + i);
    tape_b[i] = static_cast<uint8_t>(0x91u + (3u * i));
  }
  const RngTape rng_a{tape_a.data(), tape_a.size(), true, RngTape::Mode::kOk};
  const RngTape rng_b{tape_b.data(), tape_b.size(), true, RngTape::Mode::kOk};
  {
    OracleSubtestTrace subtest = MakeSubtest("same_tape_keygen_reproducible", config.oracle_id, "EXPECT_EQUAL");
    SIGKeyPair first = SnovaKeygenFromTape(config.left, "left", rng_a, &subtest);
    SIGKeyPair second = SnovaKeygenFromTape(config.left, "left", rng_a, &subtest);
    subtest.passed = first.status == PQCFUZZ_OK && second.status == PQCFUZZ_OK && first.pk == second.pk;
    if (!subtest.passed) {
      subtest.note = "key generation under a fixed tape is not reproducible";
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("different_tape_keygen_differs", config.oracle_id, "EXPECT_DIFFERENT");
    SIGKeyPair first = SnovaKeygenFromTape(config.left, "left", rng_a, &subtest);
    SIGKeyPair second = SnovaKeygenFromTape(config.left, "left", rng_b, &subtest);
    subtest.passed = first.status == PQCFUZZ_OK && second.status == PQCFUZZ_OK && first.pk != second.pk;
    if (!subtest.passed) {
      subtest.note = "different RNG tapes produced the same public key";
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("same_tape_sign_reproducible", config.oracle_id, "EXPECT_EQUAL");
    SIGKeyPair keypair = SnovaKeygen(config.left, "left", config.seed, "rng-replay", &subtest);
    SIGSignature first = SnovaSignFromTape(config.left, "left", config.message, keypair.sk, rng_a, &subtest);
    SIGSignature second = SnovaSignFromTape(config.left, "left", config.message, keypair.sk, rng_a, &subtest);
    subtest.passed = keypair.status == PQCFUZZ_OK && first.status == PQCFUZZ_OK && second.status == PQCFUZZ_OK &&
                     first.sig == second.sig;
    if (!subtest.passed) {
      subtest.note = "signing under a fixed salt tape is not reproducible";
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("different_tape_sign_differs", config.oracle_id, "EXPECT_DIFFERENT");
    SIGKeyPair keypair = SnovaKeygen(config.left, "left", config.seed, "rng-replay", &subtest);
    SIGSignature first = SnovaSignFromTape(config.left, "left", config.message, keypair.sk, rng_a, &subtest);
    SIGSignature second = SnovaSignFromTape(config.left, "left", config.message, keypair.sk, rng_b, &subtest);
    subtest.passed = keypair.status == PQCFUZZ_OK && first.status == PQCFUZZ_OK && second.status == PQCFUZZ_OK &&
                     first.sig != second.sig;
    if (!subtest.passed) {
      subtest.note = "different salt tapes produced identical signatures";
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("rng_failure_keygen_reported", config.oracle_id, "REJECT_OR_INVALID_INPUT");
    const uint8_t dummy = 0x5A;
    const RngTape failing{&dummy, 1, true, RngTape::Mode::kReportedFailure};
    pqcfuzz_rng_reset_failure_observed();
    SIGKeyPair keypair = SnovaKeygenFromTape(config.left, "left", failing, &subtest);
    const bool observed = pqcfuzz_rng_failure_observed();
    subtest.passed = keypair.status == PQCFUZZ_INVALID_INPUT && observed;
    if (!subtest.passed) {
      subtest.note = "key generation did not report a requested RNG failure";
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("rng_failure_sign_reported", config.oracle_id, "REJECT_OR_INVALID_INPUT");
    SIGKeyPair keypair = SnovaKeygen(config.left, "left", config.seed, "rng-replay", &subtest);
    const uint8_t dummy = 0x5A;
    const RngTape failing{&dummy, 1, true, RngTape::Mode::kReportedFailure};
    pqcfuzz_rng_reset_failure_observed();
    SIGSignature signature = SnovaSignFromTape(config.left, "left", config.message, keypair.sk, failing, &subtest);
    const bool observed = pqcfuzz_rng_failure_observed();
    subtest.passed = signature.status == PQCFUZZ_INVALID_INPUT && observed;
    if (!subtest.passed) {
      subtest.note = "signing did not report a requested RNG failure";
    }
    subtests.push_back(std::move(subtest));
  }
  return subtests;
}

// --------------------------------------------------------------------------
// Oracle 156: snova_malformed_key_state
// --------------------------------------------------------------------------
std::vector<OracleSubtestTrace> SnovaMalformedKeyState(const SnovaOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup_trace = MakeSubtest("setup", config.oracle_id, "EXPECT_EQUAL");
  SIGKeyPair keypair = SnovaKeygen(config.left, "left", config.seed, "malformed", &setup_trace);
  if (keypair.status != PQCFUZZ_OK || config.left_api == nullptr || config.left_api->keygen_from_sk == nullptr) {
    OracleSubtestTrace failed = MakeSubtest("seed_format_wrong_length_rejected", config.oracle_id, "REJECT_OR_INVALID_INPUT");
    failed.passed = false;
    failed.note = "honest setup failed";
    failed.calls = setup_trace.calls;
    subtests.push_back(std::move(failed));
    return subtests;
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("seed_format_wrong_length_rejected", config.oracle_id, "REJECT_OR_INVALID_INPUT");
    subtest.calls = setup_trace.calls;
    std::vector<uint8_t> pk(config.left->pk_len);
    const pqcfuzz_status status =
        config.left_api->keygen_from_sk(pk.data(), keypair.sk.data(), keypair.sk.size() - 1);
    subtest.passed = status == PQCFUZZ_INVALID_INPUT;
    if (!subtest.passed) {
      subtest.note = "keygen_from_sk accepted a private key with the wrong length";
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("corrupt_expanded_key_graceful", config.oracle_id, "NO_CRASH");
    subtest.calls = setup_trace.calls;
    if (keypair.sk.size() <= 48) {
      MarkNotApplicable(&subtest, "seed-format private key has no expanded matrix section");
    } else {
      std::vector<uint8_t> corrupted = keypair.sk;
      const size_t target = (keypair.sk.size() - 48) / 2;
      corrupted[target] ^= 0xFF;
      std::vector<uint8_t> pk(config.left->pk_len);
      const pqcfuzz_status status = config.left_api->keygen_from_sk(pk.data(), corrupted.data(), corrupted.size());
      const bool graceful = status == PQCFUZZ_INVALID_INPUT || status == PQCFUZZ_OK;
      const bool changed = status != PQCFUZZ_OK || pk != keypair.pk;
      subtest.passed = graceful && changed;
      if (!subtest.passed) {
        subtest.note = "corrupt expanded key produced the honest public key or an unexpected status";
      }
      MutationRecord record;
      record.operation = "xor_byte";
      record.target = "private_key.expanded";
      record.offset = target;
      record.length = 1;
      RecordMutationEffect(&record, keypair.sk, corrupted);
      trace->mutations.push_back(record);
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("zero_public_key_negative", config.oracle_id, "VERIFY_FALSE");
    subtest.calls = setup_trace.calls;
    SIGSignature signature = SnovaSign(config.left, "left", config.message, keypair.sk, config.seed, "malformed-sign", &subtest);
    std::vector<uint8_t> zero_pk(config.left->pk_len, 0);
    if (signature.status != PQCFUZZ_OK) {
      subtest.passed = false;
      subtest.note = "honest signing failed";
    } else {
      SIGVerifyResult verified = SnovaVerify(config.left, "left", signature.sig, config.message, zero_pk, &subtest);
      subtest.passed = RejectionLike(verified.status) || verified.status == PQCFUZZ_API_UNSUPPORTED;
      if (!subtest.passed) {
        subtest.note = "all-zero public key accepted";
      }
    }
    subtests.push_back(std::move(subtest));
  }
  return subtests;
}

// --------------------------------------------------------------------------
// Oracle 157: snova_backend_profile_gate
// --------------------------------------------------------------------------
std::vector<OracleSubtestTrace> SnovaBackendProfileGate(const SnovaOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  {
    OracleSubtestTrace subtest = MakeSubtest("adapter_matches_profile", config.oracle_id, "EXPECT_EQUAL");
    bool ok = config.left != nullptr && config.left_api != nullptr &&
              std::strcmp(config.left_api->backend, config.params.backend) == 0 &&
              config.left->pk_len == config.params.pk_len && config.left->sig_max_len == config.params.sig_max_len &&
              (config.left->sk_len == config.params.ssk_len || config.left->sk_len == config.params.esk_len);
    const bool sk_format_valid =
        config.left_api != nullptr &&
        ((std::strcmp(config.left_api->sk_format, "SSK") == 0 && config.left->sk_len == config.params.ssk_len) ||
         (std::strcmp(config.left_api->sk_format, "ESK") == 0 && config.left->sk_len == config.params.esk_len));
    ok = ok && sk_format_valid;
    subtest.passed = ok;
    if (!ok) {
      subtest.note = "compiled adapter backend/sk format/ABI does not match the SNOVA profile";
      trace->diagnostics.push_back({"harness_error", "profile_gate", subtest.note});
    }
    subtests.push_back(std::move(subtest));
  }
  {
    OracleSubtestTrace subtest = MakeSubtest("right_adapter_matches_left", config.oracle_id, "EXPECT_EQUAL");
    if (config.right == nullptr || config.right_api == nullptr) {
      MarkNotApplicable(&subtest, "no right adapter registered");
    } else {
      const bool same_backend = std::strcmp(config.right_api->backend, config.left_api->backend) == 0;
      const bool same_algorithm = std::strcmp(config.right_api->algorithm, config.left_api->algorithm) == 0;
      subtest.passed = same_backend && same_algorithm;
      if (!subtest.passed) {
        subtest.note = "pair mixes SNOVA backends/algorithms; forward cross-verify is forbidden";
        trace->diagnostics.push_back({"harness_error", "profile_gate", subtest.note});
      }
    }
    subtests.push_back(std::move(subtest));
  }
  return subtests;
}

// --------------------------------------------------------------------------
// Model/opt-in lanes (P1 algebra and P2 lanes)
// --------------------------------------------------------------------------
OracleSubtestTrace SnovaModelLane(const SnovaOracleConfig &config, const std::string &reason) {
  OracleSubtestTrace subtest = MakeSubtest("model_lane", config.oracle_id, "EXPECT_EQUAL");
  MarkNotApplicable(&subtest, reason + "; evaluated by tests/models/snova_model.py");
  return subtest;
}

}  // namespace

KEMOracleTrace ExecuteSnovaOracle(const SnovaOracleConfig &config) {
  KEMOracleTrace trace;
  trace.job_id = config.job_id;
  trace.pair_id = config.pair_id;
  trace.algorithm = config.algorithm;
  trace.oracle_id = config.oracle_id;

  if (config.left == nullptr || config.left_api == nullptr || config.left->sig_max_len == 0 ||
      config.left->pk_len != config.params.pk_len || config.left->sig_max_len != config.params.sig_max_len ||
      (config.left->sk_len != config.params.ssk_len && config.left->sk_len != config.params.esk_len)) {
    trace.diagnostic_event = "harness_error: SNOVA adapter ABI does not match the profile";
    trace.relation_evaluable = false;
    trace.intervention_supported = false;
    trace.intervention_effective = false;
    return trace;
  }
  const bool profile_matches =
      std::strcmp(config.left_api->backend, config.params.backend) == 0 &&
      std::strcmp(config.left->algorithm, config.algorithm.c_str()) == 0;
  if (!profile_matches && config.oracle_id != "snova_backend_profile_gate") {
    trace.diagnostic_event = "harness_error: SNOVA adapter backend/algorithm does not match the profile";
    trace.relation_evaluable = false;
    trace.intervention_supported = false;
    trace.intervention_effective = false;
    return trace;
  }

  const std::string &oracle_id = config.oracle_id;
  trace.controls = {};
  PopulateSnovaControls(oracle_id, &trace);
  if (oracle_id == "snova_kat") {
    trace.subtests.push_back(SnovaKat(config, &trace));
  } else if (oracle_id == "snova_local_sign_verify") {
    for (auto &subtest : SnovaLocalSignVerify(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "snova_cross_verify") {
    trace.subtests.push_back(SnovaCrossVerify(config));
  } else if (oracle_id == "snova_message_salt_binding") {
    for (auto &subtest : SnovaMessageSaltBinding(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "snova_public_seed_binding") {
    for (auto &subtest : SnovaPublicSeedBinding(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "snova_exact_lengths") {
    for (auto &subtest : SnovaExactLengths(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "snova_nibble_encoding") {
    for (auto &subtest : SnovaNibbleEncoding(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "snova_public_map") {
    for (auto &subtest : SnovaPublicMap(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "snova_fixed_abq") {
    for (auto &subtest : SnovaFixedAbq(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "snova_ssk_esk_equivalence") {
    for (auto &subtest : SnovaSskEskEquivalence(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "snova_rng_replay") {
    for (auto &subtest : SnovaRngReplay(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "snova_malformed_key_state") {
    for (auto &subtest : SnovaMalformedKeyState(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "snova_backend_profile_gate") {
    for (auto &subtest : SnovaBackendProfileGate(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "snova_gf16_arithmetic") {
    trace.subtests.push_back(SnovaModelLane(config, "GF16 arithmetic and matrix basis tests"));
    trace.relation_not_applicable = true;
  } else if (oracle_id == "snova_key_alignment") {
    trace.subtests.push_back(SnovaModelLane(config, "T/F/P key-alignment algebra"));
    trace.relation_not_applicable = true;
  } else if (oracle_id == "snova_round2_terms") {
    trace.subtests.push_back(SnovaModelLane(config, "round-2 l^2+l terms and index separation"));
    trace.relation_not_applicable = true;
  } else if (oracle_id == "snova_public_expansion") {
    trace.subtests.push_back(SnovaModelLane(config, "AES-CTR and indexed-SHAKE public expansion"));
    trace.relation_not_applicable = true;
  } else if (oracle_id == "snova_gauss_retry") {
    trace.subtests.push_back(SnovaModelLane(config, "Gaussian solve/retry fixtures"));
    trace.relation_not_applicable = true;
  } else if (oracle_id == "snova_fault_checks") {
    trace.subtests.push_back(SnovaModelLane(config, "opt-in fault-injection lane"));
    trace.relation_not_applicable = true;
  } else if (oracle_id == "snova_timing_resources") {
    trace.subtests.push_back(SnovaModelLane(config, "opt-in timing/resource lane"));
    trace.relation_not_applicable = true;
  } else {
    trace.diagnostic_event = "unknown SNOVA oracle_id";
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
  SetSnovaTraceReachability(&trace);
  AddSnovaFindingsForFailures(config, &trace);
  if (!trace.mutations.empty()) {
    trace.mutation_target = trace.mutations.front().target;
  }
  return trace;
}

}  // namespace pqcfuzz

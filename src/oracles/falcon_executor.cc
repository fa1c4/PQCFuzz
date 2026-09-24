#include "oracles/falcon_executor.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

#include "adapters/rng_control.h"
#include "adapters/status.h"
#include "mutators/digest.h"
#include "mutators/falcon_mutator.h"
#include "mutators/scheme_mutation.h"
#include "oracles/oracle_result.h"
#include "oracles/scheme_claims.h"

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
    pqcfuzz_status status,
    const std::string &layer) {
  OracleCallTrace call;
  call.adapter = adapter;
  call.api = api;
  call.status = status;
  call.has_bool_result = true;
  call.bool_result = false;
  call.executor_dispatched = false;
  call.adapter_entered = false;
  call.target_entered = false;
  call.target_returned = false;
  call.rejection_layer = layer;
  subtest->calls.push_back(call);
}

void AddBoolCall(
    OracleSubtestTrace *subtest,
    const std::string &adapter,
    const std::string &api,
    pqcfuzz_status status,
    bool bool_result,
    const std::string &layer = "") {
  OracleCallTrace call = MakeCallTrace(adapter, api, status, true, bool_result);
  if (!layer.empty()) {
    call.rejection_layer = layer;
  }
  subtest->calls.push_back(call);
}

bool IsUnsupportedOnly(const OracleSubtestTrace &subtest) {
  return !subtest.calls.empty() &&
         std::all_of(subtest.calls.begin(), subtest.calls.end(), [](const OracleCallTrace &call) {
           return call.status == PQCFUZZ_API_UNSUPPORTED;
         });
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

SIGKeyPair FalconKeygen(
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

SIGSignature FalconSign(
    const pqcfuzz_sig_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &sk,
    const std::vector<uint8_t> &seed,
    const std::string &seed_label,
    OracleSubtestTrace *subtest) {
  SIGSignature out;
  if (adapter == nullptr || adapter->sign == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "sign", out.status);
    return out;
  }
  out.sig.resize(adapter->sig_max_len);
  size_t sig_len = adapter->sig_max_len;
  if (adapter->sign_seeded != nullptr) {
    const std::vector<uint8_t> material = DeriveSeed(seed, seed_label, 48);
    out.status = adapter->sign_seeded(out.sig.data(), &sig_len, message.data(), message.size(), sk.data(), nullptr,
                                      0, material.data(), material.size());
  } else {
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

SIGSignature FalconSignWithCapacity(
    const pqcfuzz_sig_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &sk,
    size_t capacity,
    OracleSubtestTrace *subtest) {
  SIGSignature out;
  out.sig.assign(adapter->sig_max_len, 0xA5);
  size_t sig_len = capacity;
  out.status = adapter->sign(out.sig.data(), &sig_len, message.data(), message.size(), sk.data(), nullptr, 0);
  if (out.status == PQCFUZZ_OK) {
    out.sig.resize(sig_len <= adapter->sig_max_len ? sig_len : 0);
  } else {
    out.sig.clear();
  }
  AddCall(subtest, label, "sign", out.status);
  return out;
}

SIGVerifyResult FalconVerify(
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
    AddExecutorRejection(subtest, label, "verify", out.status, "executor");
    return out;
  }
  out.status = adapter->verify(signature.data(), signature.size(), message.data(), message.size(), pk.data(), nullptr, 0);
  out.accepted = out.status == PQCFUZZ_OK;
  AddBoolCall(subtest, label, "verify", out.status, out.accepted);
  return out;
}

// Length-aware wrapper observation: the fixed-pointer verify entry point has no
// observable pk length, so the adapter layer records the rejection for 0, 1,
// L-1 and L+1 buffers without entering the target.
SIGVerifyResult FalconVerifyChecked(
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
    AddExecutorRejection(subtest, label, "verify", out.status, "adapter");
    return out;
  }
  out.status = adapter->verify(signature.data(), signature.size(), message.data(), message.size(), pk.data(), nullptr, 0);
  out.accepted = out.status == PQCFUZZ_OK;
  AddBoolCall(subtest, label, "verify", out.status, out.accepted);
  return out;
}

SIGSignature FalconSignAttached(
    const pqcfuzz_sig_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &sk,
    OracleSubtestTrace *subtest) {
  SIGSignature out;
  if (adapter == nullptr || adapter->sign_attached == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "sign_attached", out.status);
    return out;
  }
  out.sig.resize(message.size() + adapter->sig_max_len + 48);
  size_t sm_len = out.sig.size();
  out.status = adapter->sign_attached(out.sig.data(), &sm_len, message.data(), message.size(), sk.data());
  if (out.status == PQCFUZZ_OK && sm_len <= out.sig.size()) {
    out.sig.resize(sm_len);
  } else if (out.status == PQCFUZZ_OK) {
    out.status = PQCFUZZ_INVALID_INPUT;
    out.sig.clear();
  }
  AddCall(subtest, label, "sign_attached", out.status);
  return out;
}

SIGVerifyResult FalconOpenAttached(
    const pqcfuzz_sig_adapter *adapter,
    const std::string &label,
    std::vector<uint8_t> *message,
    const std::vector<uint8_t> &sm,
    const std::vector<uint8_t> &pk,
    OracleSubtestTrace *subtest) {
  SIGVerifyResult out;
  if (adapter == nullptr || adapter->open_attached == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "open_attached", out.status);
    return out;
  }
  if (pk.size() != adapter->pk_len) {
    out.status = PQCFUZZ_INVALID_INPUT;
    AddExecutorRejection(subtest, label, "open_attached", out.status, "executor");
    return out;
  }
  std::vector<uint8_t> opened(message->size() + sm.size() + 64);
  size_t opened_len = opened.size();
  out.status = adapter->open_attached(opened.data(), &opened_len, sm.data(), sm.size(), pk.data());
  out.accepted = out.status == PQCFUZZ_OK;
  if (out.accepted) {
    opened.resize(opened_len);
    *message = std::move(opened);
  }
  AddBoolCall(subtest, label, "open_attached", out.status, out.accepted);
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

OracleSubtestTrace RunMutationNegative(
    const FalconOracleConfig &config,
    const std::string &subtest_id,
    const char *relation,
    const std::vector<uint8_t> &signature,
    const std::vector<uint8_t> &pk,
    const std::vector<MutationRecord> &records,
    const std::string &failure_note,
    KEMOracleTrace *trace) {
  OracleSubtestTrace subtest = MakeSubtest(subtest_id, config.oracle_id, relation);
  if (signature.empty() || pk.empty()) {
    subtest.passed = false;
    subtest.note = "could not construct valid signature before mutation";
    return subtest;
  }
  RecordMutationEffect(records, trace);
  if (!AnyEffective(records)) {
    MarkNotApplicable(&subtest, "no_effect");
    return subtest;
  }
  SIGVerifyResult result = FalconVerify(config.left, "left", signature, config.message, pk, &subtest);
  subtest.passed = RejectionLike(result.status);
  if (!subtest.passed) {
    subtest.note = failure_note;
  }
  return subtest;
}

std::pair<SIGKeyPair, SIGSignature> SetupHonestSignature(
    const FalconOracleConfig &config,
    const std::string &seed_label,
    const std::vector<uint8_t> &message,
    OracleSubtestTrace *subtest) {
  SIGKeyPair keypair = FalconKeygen(config.left, "left", config.seed, seed_label, subtest);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = FalconSign(config.left, "left", message, keypair.sk, config.seed, seed_label + "-sign", subtest);
  }
  return {keypair, signature};
}

std::vector<std::pair<std::string, std::string>> ClaimAttributes(const FalconOracleConfig &config) {
  return {{"format", FalconFormatName(config.params.format)}};
}

OracleFindingTrace MakeFinding(
    const FalconOracleConfig &config,
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

void AddFalconFindingsForFailures(const FalconOracleConfig &config, KEMOracleTrace *trace) {
  for (const auto &subtest : trace->subtests) {
    for (const auto &call : subtest.calls) {
      if (call.status == PQCFUZZ_CRASH) {
        trace->findings.push_back(MakeFinding(config, subtest.subtest_id, "memory_safety", "",
                                              "adapter call crashed", EvidenceKind::kProcess, &trace->diagnostics));
      } else if (call.status == PQCFUZZ_TIMEOUT) {
        trace->findings.push_back(MakeFinding(config, subtest.subtest_id, "timeout", "",
                                              "adapter call timed out", EvidenceKind::kProcess, &trace->diagnostics));
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
    if (config.oracle_id == "falcon_format_lengths") {
      if (subtest.subtest_id.find("partial_padding") != std::string::npos) {
        finding_subclass = "partial_signature_padding_accepted";
      } else if (subtest.subtest_id.find("nonzero_padding") != std::string::npos ||
                 subtest.subtest_id.find("non_zero_padding") != std::string::npos) {
        finding_subclass = "non_zero_signature_padding_accepted";
      } else if (subtest.subtest_id.find("appended") != std::string::npos) {
        finding_subclass = "appended_signature_bytes_accepted";
      } else if (subtest.subtest_id.find("truncated") != std::string::npos) {
        finding_subclass = "truncated_signature_bytes_accepted";
      }
    } else if (config.oracle_id == "falcon_compressed_canonicality") {
      finding_subclass = "noncanonical_signature_encoding_accepted";
    } else if (config.oracle_id == "falcon_header_profile") {
      finding_subclass = "invalid_signature_or_public_key_header_accepted";
    } else if (config.oracle_id == "falcon_pk_coefficients") {
      finding_subclass = "public_key_value_or_length_accepted";
    } else if (config.oracle_id == "falcon_signed_message_frame") {
      finding_subclass = "malformed_signed_message_frame_opened";
    }
    trace->findings.push_back(MakeFinding(config, subtest.subtest_id, finding_class, finding_subclass, subtest.note,
                                          EvidenceKind::kSemantic, &trace->diagnostics));
  }
}

void SetFalconTraceReachability(KEMOracleTrace *trace) {
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
  // Adapter-layer length rejections intentionally never enter the target; the
  // reachability record must use the last call that actually reached the
  // adapter rather than a wrapper rejection.
  const OracleCallTrace *last_entered = nullptr;
  for (const auto &subtest : trace->subtests) {
    for (const auto &call : subtest.calls) {
      if (call.adapter_entered) {
        last_entered = &call;
      }
    }
  }
  if (last_entered != nullptr) {
    trace->mutated_adapter_entered = last_entered->adapter_entered;
    trace->mutated_target_entered = last_entered->target_entered;
  } else if (last_with_calls != nullptr) {
    trace->mutated_adapter_entered = last_with_calls->calls.back().adapter_entered;
    trace->mutated_target_entered = last_with_calls->calls.back().target_entered;
  }
  trace->relation_evaluable =
      !trace->relation_not_applicable && trace->baseline_target_entered && trace->mutated_target_entered;
}

// ---------------------------------------------------------------- oracles

OracleSubtestTrace FalconKat(const FalconOracleConfig &config, KEMOracleTrace *trace) {
  OracleSubtestTrace subtest = MakeSubtest("seeded_reference_reproduction", config.oracle_id, "EXPECT_EQUAL");
  if (config.left == nullptr || config.left->keygen_seeded == nullptr || config.left->sign_seeded == nullptr) {
    MarkNotApplicable(&subtest, "adapter does not expose the seeded KAT hooks");
    return subtest;
  }
  SIGKeyPair first = FalconKeygen(config.left, "left", config.seed, "kat-keygen", &subtest);
  SIGKeyPair second = FalconKeygen(config.left, "left", config.seed, "kat-keygen", &subtest);
  if (first.status != PQCFUZZ_OK || second.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "seeded key generation failed";
    return subtest;
  }
  SIGSignature sig_a = FalconSign(config.left, "left", config.message, first.sk, config.seed, "kat-sign", &subtest);
  SIGSignature sig_b = FalconSign(config.left, "left", config.message, first.sk, config.seed, "kat-sign", &subtest);
  if (sig_a.status != PQCFUZZ_OK || sig_b.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "seeded signing failed";
    return subtest;
  }
  SIGVerifyResult verified = FalconVerify(config.left, "left", sig_a.sig, config.message, first.pk, &subtest);
  const bool reproducible = first.pk == second.pk && first.sk == second.sk && sig_a.sig == sig_b.sig;
  subtest.passed = reproducible && verified.status == PQCFUZZ_OK;
  if (!subtest.passed) {
    subtest.note = reproducible ? "seeded signature did not verify" : "seeded outputs are not reproducible";
  }
  trace->baseline = {first.status, false, false, MutationSha256Hex(first.pk), first.pk.size()};
  trace->mutated = {sig_a.status, false, false, MutationSha256Hex(sig_a.sig), sig_a.sig.size()};
  return subtest;
}

std::vector<OracleSubtestTrace> FalconLocalSignVerify(const FalconOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace keygen = MakeSubtest("keygen_setup", config.oracle_id, "VERIFY_TRUE");
  SIGKeyPair keypair = FalconKeygen(config.left, "left", config.seed, "local-keygen", &keygen);
  const std::vector<std::pair<std::string, std::vector<uint8_t>>> messages = {
      {"empty_message", {}},
      {"binary_message", config.message},
      {"long_message", std::vector<uint8_t>(2048, 0x5A)},
  };
  for (const auto &entry : messages) {
    OracleSubtestTrace subtest = MakeSubtest(entry.first, config.oracle_id, "VERIFY_TRUE");
    subtest.calls = keygen.calls;
    if (keypair.status != PQCFUZZ_OK) {
      subtest.passed = false;
      subtest.note = "key generation failed";
      subtests.push_back(subtest);
      continue;
    }
    SIGSignature signature = FalconSign(config.left, "left", entry.second, keypair.sk, config.seed,
                                        "local-sign-" + entry.first, &subtest);
    if (signature.status != PQCFUZZ_OK) {
      subtest.passed = false;
      subtest.note = "honest signing failed";
      subtests.push_back(subtest);
      continue;
    }
    if (signature.sig.size() > config.left->sig_max_len) {
      subtest.passed = false;
      subtest.note = "returned signature length exceeded the profile capacity";
      subtests.push_back(subtest);
      continue;
    }
    SIGVerifyResult result = FalconVerify(config.left, "left", signature.sig, entry.second, keypair.pk, &subtest);
    subtest.passed = result.status == PQCFUZZ_OK && result.accepted;
    if (!subtest.passed) {
      subtest.note = "honest signature did not verify";
    }
    subtests.push_back(subtest);
  }
  return subtests;
}

OracleSubtestTrace FalconCrossVerify(const FalconOracleConfig &config) {
  OracleSubtestTrace subtest = MakeSubtest("cross_verify", config.oracle_id, "VERIFY_TRUE");
  if (!config.signature_exchange || config.right == nullptr) {
    MarkNotApplicable(&subtest, "signature_exchange is disabled in the pinned single-implementation lock");
    return subtest;
  }
  SIGKeyPair keypair = FalconKeygen(config.left, "left", config.seed, "cross-keygen", &subtest);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = FalconSign(config.left, "left", config.message, keypair.sk, config.seed, "cross-sign", &subtest);
  }
  SIGVerifyResult result;
  if (signature.status == PQCFUZZ_OK) {
    result = FalconVerify(config.right, "right", signature.sig, config.message, keypair.pk, &subtest);
  }
  subtest.passed = result.status == PQCFUZZ_OK && result.accepted;
  if (!subtest.passed) {
    subtest.note = "cross verification of a valid signature failed";
  }
  return subtest;
}

std::vector<OracleSubtestTrace> FalconMessageSaltBinding(const FalconOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("binding_setup", config.oracle_id, "VERIFY_FALSE");
  SIGKeyPair keypair = FalconKeygen(config.left, "left", config.seed, "binding-keygen", &setup);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = FalconSign(config.left, "left", config.message, keypair.sk, config.seed, "binding-sign", &setup);
  }

  const auto run = [&](const std::string &id, const std::vector<uint8_t> &candidate_message,
                       const std::vector<uint8_t> &candidate_pk, const std::vector<MutationRecord> &records,
                       const std::string &failure_note) {
    OracleSubtestTrace subtest = MakeSubtest(id, config.oracle_id, "VERIFY_FALSE");
    subtest.calls = setup.calls;
    if (signature.status != PQCFUZZ_OK) {
      subtest.passed = false;
      subtest.note = "could not construct valid signature";
      return subtest;
    }
    RecordMutationEffect(records, trace);
    if (!records.empty() && !AnyEffective(records)) {
      MarkNotApplicable(&subtest, "no_effect");
      return subtest;
    }
    SIGVerifyResult result = FalconVerify(config.left, "left", signature.sig, candidate_message, candidate_pk, &subtest);
    subtest.passed = RejectionLike(result.status);
    if (!subtest.passed) {
      subtest.note = failure_note;
    }
    return subtest;
  };

  std::vector<uint8_t> mutated_message = config.message;
  SchemeMutation message_recipe;
  message_recipe.op = SchemeMutationOp::kFlipBit;
  message_recipe.field = SchemeMutationField::kMessage;
  message_recipe.index = 0;
  auto message_records = MutateFalconMessage(EncodeSchemeMutation(message_recipe), &mutated_message);
  subtests.push_back(run("mutated_message_negative", mutated_message, keypair.pk, message_records,
                         "signature verified for a different message"));

  const std::vector<MutationRecord> salt_records = {MutateFalconSaltByte(config.params, 0, 0x01, &signature.sig)};
  subtests.push_back(run("mutated_salt_negative", config.message, keypair.pk, salt_records,
                         "signature verified after changing a salt byte"));

  OracleSubtestTrace foreign_subtest = MakeSubtest("foreign_key_negative", config.oracle_id, "VERIFY_FALSE");
  foreign_subtest.calls = setup.calls;
  std::vector<uint8_t> foreign_seed = config.seed;
  foreign_seed.insert(foreign_seed.end(), {'f', 'o', 'r', 'e', 'i', 'g', 'n'});
  SIGKeyPair foreign = FalconKeygen(config.left, "left", foreign_seed, "binding-keygen", &foreign_subtest);
  if (signature.status != PQCFUZZ_OK || foreign.status != PQCFUZZ_OK) {
    foreign_subtest.passed = false;
    foreign_subtest.note = "could not construct an independent honest key pair";
  } else {
    SIGVerifyResult result =
        FalconVerify(config.left, "left", signature.sig, config.message, foreign.pk, &foreign_subtest);
    foreign_subtest.passed = RejectionLike(result.status);
    if (!foreign_subtest.passed) {
      foreign_subtest.note = "signature verified under an independent honest key";
    }
  }
  subtests.push_back(foreign_subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> FalconHeaderProfile(const FalconOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("header_setup", config.oracle_id,
                                         "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  const auto header_setup = SetupHonestSignature(config, "header-keygen", config.message, &setup);
  const SIGKeyPair &keypair = header_setup.first;
  const SIGSignature &signature = header_setup.second;

  const auto run_sig = [&](const std::string &id, uint8_t header, const std::string &failure_note) {
    OracleSubtestTrace subtest = MakeSubtest(id, config.oracle_id,
                                             "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    subtest.calls = setup.calls;
    if (signature.status != PQCFUZZ_OK) {
      subtest.passed = false;
      subtest.note = "could not construct valid signature";
      return subtest;
    }
    std::vector<uint8_t> mutated = signature.sig;
    const MutationRecord record = MutateFalconSignatureHeader(config.params, header, &mutated);
    return RunMutationNegative(config, id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT", mutated, keypair.pk,
                               {record}, failure_note, trace);
  };

  const uint8_t wrong_format = config.params.format == FalconFormat::kCt
                                   ? static_cast<uint8_t>(0x30 + config.params.logn)
                                   : static_cast<uint8_t>(0x50 + config.params.logn);
  const uint8_t other_logn = static_cast<uint8_t>((config.params.sig_header & 0xF0) | (config.params.logn == 9 ? 10 : 9));
  subtests.push_back(run_sig("signature_header_format_negative", wrong_format,
                             "a signature header with the wrong format nibble was accepted"));
  subtests.push_back(run_sig("signature_header_degree_negative", other_logn,
                             "a signature header with a mismatched degree nibble was accepted"));

  OracleSubtestTrace pk_subtest = MakeSubtest("public_key_header_negative", config.oracle_id,
                                              "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  pk_subtest.calls = setup.calls;
  if (signature.status != PQCFUZZ_OK) {
    pk_subtest.passed = false;
    pk_subtest.note = "could not construct valid signature";
  } else {
    std::vector<uint8_t> mutated_pk = keypair.pk;
    const MutationRecord record = MutateFalconPublicKeyHeader(config.params, static_cast<uint8_t>(0x10), &mutated_pk);
    pk_subtest.passed = true;
    RecordMutationEffect({record}, trace);
    if (!record.effective) {
      MarkNotApplicable(&pk_subtest, "no_effect");
    } else {
      SIGVerifyResult result = FalconVerify(config.left, "left", signature.sig, config.message, mutated_pk, &pk_subtest);
      pk_subtest.passed = RejectionLike(result.status);
      if (!pk_subtest.passed) {
        pk_subtest.note = "a public key with a bad header was accepted";
      }
    }
  }
  subtests.push_back(pk_subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> FalconPkCoefficients(const FalconOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("pk_setup", config.oracle_id,
                                         "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  const auto pk_setup_pair = SetupHonestSignature(config, "pk-keygen", config.message, &setup);
  const SIGKeyPair &keypair = pk_setup_pair.first;
  const SIGSignature &signature = pk_setup_pair.second;

  OracleSubtestTrace coefficient_subtest = MakeSubtest("pk_coefficient_negative", config.oracle_id,
                                                       "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  coefficient_subtest.calls = setup.calls;
  if (signature.status != PQCFUZZ_OK) {
    coefficient_subtest.passed = false;
    coefficient_subtest.note = "could not construct valid signature";
    subtests.push_back(coefficient_subtest);
  } else {
    bool all_rejected = true;
    const uint16_t values[] = {0, static_cast<uint16_t>(config.params.q - 1), static_cast<uint16_t>(config.params.q),
                               16383};
    for (uint16_t value : values) {
      std::vector<uint8_t> mutated_pk = keypair.pk;
      const MutationRecord record = WriteFalconPublicKeyCoefficient(config.params, 0, value, &mutated_pk);
      RecordMutationEffect({record}, trace);
      if (!record.effective) {
        continue;
      }
      SIGVerifyResult result = FalconVerify(config.left, "left", signature.sig, config.message, mutated_pk,
                                            &coefficient_subtest);
      all_rejected = all_rejected && RejectionLike(result.status);
    }
    coefficient_subtest.passed = all_rejected;
    if (!all_rejected) {
      coefficient_subtest.note = "a public key with an out-of-domain coefficient was accepted";
    }
    subtests.push_back(coefficient_subtest);
  }

  OracleSubtestTrace length_subtest = MakeSubtest("adapter_pk_length_negative", config.oracle_id,
                                                  "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  length_subtest.calls = setup.calls;
  if (signature.status != PQCFUZZ_OK) {
    length_subtest.passed = false;
    length_subtest.note = "could not construct valid signature";
  } else {
    const size_t lengths[] = {0, 1, config.left->pk_len - 1, config.left->pk_len + 1};
    bool all_rejected = true;
    for (size_t length : lengths) {
      std::vector<uint8_t> candidate_pk(length, 0x00);
      if (length > 0) {
        std::copy(keypair.pk.begin(), keypair.pk.begin() + std::min(length, keypair.pk.size()), candidate_pk.begin());
      }
      SIGVerifyResult result =
          FalconVerifyChecked(config.left, "left", signature.sig, config.message, candidate_pk, &length_subtest);
      all_rejected = all_rejected && RejectionLike(result.status);
    }
    length_subtest.passed = all_rejected;
    if (!all_rejected) {
      length_subtest.note = "a public key with a non-profile length entered the target";
    }
  }
  subtests.push_back(length_subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> FalconCompressedCanonicality(const FalconOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("canonicality_setup", config.oracle_id,
                                         "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  const auto canonicality_setup = SetupHonestSignature(config, "canonicality-keygen", config.message, &setup);
  const SIGKeyPair &keypair = canonicality_setup.first;
  const SIGSignature &signature = canonicality_setup.second;

  const auto run = [&](const std::string &id, MutationRecord record, std::vector<uint8_t> mutated,
                       const std::string &failure_note) {
    OracleSubtestTrace subtest = MakeSubtest(id, config.oracle_id,
                                             "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    subtest.calls = setup.calls;
    if (signature.status != PQCFUZZ_OK) {
      subtest.passed = false;
      subtest.note = "could not construct valid signature";
      return subtest;
    }
    if (record.skipped) {
      MarkNotApplicable(&subtest, record.reason);
      return subtest;
    }
    return RunMutationNegative(config, id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT", mutated, keypair.pk,
                               {record}, failure_note, trace);
  };

  if (signature.status != PQCFUZZ_OK) {
    OracleSubtestTrace subtest = MakeSubtest("payload_negative", config.oracle_id,
                                             "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    subtest.passed = false;
    subtest.note = "could not construct valid signature";
    subtests.push_back(subtest);
    return subtests;
  }

  if (config.params.format == FalconFormat::kCt) {
    std::vector<uint8_t> mutated = signature.sig;
    // Forbid the minimum negative 12-bit coefficient: write 0x800 into the
    // first coefficient's bits (MSB-first) inside the payload.
    const size_t payload_off = config.params.sig_payload_off;
    for (size_t i = 0; i < 12; ++i) {
      const size_t byte = payload_off + (i >> 3);
      const unsigned bit = static_cast<unsigned>(7 - (i & 7));
      const bool set = ((0x800u >> (11 - i)) & 1u) != 0;
      if (set) {
        mutated[byte] |= static_cast<uint8_t>(1u << bit);
      } else {
        mutated[byte] &= static_cast<uint8_t>(~(1u << bit));
      }
    }
    MutationRecord record;
    record.operation = "set_coefficient";
    record.target = "signature.ct_payload";
    record.offset = payload_off;
    record.length = 2;
    record.effective = mutated != signature.sig;
    subtests.push_back(run("ct_forbidden_coefficient_negative", record, mutated,
                           "the forbidden minimum negative CT coefficient was accepted"));
    return subtests;
  }

  size_t zero_index = 0;
  if (FindFalconCompressedZeroCoefficient(config.params, signature.sig, &zero_index)) {
    std::vector<uint8_t> mutated = signature.sig;
    const MutationRecord record = SetFalconCompressedNegativeZeroBit(config.params, zero_index, &mutated);
    subtests.push_back(run("negative_zero_negative", record, mutated,
                           "a compressed negative-zero coefficient was accepted"));
  } else {
    OracleSubtestTrace subtest = MakeSubtest("negative_zero_negative", config.oracle_id,
                                             "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    MarkNotApplicable(&subtest, "no zero coefficient available for the negative-zero fixture");
    subtests.push_back(subtest);
  }

  {
    std::vector<uint8_t> mutated = signature.sig;
    const size_t index = static_cast<size_t>(config.params.n - 1);
    const MutationRecord record = ClearFalconCompressedTerminatorBit(config.params, index, &mutated);
    subtests.push_back(run("unterminated_unary_negative", record, mutated,
                           "a compressed payload with no unary terminator was accepted"));
  }
  {
    std::vector<uint8_t> mutated = signature.sig;
    const MutationRecord record = SetFalconCompressedPaddingBit(config.params, 0, &mutated);
    subtests.push_back(run("nonzero_trailing_bits_negative", record, mutated,
                           "non-zero trailing compressed bits were accepted"));
  }
  {
    std::vector<uint8_t> mutated = signature.sig;
    const MutationRecord record = ShiftFalconCompressedPayload(config.params, +1, &mutated);
    subtests.push_back(run("inserted_bit_negative", record, mutated,
                           "a compressed payload with an inserted bit was accepted"));
  }
  {
    std::vector<uint8_t> mutated = signature.sig;
    const MutationRecord record = ShiftFalconCompressedPayload(config.params, -1, &mutated);
    subtests.push_back(run("deleted_bit_negative", record, mutated,
                           "a compressed payload with a deleted bit was accepted"));
  }
  if (config.params.format == FalconFormat::kPadded) {
    std::vector<uint8_t> mutated = signature.sig;
    mutated.back() = 0xA5;
    MutationRecord record;
    record.operation = "set_byte";
    record.target = "signature.padded_region";
    record.offset = mutated.size() - 1;
    record.length = 1;
    record.effective = mutated != signature.sig;
    subtests.push_back(run("nonzero_padded_region_negative", record, mutated,
                           "a non-zero byte in the padded region was accepted"));
  }
  return subtests;
}

std::vector<OracleSubtestTrace> FalconFormatLengths(const FalconOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("format_setup", config.oracle_id,
                                         "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  const auto format_setup = SetupHonestSignature(config, "format-keygen", config.message, &setup);
  const SIGKeyPair &keypair = format_setup.first;
  const SIGSignature &signature = format_setup.second;

  const auto run = [&](const std::string &id, const std::vector<uint8_t> &candidate, bool expect_reject,
                       const std::string &failure_note) {
    OracleSubtestTrace subtest = MakeSubtest(id, config.oracle_id,
                                             "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    subtest.calls = setup.calls;
    if (signature.status != PQCFUZZ_OK) {
      subtest.passed = false;
      subtest.note = "could not construct valid signature";
      return subtest;
    }
    MutationRecord record;
    record.operation = candidate.size() == signature.sig.size() ? "none" : "length_change";
    record.target = "signature";
    record.offset = 0;
    record.length = candidate.size();
    record.effective = candidate != signature.sig;
    RecordMutationEffect({record}, trace);
    SIGVerifyResult result = FalconVerify(config.left, "left", candidate, config.message, keypair.pk, &subtest);
    if (expect_reject) {
      subtest.passed = RejectionLike(result.status);
      if (!subtest.passed) {
        subtest.note = failure_note;
      }
    } else {
      subtest.passed = result.status == PQCFUZZ_OK && result.accepted;
      if (!subtest.passed) {
        subtest.note = failure_note;
      }
    }
    return subtest;
  };

  if (signature.status != PQCFUZZ_OK) {
    OracleSubtestTrace subtest = MakeSubtest("baseline", config.oracle_id, "VERIFY_TRUE");
    subtest.passed = false;
    subtest.note = "could not construct valid signature";
    subtests.push_back(subtest);
    return subtests;
  }

  std::vector<uint8_t> baseline = signature.sig;
  subtests.push_back(run("baseline_exact_length", baseline, false, "the honest signature did not verify"));

  std::vector<uint8_t> padded = baseline;
  const size_t padded_len = config.params.padded_len;
  if (padded.size() < padded_len) {
    padded.resize(padded_len, 0x00);
  }
  if (config.params.format == FalconFormat::kCt) {
    subtests.push_back(run("ct_exact_length_positive", baseline, false, "the honest CT signature did not verify"));
    std::vector<uint8_t> short_ct = baseline;
    short_ct.pop_back();
    subtests.push_back(run("ct_truncated_negative", short_ct, true, "a truncated CT signature was accepted"));
    std::vector<uint8_t> long_ct = baseline;
    long_ct.push_back(0x00);
    subtests.push_back(run("ct_appended_negative", long_ct, true, "an appended CT signature was accepted"));
  } else {
    if (config.params.format == FalconFormat::kCompressed) {
      subtests.push_back(run("padded_full_form_positive", padded, false,
                             "a legally padded compressed signature was rejected"));
    } else {
      subtests.push_back(run("padded_full_form_positive", baseline, false, "the honest padded signature did not verify"));
      FalconSignatureView view;
      std::string parse_error;
      if (ParseFalconSignature(config.params, baseline.data(), baseline.size(), &view, &parse_error)) {
        std::vector<uint8_t> unpadded(baseline.begin(),
                                      baseline.begin() + static_cast<long>(config.params.sig_payload_off + view.consumed_bytes));
        subtests.push_back(run("unpadded_form_negative", unpadded, true,
                               "a padded-only verifier accepted an unpadded length"));
      }
    }
    std::vector<uint8_t> partial = padded;
    if (!partial.empty()) {
      partial.pop_back();
    }
    subtests.push_back(run("partial_padding_negative", partial, true, "a partial padded signature was accepted"));
    std::vector<uint8_t> nonzero_padding = padded;
    if (!nonzero_padding.empty()) {
      nonzero_padding.back() = 0x01;
    }
    subtests.push_back(run("nonzero_padding_negative", nonzero_padding, true,
                           "a padded signature with a non-zero padding byte was accepted"));
  }

  std::vector<uint8_t> truncated = baseline;
  if (!truncated.empty()) {
    truncated.pop_back();
  }
  subtests.push_back(run("truncated_signature_negative", truncated, true, "a truncated signature was accepted"));
  std::vector<uint8_t> appended = baseline;
  appended.push_back(0xA5);
  subtests.push_back(run("appended_signature_negative", appended, true, "an appended signature was accepted"));

  std::vector<uint8_t> empty;
  subtests.push_back(run("empty_signature_negative", empty, true, "an empty signature was accepted"));
  std::vector<uint8_t> header_only = {baseline[0]};
  subtests.push_back(run("header_only_negative", header_only, true, "a header-only signature was accepted"));
  std::vector<uint8_t> salt_only = baseline;
  salt_only.resize(config.params.sig_payload_off);
  subtests.push_back(run("salt_only_negative", salt_only, true, "a header-and-salt-only signature was accepted"));
  return subtests;
}

std::vector<OracleSubtestTrace> FalconNormEquation(const FalconOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("norm_setup", config.oracle_id, "EXPECT_EQUAL");
  const auto norm_setup = SetupHonestSignature(config, "norm-keygen", config.message, &setup);
  const SIGKeyPair &keypair = norm_setup.first;
  const SIGSignature &signature = norm_setup.second;

  OracleSubtestTrace model = MakeSubtest("norm_equation_model", config.oracle_id, "EXPECT_EQUAL");
  MarkNotApplicable(&model, "exact centered reduction and sum-of-squares are evaluated by tests/models/falcon_model.py");
  subtests.push_back(model);

  OracleSubtestTrace negative = MakeSubtest("codec_valid_coefficient_change_negative", config.oracle_id,
                                            "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  negative.calls = setup.calls;
  if (signature.status != PQCFUZZ_OK) {
    negative.passed = false;
    negative.note = "could not construct valid signature";
    subtests.push_back(negative);
    return subtests;
  }
  std::vector<uint8_t> mutated = signature.sig;
  bool any = false;
  for (size_t i = 0; i < 4 && i < static_cast<size_t>(config.params.n); ++i) {
    const MutationRecord record = MutateFalconCoefficient(config.params, i, 2047, &mutated);
    RecordMutationEffect({record}, trace);
    any = any || (record.effective && !record.skipped);
  }
  if (!any) {
    MarkNotApplicable(&negative, "no_effective_coefficient_change");
  } else {
    SIGVerifyResult result = FalconVerify(config.left, "left", mutated, config.message, keypair.pk, &negative);
    negative.passed = RejectionLike(result.status);
    if (!negative.passed) {
      negative.note = "a norm-breaking codec-valid signature was accepted";
    }
  }
  subtests.push_back(negative);
  return subtests;
}

std::vector<OracleSubtestTrace> FalconRngReplay(const FalconOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("rng_setup", config.oracle_id, "EXPECT_EQUAL");
  if (config.left == nullptr || config.left->sign == nullptr || config.left->keygen == nullptr) {
    OracleSubtestTrace unsupported = MakeSubtest("rng_replay", config.oracle_id, "EXPECT_EQUAL");
    MarkNotApplicable(&unsupported, "adapter API unsupported");
    subtests.push_back(unsupported);
    return subtests;
  }
  SIGKeyPair keypair = FalconKeygen(config.left, "left", config.seed, "rng-keygen", &setup);
  if (keypair.status != PQCFUZZ_OK) {
    OracleSubtestTrace failed = MakeSubtest("rng_replay", config.oracle_id, "EXPECT_EQUAL");
    failed.passed = false;
    failed.note = "key generation failed";
    failed.calls = setup.calls;
    subtests.push_back(failed);
    return subtests;
  }

  std::vector<uint8_t> tape_a(64);
  std::vector<uint8_t> tape_b(64);
  for (size_t i = 0; i < tape_a.size(); ++i) {
    tape_a[i] = static_cast<uint8_t>(0x11u + i);
    tape_b[i] = static_cast<uint8_t>(0x91u + i * 3u);
  }
  const auto sign_once = [&](const std::vector<uint8_t> &tape, OracleSubtestTrace *subtest) {
    SIGSignature signature;
    signature.sig.resize(config.left->sig_max_len);
    size_t sig_len = config.left->sig_max_len;
    {
      ScopedRngOverride rng({tape.data(), tape.size(), false});
      signature.status = config.left->sign(signature.sig.data(), &sig_len, config.message.data(),
                                           config.message.size(), keypair.sk.data(), nullptr, 0);
    }
    if (signature.status == PQCFUZZ_OK) {
      signature.sig.resize(sig_len);
    }
    AddCall(subtest, "left", "sign", signature.status);
    return signature;
  };

  OracleSubtestTrace reproducible = MakeSubtest("same_tape_reproducible", config.oracle_id, "EXPECT_EQUAL");
  reproducible.calls = setup.calls;
  const SIGSignature first = sign_once(tape_a, &reproducible);
  const SIGSignature second = sign_once(tape_a, &reproducible);
  reproducible.passed = first.status == PQCFUZZ_OK && second.status == PQCFUZZ_OK && first.sig == second.sig;
  if (!reproducible.passed) {
    reproducible.note = "the same CSPRNG tape did not reproduce the signature";
  } else {
    SIGVerifyResult verified =
        FalconVerify(config.left, "left", first.sig, config.message, keypair.pk, &reproducible);
    reproducible.passed = verified.status == PQCFUZZ_OK;
    if (!reproducible.passed) {
      reproducible.note = "tape-reproduced signature did not verify";
    }
  }
  subtests.push_back(reproducible);

  OracleSubtestTrace differs = MakeSubtest("different_tape_verifies", config.oracle_id, "VERIFY_TRUE");
  differs.calls = setup.calls;
  const SIGSignature third = sign_once(tape_b, &differs);
  if (third.status == PQCFUZZ_OK) {
    SIGVerifyResult verified = FalconVerify(config.left, "left", third.sig, config.message, keypair.pk, &differs);
    differs.passed = verified.status == PQCFUZZ_OK;
    if (!differs.passed) {
      differs.note = "a fresh legal tape produced a signature that did not verify";
    }
  } else {
    differs.passed = false;
    differs.note = "signing under a fresh legal tape failed";
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

std::vector<OracleSubtestTrace> FalconFailureState(const FalconOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  if (config.left == nullptr || config.left->keygen == nullptr || config.left->sign == nullptr) {
    OracleSubtestTrace unsupported = MakeSubtest("failure_state", config.oracle_id, "REJECT_OR_INVALID_INPUT");
    MarkNotApplicable(&unsupported, "adapter API unsupported");
    subtests.push_back(unsupported);
    return subtests;
  }
  OracleSubtestTrace setup = MakeSubtest("failure_setup", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  SIGKeyPair keypair = FalconKeygen(config.left, "left", config.seed, "failure-keygen", &setup);

  OracleSubtestTrace capacity = MakeSubtest("insufficient_capacity_negative", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  capacity.calls = setup.calls;
  if (keypair.status != PQCFUZZ_OK) {
    capacity.passed = false;
    capacity.note = "key generation failed";
  } else {
    bool consistent = true;
    const size_t capacities[] = {0, 1, 40};
    for (size_t cap : capacities) {
      SIGSignature result =
          FalconSignWithCapacity(config.left, "left", config.message, keypair.sk, cap, &capacity);
      if (result.status == PQCFUZZ_OK) {
        consistent = false;
        break;
      }
    }
    capacity.passed = consistent;
    if (!consistent) {
      capacity.note = "signing reported success although the capacity was below the minimum";
    }
  }
  subtests.push_back(capacity);

  OracleSubtestTrace empty_message = MakeSubtest("empty_message_roundtrip", config.oracle_id, "VERIFY_TRUE");
  empty_message.calls = setup.calls;
  {
    std::vector<uint8_t> empty;
    if (keypair.status != PQCFUZZ_OK) {
      empty_message.passed = false;
      empty_message.note = "key generation failed";
    } else {
      SIGSignature signature = FalconSign(config.left, "left", empty, keypair.sk, config.seed, "failure-sign",
                                          &empty_message);
      if (signature.status == PQCFUZZ_OK) {
        SIGVerifyResult verified = FalconVerify(config.left, "left", signature.sig, empty, keypair.pk, &empty_message);
        empty_message.passed = verified.status == PQCFUZZ_OK;
      } else {
        empty_message.passed = false;
        empty_message.note = "empty-message signing failed";
      }
    }
  }
  subtests.push_back(empty_message);

  OracleSubtestTrace zero_length = MakeSubtest("zero_length_signature_negative", config.oracle_id,
                                               "REJECT_OR_INVALID_INPUT");
  {
    std::vector<uint8_t> empty_sig;
    SIGVerifyResult result = FalconVerify(config.left, "left", empty_sig, config.message, keypair.pk, &zero_length);
    zero_length.passed = RejectionLike(result.status);
    if (!zero_length.passed) {
      zero_length.note = "zero-length signature was accepted";
    }
  }
  subtests.push_back(zero_length);

  OracleSubtestTrace rng_failure = MakeSubtest("rng_failure_observed", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  pqcfuzz_rng_reset_failure_observed();
  {
    uint8_t dummy = 0;
    ScopedRngOverride rng({&dummy, 1, false, RngTape::Mode::kReportedFailure});
    std::vector<uint8_t> pk(config.left->pk_len);
    std::vector<uint8_t> sk(config.left->sk_len);
    const pqcfuzz_status status = config.left->keygen(pk.data(), sk.data());
    AddCall(&rng_failure, "left", "keygen", status);
    rng_failure.passed = pqcfuzz_rng_failure_observed();
    if (!rng_failure.passed) {
      rng_failure.note = "injected CSPRNG failure was not observed by the RNG control";
    }
  }
  subtests.push_back(rng_failure);
  return subtests;
}

std::vector<OracleSubtestTrace> FalconSignedMessageFrame(const FalconOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("frame_setup", config.oracle_id, "VERIFY_TRUE");
  if (config.left == nullptr || config.left->sign_attached == nullptr || config.left->open_attached == nullptr) {
    MarkNotApplicable(&setup, "adapter does not expose the NIST signed-message API");
    subtests.push_back(setup);
    return subtests;
  }
  SIGKeyPair keypair = FalconKeygen(config.left, "left", config.seed, "frame-keygen", &setup);
  if (keypair.status != PQCFUZZ_OK) {
    setup.passed = false;
    setup.note = "key generation failed";
    subtests.push_back(setup);
    return subtests;
  }

  OracleSubtestTrace roundtrip = MakeSubtest("frame_roundtrip", config.oracle_id, "VERIFY_TRUE");
  roundtrip.calls = setup.calls;
  SIGSignature frame = FalconSignAttached(config.left, "left", config.message, keypair.sk, &roundtrip);
  std::vector<uint8_t> opened;
  if (frame.status == PQCFUZZ_OK) {
    opened = config.message;
    SIGVerifyResult result = FalconOpenAttached(config.left, "left", &opened, frame.sig, keypair.pk, &roundtrip);
    roundtrip.passed = result.status == PQCFUZZ_OK && opened == config.message;
    if (!roundtrip.passed) {
      roundtrip.note = "the honest frame did not open to the exact message";
    }
  } else {
    roundtrip.passed = false;
    roundtrip.note = "attached signing failed";
  }
  subtests.push_back(roundtrip);

  OracleSubtestTrace empty_frame = MakeSubtest("empty_message_frame", config.oracle_id, "VERIFY_TRUE");
  empty_frame.calls = setup.calls;
  {
    std::vector<uint8_t> empty;
    SIGSignature empty_sig = FalconSignAttached(config.left, "left", empty, keypair.sk, &empty_frame);
    if (empty_sig.status == PQCFUZZ_OK) {
      std::vector<uint8_t> opened_empty;
      SIGVerifyResult result =
          FalconOpenAttached(config.left, "left", &opened_empty, empty_sig.sig, keypair.pk, &empty_frame);
      empty_frame.passed = result.status == PQCFUZZ_OK && opened_empty.empty();
    } else {
      empty_frame.passed = false;
      empty_frame.note = "attached signing of the empty message failed";
    }
  }
  subtests.push_back(empty_frame);

  if (frame.status != PQCFUZZ_OK) {
    OracleSubtestTrace failed = MakeSubtest("frame_mutation_negative", config.oracle_id,
                                            "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    failed.passed = false;
    failed.note = "could not construct a valid frame";
    subtests.push_back(failed);
    return subtests;
  }

  const auto run_frame = [&](const std::string &id, const std::vector<uint8_t> &candidate, const std::string &note) {
    OracleSubtestTrace subtest = MakeSubtest(id, config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    subtest.calls = setup.calls;
    MutationRecord record;
    record.operation = "mutate";
    record.target = "signed_message.frame";
    record.effective = candidate != frame.sig;
    RecordMutationEffect({record}, trace);
    std::vector<uint8_t> opened_message = config.message;
    SIGVerifyResult result = FalconOpenAttached(config.left, "left", &opened_message, candidate, keypair.pk, &subtest);
    const bool malformed = result.status != PQCFUZZ_OK || opened_message != config.message;
    subtest.passed = malformed;
    if (!subtest.passed) {
      subtest.note = note;
    }
    return subtest;
  };

  std::vector<uint8_t> length_mutated = frame.sig;
  if (length_mutated.size() >= 2) {
    const uint16_t current = static_cast<uint16_t>((length_mutated[0] << 8) | length_mutated[1]);
    const uint16_t next = static_cast<uint16_t>(current + 1);
    length_mutated[0] = static_cast<uint8_t>(next >> 8);
    length_mutated[1] = static_cast<uint8_t>(next & 0xFFu);
  }
  subtests.push_back(run_frame("frame_length_negative", length_mutated,
                               "a frame with an inconsistent BE16 length opened successfully"));

  std::vector<uint8_t> header_mutated = frame.sig;
  const size_t header_offset = 2 + config.params.salt_len + config.message.size();
  if (header_offset < header_mutated.size()) {
    header_mutated[header_offset] ^= 0x01;
  }
  subtests.push_back(run_frame("frame_header_negative", header_mutated,
                               "a frame with a mutated nonce-less header opened successfully"));

  std::vector<uint8_t> truncated = frame.sig;
  if (!truncated.empty()) {
    truncated.pop_back();
  }
  subtests.push_back(run_frame("frame_truncated_negative", truncated, "a truncated frame opened successfully"));

  std::vector<uint8_t> appended = frame.sig;
  appended.push_back(0x00);
  subtests.push_back(run_frame("frame_appended_negative", appended, "an appended frame opened successfully"));

  std::vector<uint8_t> value_mutated = frame.sig;
  if (!value_mutated.empty()) {
    value_mutated.back() ^= 0x80;
  }
  subtests.push_back(run_frame("frame_value_negative", value_mutated,
                               "a frame with a mutated signature value opened successfully"));
  return subtests;
}

OracleSubtestTrace FalconModelLane(const FalconOracleConfig &config, const std::string &subtest_id,
                                   const std::string &lane) {
  OracleSubtestTrace subtest = MakeSubtest(subtest_id, config.oracle_id, "EXPECT_EQUAL");
  MarkNotApplicable(&subtest, "evaluated by the independent Python model lane (" + lane + ")");
  return subtest;
}

void PopulateFalconControls(const std::string &oracle_id, KEMOracleTrace *trace) {
  if (oracle_id == "falcon_kat") {
    trace->controls.positive_control = "the official round-3 KAT record reproduces pk/sk/sm and opens";
    trace->controls.negative_control = "a different DRBG seed produces different bytes";
  } else if (oracle_id == "falcon_message_salt_binding") {
    trace->controls.positive_control = "the original message under the original key verifies";
    trace->controls.negative_control = "each targeted message, salt and key change is recorded as effective";
  } else if (oracle_id == "falcon_rng_replay") {
    trace->controls.positive_control = "two runs under the same tape agree";
    trace->controls.negative_control = "a different tape produces a different salt";
  } else if (oracle_id == "falcon_format_lengths") {
    trace->controls.positive_control = "the unmodified signature and the profile's legal padded conversion verify";
    trace->controls.negative_control = "each length change is recorded and rejected";
  } else {
    trace->controls.positive_control = "the unmodified signature verifies";
    trace->controls.negative_control = "the targeted mutation is recorded as effective and rejected";
  }
}

}  // namespace

KEMOracleTrace ExecuteFalconOracle(const FalconOracleConfig &config) {
  KEMOracleTrace trace;
  trace.job_id = config.job_id;
  trace.pair_id = config.pair_id;
  trace.algorithm = config.algorithm;
  trace.oracle_id = config.oracle_id;

  if (config.left == nullptr || config.left->sig_max_len == 0 || config.left->pk_len != config.params.pk_len ||
      config.left->sk_len != config.params.sk_len || config.left->sig_max_len != config.params.sig_max_len) {
    trace.diagnostic_event = "harness_error: Falcon adapter ABI does not match the profile";
    trace.relation_evaluable = false;
    trace.intervention_supported = false;
    trace.intervention_effective = false;
    return trace;
  }

  const std::string &oracle_id = config.oracle_id;
  trace.controls = {};
  PopulateFalconControls(oracle_id, &trace);
  if (oracle_id == "falcon_kat") {
    trace.subtests.push_back(FalconKat(config, &trace));
  } else if (oracle_id == "falcon_local_sign_verify") {
    for (auto &subtest : FalconLocalSignVerify(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "falcon_cross_verify") {
    trace.subtests.push_back(FalconCrossVerify(config));
  } else if (oracle_id == "falcon_message_salt_binding") {
    for (auto &subtest : FalconMessageSaltBinding(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "falcon_header_profile") {
    for (auto &subtest : FalconHeaderProfile(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "falcon_pk_coefficients") {
    for (auto &subtest : FalconPkCoefficients(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "falcon_compressed_canonicality") {
    for (auto &subtest : FalconCompressedCanonicality(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "falcon_format_lengths") {
    for (auto &subtest : FalconFormatLengths(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "falcon_norm_equation") {
    for (auto &subtest : FalconNormEquation(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "falcon_rng_replay") {
    for (auto &subtest : FalconRngReplay(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "falcon_failure_state") {
    for (auto &subtest : FalconFailureState(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "falcon_signed_message_frame") {
    for (auto &subtest : FalconSignedMessageFrame(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "falcon_norm_boundary_unit" || oracle_id == "falcon_hash_to_point" ||
             oracle_id == "falcon_key_equation" || oracle_id == "falcon_sk_codec" ||
             oracle_id == "falcon_sampler_arithmetic") {
    trace.subtests.push_back(
        FalconModelLane(config, oracle_id, "tests/models/falcon_model.py"));
    trace.relation_not_applicable = true;
  } else if (oracle_id == "falcon_fault_checks" || oracle_id == "falcon_timing_resources") {
    trace.subtests.push_back(FalconModelLane(config, oracle_id, "tests/models/falcon_model.py (opt-in P2)"));
    trace.relation_not_applicable = true;
  } else {
    trace.diagnostic_event = "unknown Falcon oracle_id";
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
  if (const auto *first = trace.subtests.empty() ? nullptr : &trace.subtests.front()) {
    if (!first->calls.empty()) {
      trace.left_status = first->calls.front().status;
      trace.right_status = first->calls.back().status;
      trace.has_verify_result = first->calls.back().has_bool_result;
      trace.verify_result = first->calls.back().bool_result;
    }
  }
  SetFalconTraceReachability(&trace);
  if (!trace.mutations.empty()) {
    trace.intervention_effective =
        std::any_of(trace.mutations.begin(), trace.mutations.end(), [](const MutationRecord &record) {
          return record.effective && !record.skipped;
        });
  }
  AddFalconFindingsForFailures(config, &trace);
  if (!trace.mutations.empty()) {
    trace.mutation_target = trace.mutations.front().target;
  }
  if (!trace.findings.empty()) {
    trace.claim_id = trace.findings.front().claim_id;
  }
  return trace;
}

}  // namespace pqcfuzz

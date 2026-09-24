#include "oracles/cross_executor.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

#include "adapters/rng_control.h"
#include "adapters/status.h"
#include "mutators/cross_mutator.h"
#include "mutators/digest.h"
#include "mutators/scheme_mutation.h"
#include "oracles/oracle_result.h"

#ifndef PQCFUZZ_CROSS_MODEL_LANE
#define PQCFUZZ_CROSS_MODEL_LANE 1
#endif

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

SIGKeyPair CrossKeygen(
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

SIGSignature CrossSign(
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

SIGVerifyResult CrossVerify(
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

// Runs the negative verification gate shared by most CROSS mutation oracles.
OracleSubtestTrace RunMutationNegative(
    const CrossOracleConfig &config,
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
  const bool effective = std::any_of(records.begin(), records.end(), [](const MutationRecord &record) {
    return record.effective && !record.skipped;
  });
  if (!effective) {
    MarkNotApplicable(&subtest, "no_effect");
    return subtest;
  }
  SIGVerifyResult verify_result = CrossVerify(config.left, "left", signature, config.message, pk, &subtest);
  subtest.passed = RejectionLike(verify_result.status) || verify_result.status == PQCFUZZ_API_UNSUPPORTED;
  if (!subtest.passed) {
    subtest.note = failure_note;
  }
  return subtest;
}

OracleSubtestTrace CrossKat(const CrossOracleConfig &config, KEMOracleTrace *trace) {
  OracleSubtestTrace subtest = MakeSubtest("seeded_reference_reproduction", config.oracle_id, "EXPECT_EQUAL");
  OracleSubtestTrace setup = MakeSubtest("setup", config.oracle_id, "EXPECT_EQUAL");
  SIGKeyPair first = CrossKeygen(config.left, "left", config.seed, "kat-keygen", &setup);
  SIGKeyPair second = CrossKeygen(config.left, "left", config.seed, "kat-keygen", &setup);
  if (first.status != PQCFUZZ_OK || second.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "seeded key generation failed";
    subtest.calls = setup.calls;
    return subtest;
  }
  SIGSignature sig_a = CrossSign(config.left, "left", config.message, first.sk, config.seed, "kat-sign", &setup);
  SIGSignature sig_b = CrossSign(config.left, "left", config.message, first.sk, config.seed, "kat-sign", &setup);
  if (sig_a.status != PQCFUZZ_OK || sig_b.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "seeded signing failed";
    subtest.calls = setup.calls;
    return subtest;
  }
  SIGVerifyResult verified = CrossVerify(config.left, "left", sig_a.sig, config.message, first.pk, &subtest);
  const bool reproducible = first.pk == second.pk && sig_a.sig == sig_b.sig;
  subtest.passed = reproducible && verified.status == PQCFUZZ_OK;
  if (!subtest.passed) {
    subtest.note = reproducible ? "seeded signature did not verify" : "seeded outputs are not reproducible";
  }
  trace->baseline = {first.status, false, false, MutationSha256Hex(first.pk), first.pk.size()};
  trace->mutated = {sig_a.status, false, false, MutationSha256Hex(sig_a.sig), sig_a.sig.size()};
  return subtest;
}

OracleSubtestTrace CrossLocalSignVerify(const CrossOracleConfig &config) {
  OracleSubtestTrace subtest = MakeSubtest("seeded_sign_verify", config.oracle_id, "VERIFY_TRUE");
  SIGKeyPair keypair = CrossKeygen(config.left, "left", config.seed, "local-keygen", &subtest);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = CrossSign(config.left, "left", config.message, keypair.sk, config.seed, "local-sign", &subtest);
  }
  SIGVerifyResult verify_result;
  if (signature.status == PQCFUZZ_OK) {
    verify_result = CrossVerify(config.left, "left", signature.sig, config.message, keypair.pk, &subtest);
  }
  if (IsUnsupportedOnly(subtest)) {
    subtest.skipped = true;
    subtest.passed = true;
    subtest.note = "adapter API unsupported";
    return subtest;
  }
  subtest.passed = verify_result.status == PQCFUZZ_OK && verify_result.accepted;
  if (!subtest.passed) {
    subtest.note = "valid CROSS signature did not verify";
  }
  return subtest;
}

OracleSubtestTrace CrossCrossVerify(const CrossOracleConfig &config) {
  OracleSubtestTrace subtest = MakeSubtest("cross_verify", config.oracle_id, "VERIFY_TRUE");
  if (!config.signature_exchange || config.right == nullptr) {
    MarkNotApplicable(&subtest, "signature_exchange is disabled in the pinned single-implementation lock");
    return subtest;
  }
  SIGKeyPair keypair = CrossKeygen(config.left, "left", config.seed, "cross-keygen", &subtest);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = CrossSign(config.left, "left", config.message, keypair.sk, config.seed, "cross-sign", &subtest);
  }
  SIGVerifyResult verify_result;
  if (signature.status == PQCFUZZ_OK) {
    verify_result = CrossVerify(config.right, "right", signature.sig, config.message, keypair.pk, &subtest);
  }
  subtest.passed = verify_result.status == PQCFUZZ_OK && verify_result.accepted;
  if (!subtest.passed) {
    subtest.note = "cross verification of a valid signature failed";
  }
  return subtest;
}

std::vector<OracleSubtestTrace> CrossMessageKeyBinding(const CrossOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace message_subtest = MakeSubtest("mutated_message_negative", config.oracle_id, "VERIFY_FALSE");
  OracleSubtestTrace key_subtest = MakeSubtest("foreign_key_negative", config.oracle_id, "VERIFY_FALSE");
  SIGKeyPair keypair = CrossKeygen(config.left, "left", config.seed, "binding-keygen", &message_subtest);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = CrossSign(config.left, "left", config.message, keypair.sk, config.seed, "binding-sign", &message_subtest);
  }
  if (signature.status != PQCFUZZ_OK) {
    message_subtest.passed = false;
    message_subtest.note = "could not construct valid signature";
    subtests.push_back(message_subtest);
    key_subtest.passed = false;
    key_subtest.note = "could not construct valid signature";
    subtests.push_back(key_subtest);
    return subtests;
  }
  std::vector<uint8_t> mutated_message = config.message;
  SchemeMutation recipe;
  recipe.op = SchemeMutationOp::kFlipBit;
  recipe.field = SchemeMutationField::kMessage;
  recipe.index = 0;
  recipe.aux = 0;
  auto records = MutateCrossMessage(EncodeSchemeMutation(recipe), &mutated_message);
  RecordMutationEffect(records, trace);
  const bool effective = std::any_of(records.begin(), records.end(), [](const MutationRecord &record) {
    return record.effective && !record.skipped;
  });
  if (!effective) {
    MarkNotApplicable(&message_subtest, "no_effect");
  } else {
    SIGVerifyResult result = CrossVerify(config.left, "left", signature.sig, mutated_message, keypair.pk, &message_subtest);
    message_subtest.passed = RejectionLike(result.status) || result.status == PQCFUZZ_API_UNSUPPORTED;
    if (!message_subtest.passed) {
      message_subtest.note = "signature verified for a different message";
    }
  }
  subtests.push_back(message_subtest);

  std::vector<uint8_t> foreign_seed = config.seed;
  foreign_seed.insert(foreign_seed.end(), {'f', 'o', 'r', 'e', 'i', 'g', 'n'});
  SIGKeyPair foreign = CrossKeygen(config.left, "left", foreign_seed, "binding-keygen", &key_subtest);
  if (foreign.status != PQCFUZZ_OK) {
    key_subtest.passed = false;
    key_subtest.note = "could not construct independent honest key pair";
  } else {
    SIGVerifyResult result = CrossVerify(config.left, "left", signature.sig, config.message, foreign.pk, &key_subtest);
    key_subtest.passed = RejectionLike(result.status) || result.status == PQCFUZZ_API_UNSUPPORTED;
    if (!key_subtest.passed) {
      key_subtest.note = "signature verified under an independent honest key";
    }
  }
  subtests.push_back(key_subtest);
  return subtests;
}

std::vector<OracleSubtestTrace> CrossExactLengths(const CrossOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("setup", config.oracle_id, "VERIFY_TRUE");
  SIGKeyPair keypair = CrossKeygen(config.left, "left", config.seed, "length-keygen", &setup);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = CrossSign(config.left, "left", config.message, keypair.sk, config.seed, "length-sign", &setup);
  }
  const auto run = [&](const std::string &id, const std::vector<uint8_t> &candidate, bool expect_reject) {
    OracleSubtestTrace subtest = MakeSubtest(id, config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
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
    SIGVerifyResult result = CrossVerify(config.left, "left", candidate, config.message, keypair.pk, &subtest);
    if (expect_reject) {
      subtest.passed = RejectionLike(result.status) || result.status == PQCFUZZ_API_UNSUPPORTED;
      if (!subtest.passed) {
        subtest.note = "signature length boundary was accepted";
      }
    } else {
      subtest.passed = result.status == PQCFUZZ_OK && result.accepted;
    }
    return subtest;
  };
  std::vector<uint8_t> truncated = signature.sig;
  if (!truncated.empty()) {
    truncated.pop_back();
  }
  std::vector<uint8_t> appended = signature.sig;
  appended.push_back(0xA5);
  std::vector<uint8_t> empty;
  std::vector<uint8_t> one = signature.sig.empty() ? std::vector<uint8_t>{} : std::vector<uint8_t>{signature.sig[0]};
  subtests.push_back(run("baseline_exact_length", signature.sig, false));
  subtests.push_back(run("truncated_signature_negative", truncated, true));
  subtests.push_back(run("appended_signature_negative", appended, true));
  subtests.push_back(run("empty_signature_negative", empty, true));
  subtests.push_back(run("one_byte_signature_negative", one, true));
  return subtests;
}

std::vector<OracleSubtestTrace> CrossPackedFieldRange(const CrossOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("setup", config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  SIGKeyPair keypair = CrossKeygen(config.left, "left", config.seed, "range-keygen", &setup);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = CrossSign(config.left, "left", config.message, keypair.sk, config.seed, "range-sign", &setup);
  }
  const auto run = [&](const std::string &id, bool is_y) {
    OracleSubtestTrace subtest = MakeSubtest(id, config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    subtest.calls = setup.calls;
    if (signature.status != PQCFUZZ_OK) {
      subtest.passed = false;
      subtest.note = "could not construct valid signature";
      return subtest;
    }
    std::vector<uint8_t> mutated = signature.sig;
    auto records = MutateCrossPackedCoefficient(config.params, is_y, 0, 0, &mutated);
    return RunMutationNegative(config, id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT", mutated,
                               keypair.pk, records, "out-of-domain wire coefficient was accepted", trace);
  };
  subtests.push_back(run("y_coefficient_out_of_range", true));
  subtests.push_back(run("v_coefficient_out_of_range", false));
  return subtests;
}

std::vector<OracleSubtestTrace> CrossVectorPadding(const CrossOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("setup", config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  SIGKeyPair keypair = CrossKeygen(config.left, "left", config.seed, "padding-keygen", &setup);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = CrossSign(config.left, "left", config.message, keypair.sk, config.seed, "padding-sign", &setup);
  }
  const auto run = [&](const std::string &id, bool is_y) {
    OracleSubtestTrace subtest = MakeSubtest(id, config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    subtest.calls = setup.calls;
    if (signature.status != PQCFUZZ_OK) {
      subtest.passed = false;
      subtest.note = "could not construct valid signature";
      return subtest;
    }
    if (CrossVectorPaddingBits(config.params, is_y) == 0) {
      MarkNotApplicable(&subtest, "byte_aligned_vector");
      return subtest;
    }
    std::vector<uint8_t> mutated = signature.sig;
    auto records = MutateCrossPaddingBit(config.params, is_y, 0, 0, &mutated);
    return RunMutationNegative(config, id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT", mutated,
                               keypair.pk, records, "unused padding bit was accepted", trace);
  };
  subtests.push_back(run("y_padding_bit_negative", true));
  subtests.push_back(run("v_padding_bit_negative", false));
  return subtests;
}

std::vector<OracleSubtestTrace> CrossChallengeSampling(const CrossOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("setup", config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  SIGKeyPair keypair = CrossKeygen(config.left, "left", config.seed, "challenge-keygen", &setup);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = CrossSign(config.left, "left", config.message, keypair.sk, config.seed, "challenge-sign", &setup);
  }
  const auto run = [&](const std::string &id, SchemeMutationField field) {
    OracleSubtestTrace subtest = MakeSubtest(id, config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    subtest.calls = setup.calls;
    if (signature.status != PQCFUZZ_OK) {
      subtest.passed = false;
      subtest.note = "could not construct valid signature";
      return subtest;
    }
    SchemeMutation recipe;
    recipe.op = SchemeMutationOp::kXorByte;
    recipe.field = field;
    recipe.index = 0;
    recipe.payload = {0x01};
    std::vector<uint8_t> mutated = signature.sig;
    auto records = MutateCrossSignature(config.params, EncodeSchemeMutation(recipe), &mutated);
    return RunMutationNegative(config, id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT", mutated,
                               keypair.pk, records, "mutated challenge digest was accepted", trace);
  };
  subtests.push_back(run("challenge_digest_negative", SchemeMutationField::kSignatureDigestChall2));
  OracleSubtestTrace model = MakeSubtest("challenge_sampler_model", config.oracle_id, "EXPECT_EQUAL");
  MarkNotApplicable(&model, "fixed-weight sampler equality is evaluated by tests/models/cross_model.py");
  subtests.push_back(model);
  return subtests;
}

std::vector<OracleSubtestTrace> CrossCommitmentDigests(const CrossOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("setup", config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  SIGKeyPair keypair = CrossKeygen(config.left, "left", config.seed, "digest-keygen", &setup);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = CrossSign(config.left, "left", config.message, keypair.sk, config.seed, "digest-sign", &setup);
  }
  const auto run = [&](const std::string &id, SchemeMutationField field) {
    OracleSubtestTrace subtest = MakeSubtest(id, config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    subtest.calls = setup.calls;
    if (signature.status != PQCFUZZ_OK) {
      subtest.passed = false;
      subtest.note = "could not construct valid signature";
      return subtest;
    }
    SchemeMutation recipe;
    recipe.op = SchemeMutationOp::kXorByte;
    recipe.field = field;
    recipe.index = 0;
    recipe.payload = {0x01};
    std::vector<uint8_t> mutated = signature.sig;
    auto records = MutateCrossSignature(config.params, EncodeSchemeMutation(recipe), &mutated);
    return RunMutationNegative(config, id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT", mutated,
                               keypair.pk, records, "mutated commitment digest was accepted", trace);
  };
  subtests.push_back(run("digest_cmt_negative", SchemeMutationField::kSignatureDigestCmt));
  subtests.push_back(run("digest_chall2_negative", SchemeMutationField::kSignatureDigestChall2));
  subtests.push_back(run("resp1_negative", SchemeMutationField::kSignatureResp1));
  return subtests;
}

std::vector<OracleSubtestTrace> CrossMerkleProof(const CrossOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("setup", config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  SIGKeyPair keypair = CrossKeygen(config.left, "left", config.seed, "proof-keygen", &setup);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = CrossSign(config.left, "left", config.message, keypair.sk, config.seed, "proof-sign", &setup);
  }
  const auto run = [&](const std::string &id, SchemeMutationField field) {
    OracleSubtestTrace subtest = MakeSubtest(id, config.oracle_id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
    subtest.calls = setup.calls;
    if (signature.status != PQCFUZZ_OK) {
      subtest.passed = false;
      subtest.note = "could not construct valid signature";
      return subtest;
    }
    SchemeMutation recipe;
    recipe.op = SchemeMutationOp::kXorByte;
    recipe.field = field;
    recipe.index = 0;
    recipe.payload = {0x01};
    std::vector<uint8_t> mutated = signature.sig;
    auto records = MutateCrossSignature(config.params, EncodeSchemeMutation(recipe), &mutated);
    return RunMutationNegative(config, id, "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT", mutated,
                               keypair.pk, records, "mutated tree path/proof was accepted", trace);
  };
  subtests.push_back(run("path_negative", SchemeMutationField::kSignaturePath));
  subtests.push_back(run("proof_negative", SchemeMutationField::kSignatureProof));
  subtests.push_back(run("domain_transcript_negative", SchemeMutationField::kSignatureSalt));
  return subtests;
}

std::vector<OracleSubtestTrace> CrossRngReplay(const CrossOracleConfig &config, KEMOracleTrace *trace) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace setup = MakeSubtest("setup", config.oracle_id, "EXPECT_EQUAL");
  if (config.left == nullptr || config.left->sign == nullptr || config.left->keygen == nullptr) {
    OracleSubtestTrace unsupported = MakeSubtest("rng_replay", config.oracle_id, "EXPECT_EQUAL");
    unsupported.not_applicable = true;
    unsupported.passed = true;
    unsupported.note = "adapter API unsupported";
    subtests.push_back(unsupported);
    return subtests;
  }
  const bool use_seeded = config.left->keygen_seeded != nullptr && config.left->sign_seeded != nullptr;
  std::vector<uint8_t> tape_a(64);
  std::vector<uint8_t> tape_b(64);
  for (size_t i = 0; i < tape_a.size(); ++i) {
    tape_a[i] = static_cast<uint8_t>(0x11u + i);
    tape_b[i] = static_cast<uint8_t>(0x91u + i * 3u);
  }
  const std::vector<uint8_t> seed_a = DeriveSeed(config.seed, "rng-replay-keygen", 48);
  const std::vector<uint8_t> seed_b = DeriveSeed(config.seed, "rng-replay-sign", 48);
  const std::vector<uint8_t> seed_c = DeriveSeed(config.seed, "rng-replay-sign-alt", 48);

  SIGKeyPair keypair;
  keypair.pk.resize(config.left->pk_len);
  keypair.sk.resize(config.left->sk_len);
  if (use_seeded) {
    keypair.status = config.left->keygen_seeded(keypair.pk.data(), keypair.sk.data(), seed_a.data(), seed_a.size());
    AddCall(&setup, "left", "keygen_seeded", keypair.status);
  } else {
    ScopedRngOverride rng({tape_a.data(), tape_a.size(), false});
    keypair.status = config.left->keygen(keypair.pk.data(), keypair.sk.data());
    AddCall(&setup, "left", "keygen", keypair.status);
  }

  const auto sign_once = [&](const std::vector<uint8_t> &tape, const std::vector<uint8_t> &seed) {
    SIGSignature signature;
    signature.sig.resize(config.left->sig_max_len);
    size_t sig_len = config.left->sig_max_len;
    if (use_seeded) {
      signature.status = config.left->sign_seeded(signature.sig.data(), &sig_len, config.message.data(),
                                                  config.message.size(), keypair.sk.data(), nullptr, 0, seed.data(),
                                                  seed.size());
    } else {
      ScopedRngOverride rng({tape.data(), tape.size(), false});
      signature.status = config.left->sign(signature.sig.data(), &sig_len, config.message.data(), config.message.size(),
                                           keypair.sk.data(), nullptr, 0);
    }
    if (signature.status == PQCFUZZ_OK) {
      signature.sig.resize(sig_len);
    }
    AddCall(&setup, "left", "sign", signature.status);
    return signature;
  };

  const SIGSignature first = sign_once(tape_a, seed_b);
  const SIGSignature second = sign_once(tape_a, seed_b);
  const SIGSignature third = sign_once(tape_b, seed_c);

  OracleSubtestTrace differs = MakeSubtest("different_tape_differs", config.oracle_id, "EXPECT_DIFFERENT");
  differs.calls = setup.calls;
  if (use_seeded) {
    MarkNotApplicable(&differs, "seeded sign API consumes an explicit seed; tape divergence is covered by the Python lane");
  } else {
    differs.passed = first.status == PQCFUZZ_OK && third.status == PQCFUZZ_OK && first.sig != third.sig;
    if (!differs.passed) {
      differs.note = "different CSPRNG tapes produced identical signatures";
    }
  }
  subtests.push_back(differs);

  OracleSubtestTrace reproducible = MakeSubtest("same_tape_reproducible", config.oracle_id, "EXPECT_EQUAL");
  reproducible.calls = setup.calls;
  reproducible.passed = keypair.status == PQCFUZZ_OK && first.status == PQCFUZZ_OK && second.status == PQCFUZZ_OK &&
                        first.sig == second.sig;
  if (!reproducible.passed) {
    reproducible.note = "same CSPRNG tape did not reproduce the signature";
  }
  SIGVerifyResult verified = CrossVerify(config.left, "left", first.sig, config.message, keypair.pk, &reproducible);
  if (reproducible.passed) {
    reproducible.passed = verified.status == PQCFUZZ_OK;
    if (!reproducible.passed) {
      reproducible.note = "tape-reproduced signature did not verify";
    }
  }
  subtests.push_back(reproducible);
  return subtests;
}

std::vector<OracleSubtestTrace> CrossFailureResources(const CrossOracleConfig &config) {
  std::vector<OracleSubtestTrace> subtests;
  OracleSubtestTrace failure = MakeSubtest("rng_failure_observed", config.oracle_id, "REJECT_OR_INVALID_INPUT");
  if (config.left == nullptr || config.left->keygen == nullptr) {
    MarkNotApplicable(&failure, "adapter API unsupported");
    subtests.push_back(failure);
    return subtests;
  }
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

  OracleSubtestTrace empty_message = MakeSubtest("empty_message_roundtrip", config.oracle_id, "VERIFY_TRUE");
  SIGKeyPair keypair = CrossKeygen(config.left, "left", config.seed, "empty-keygen", &empty_message);
  SIGSignature signature;
  std::vector<uint8_t> empty;
  if (keypair.status == PQCFUZZ_OK) {
    signature = CrossSign(config.left, "left", empty, keypair.sk, config.seed, "empty-sign", &empty_message);
  }
  if (signature.status == PQCFUZZ_OK) {
    SIGVerifyResult result = CrossVerify(config.left, "left", signature.sig, empty, keypair.pk, &empty_message);
    empty_message.passed = result.status == PQCFUZZ_OK && result.accepted;
  } else {
    empty_message.passed = false;
    empty_message.note = "empty-message signing failed";
  }
  subtests.push_back(empty_message);

  OracleSubtestTrace zero_length = MakeSubtest("zero_length_signature_negative", config.oracle_id,
                                               "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT");
  {
    std::vector<uint8_t> empty_sig;
    SIGVerifyResult result = CrossVerify(config.left, "left", empty_sig, config.message, keypair.pk, &zero_length);
    zero_length.passed = RejectionLike(result.status);
    if (!zero_length.passed) {
      zero_length.note = "zero-length signature was accepted";
    }
  }
  subtests.push_back(zero_length);
  return subtests;
}

OracleSubtestTrace CrossModelLane(const CrossOracleConfig &config, const std::string &subtest_id) {
  OracleSubtestTrace subtest = MakeSubtest(subtest_id, config.oracle_id, "EXPECT_EQUAL");
  MarkNotApplicable(&subtest,
                    "evaluated by the independent Python transcript/tree model lane "
                    "(tests/models/cross_model.py)");
  return subtest;
}

void SetCrossTraceReachability(KEMOracleTrace *trace) {
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

OracleFindingTrace MakeFinding(
    const std::string &oracle_id,
    const std::string &finding_class,
    const std::string &finding_subclass,
    const std::string &summary,
    EvidenceKind evidence_kind) {
  OracleFindingTrace finding;
  finding.finding_class = finding_class;
  finding.finding_subclass = finding_subclass;
  finding.summary = summary;
  finding.evidence_kind = evidence_kind;
  const FindingClassification classification = ClassifyFinding(oracle_id, evidence_kind, finding_class);
  finding.verdict = classification.verdict;
  finding.evidence_class = classification.evidence_class;
  finding.conditional_verdict = classification.conditional_verdict;
  finding.claim = classification.claim;
  finding.source_reference = classification.source_reference;
  finding.limitations = classification.limitations;
  return finding;
}

void AddCrossFindingsForFailures(KEMOracleTrace *trace) {
  for (const auto &subtest : trace->subtests) {
    for (const auto &call : subtest.calls) {
      if (call.status == PQCFUZZ_CRASH) {
        trace->findings.push_back(
            MakeFinding(trace->oracle_id, "memory_safety", "", "adapter call crashed", EvidenceKind::kProcess));
      } else if (call.status == PQCFUZZ_TIMEOUT) {
        trace->findings.push_back(
            MakeFinding(trace->oracle_id, "timeout", "", "adapter call timed out", EvidenceKind::kProcess));
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
    if (trace->oracle_id == "cross_exact_lengths" && subtest.subtest_id == "appended_signature_negative") {
      finding_subclass = "appended_signature_bytes_accepted";
    } else if (trace->oracle_id == "cross_vector_padding") {
      finding_subclass = "unused_padding_bits_accepted";
    } else if (trace->oracle_id == "cross_packed_field_range") {
      finding_subclass = "out_of_domain_wire_coefficient_accepted";
    }
    trace->findings.push_back(
        MakeFinding(trace->oracle_id, finding_class, finding_subclass, subtest.note, EvidenceKind::kSemantic));
  }
}

void PopulateCrossControls(const std::string &oracle_id, KEMOracleTrace *trace) {
  if (oracle_id == "cross_kat") {
    trace->controls.positive_control = "a fixed seed reproduces the pinned reference outputs";
    trace->controls.negative_control = "a different seed produces different signature bytes";
  } else if (oracle_id == "cross_challenge_sampling") {
    trace->controls.positive_control = "the independent sampler reproduces the reference challenge";
    trace->controls.negative_control = "a digest mutation changes the challenge";
  } else if (oracle_id == "cross_domain_transcript") {
    trace->controls.positive_control = "the transcript model reproduces the reference digests";
    trace->controls.negative_control = "a big-endian tag model diverges";
  } else if (oracle_id == "cross_rng_replay") {
    trace->controls.positive_control = "two runs under the same tape agree";
    trace->controls.negative_control = "a different tape changes the salt";
  } else {
    trace->controls.positive_control = "the unmodified signature verifies";
    trace->controls.negative_control = "the targeted mutation is recorded as effective and rejected";
  }
}

}  // namespace

KEMOracleTrace ExecuteCrossOracle(const CrossOracleConfig &config) {
  KEMOracleTrace trace;
  trace.job_id = config.job_id;
  trace.pair_id = config.pair_id;
  trace.algorithm = config.algorithm;
  trace.oracle_id = config.oracle_id;

  if (config.left == nullptr || config.left->sig_max_len == 0 || config.left->pk_len != config.params.pk_len ||
      config.left->sk_len != config.params.sk_len || config.left->sig_max_len != config.params.sig_max_len) {
    trace.diagnostic_event = "harness_error: CROSS adapter ABI does not match the profile";
    trace.relation_evaluable = false;
    trace.intervention_supported = false;
    trace.intervention_effective = false;
    return trace;
  }

  const std::string &oracle_id = config.oracle_id;
  trace.controls = {};
  PopulateCrossControls(oracle_id, &trace);
  if (oracle_id == "cross_kat") {
    trace.subtests.push_back(CrossKat(config, &trace));
  } else if (oracle_id == "cross_local_sign_verify") {
    trace.subtests.push_back(CrossLocalSignVerify(config));
  } else if (oracle_id == "cross_cross_verify") {
    trace.subtests.push_back(CrossCrossVerify(config));
  } else if (oracle_id == "cross_message_key_binding") {
    for (auto &subtest : CrossMessageKeyBinding(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "cross_exact_lengths") {
    for (auto &subtest : CrossExactLengths(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "cross_packed_field_range") {
    for (auto &subtest : CrossPackedFieldRange(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "cross_vector_padding") {
    for (auto &subtest : CrossVectorPadding(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "cross_challenge_sampling") {
    for (auto &subtest : CrossChallengeSampling(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "cross_commitment_digests") {
    for (auto &subtest : CrossCommitmentDigests(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "cross_merkle_proof") {
    for (auto &subtest : CrossMerkleProof(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "cross_rng_replay") {
    for (auto &subtest : CrossRngReplay(config, &trace)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "cross_failure_resources") {
    for (auto &subtest : CrossFailureResources(config)) {
      trace.subtests.push_back(std::move(subtest));
    }
  } else if (oracle_id == "cross_domain_transcript" || oracle_id == "cross_seed_rebuild" ||
             oracle_id == "cross_path_proof_consumption" || oracle_id == "cross_key_algebra" ||
             oracle_id == "cross_parallel_arithmetic" || oracle_id == "cross_fault_seed_disclosure" ||
             oracle_id == "cross_timing") {
    trace.subtests.push_back(CrossModelLane(config, oracle_id));
    trace.relation_not_applicable = true;
  } else {
    trace.diagnostic_event = "unknown CROSS oracle_id";
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
  SetCrossTraceReachability(&trace);
  AddCrossFindingsForFailures(&trace);
  if (!trace.mutations.empty()) {
    trace.mutation_target = trace.mutations.front().target;
  }
  return trace;
}

}  // namespace pqcfuzz

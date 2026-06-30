#include "oracles/oracle_executor.h"

#include <algorithm>
#include <sstream>

#include "adapters/status.h"
#include "mutators/ml_dsa_mutator.h"
#include "mutators/slh_dsa_mutator.h"

namespace pqcfuzz {
namespace {

std::string JsonEscape(const std::string &value) {
  std::ostringstream out;
  for (char ch : value) {
    switch (ch) {
      case '\\':
        out << "\\\\";
        break;
      case '"':
        out << "\\\"";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        out << ch;
        break;
    }
  }
  return out.str();
}

bool IsUnsupportedOnly(const OracleSubtestTrace &subtest) {
  return !subtest.calls.empty() &&
         std::all_of(subtest.calls.begin(), subtest.calls.end(), [](const OracleCallTrace &call) {
           return call.status == PQCFUZZ_API_UNSUPPORTED;
         });
}

void AddCall(OracleSubtestTrace *subtest, const std::string &adapter, const std::string &api, pqcfuzz_status status) {
  subtest->calls.push_back({adapter, api, status, false, false});
}

void AddBoolCall(
    OracleSubtestTrace *subtest,
    const std::string &adapter,
    const std::string &api,
    pqcfuzz_status status,
    bool bool_result) {
  subtest->calls.push_back({adapter, api, status, true, bool_result});
}

KEMKeyPair Keygen(const pqcfuzz_kem_adapter *adapter, const std::string &label, OracleSubtestTrace *subtest) {
  KEMKeyPair out;
  if (adapter == nullptr || adapter->keygen == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "keygen", out.status);
    return out;
  }
  out.pk.resize(adapter->pk_len);
  out.sk.resize(adapter->sk_len);
  out.status = adapter->keygen(out.pk.data(), out.sk.data());
  AddCall(subtest, label, "keygen", out.status);
  return out;
}

KEMCiphertext Encaps(
    const pqcfuzz_kem_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &pk,
    OracleSubtestTrace *subtest,
    KEMSharedSecret *shared_secret) {
  KEMCiphertext out;
  if (adapter == nullptr || adapter->encaps == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    if (shared_secret != nullptr) {
      shared_secret->status = out.status;
    }
    AddCall(subtest, label, "encaps", out.status);
    return out;
  }
  if (pk.size() != adapter->pk_len) {
    out.status = PQCFUZZ_INVALID_INPUT;
    if (shared_secret != nullptr) {
      shared_secret->status = out.status;
    }
    AddCall(subtest, label, "encaps", out.status);
    return out;
  }
  out.ct.resize(adapter->ct_len);
  if (shared_secret != nullptr) {
    shared_secret->ss.resize(adapter->ss_len);
    shared_secret->status = adapter->encaps(out.ct.data(), shared_secret->ss.data(), pk.data());
    out.status = shared_secret->status;
  } else {
    std::vector<uint8_t> ss(adapter->ss_len);
    out.status = adapter->encaps(out.ct.data(), ss.data(), pk.data());
  }
  AddCall(subtest, label, "encaps", out.status);
  return out;
}

KEMSharedSecret Decaps(
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
    AddCall(subtest, label, "decaps", out.status);
    return out;
  }
  out.ss.resize(adapter->ss_len);
  out.status = adapter->decaps(out.ss.data(), ct.data(), sk.data());
  AddCall(subtest, label, "decaps", out.status);
  return out;
}

bool SameSecret(const KEMSharedSecret &left, const KEMSharedSecret &right) {
  return left.status == PQCFUZZ_OK && right.status == PQCFUZZ_OK && left.ss == right.ss;
}

void FinalizeRoundtrip(OracleSubtestTrace *subtest, const KEMSharedSecret &encaps_ss, const KEMSharedSecret &decaps_ss) {
  if (IsUnsupportedOnly(*subtest)) {
    subtest->skipped = true;
    subtest->passed = true;
    subtest->note = "adapter API unsupported";
    return;
  }
  subtest->passed = SameSecret(encaps_ss, decaps_ss);
  if (!subtest->passed) {
    subtest->note = "shared secret relation failed";
  }
}

OracleSubtestTrace LocalRoundtrip(
    const std::string &subtest_id,
    const std::string &adapter_label,
    const pqcfuzz_kem_adapter *adapter) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = subtest_id;
  subtest.oracle_id = "mlkem_local_roundtrip";
  subtest.expected_relation = "SAME_SHARED_SECRET";
  KEMKeyPair keypair = Keygen(adapter, adapter_label, &subtest);
  KEMSharedSecret encaps_ss;
  KEMCiphertext ciphertext;
  if (keypair.status == PQCFUZZ_OK) {
    ciphertext = Encaps(adapter, adapter_label, keypair.pk, &subtest, &encaps_ss);
  }
  KEMSharedSecret decaps_ss;
  if (ciphertext.status == PQCFUZZ_OK) {
    decaps_ss = Decaps(adapter, adapter_label, ciphertext.ct, keypair.sk, &subtest);
  }
  FinalizeRoundtrip(&subtest, encaps_ss, decaps_ss);
  return subtest;
}

OracleSubtestTrace CrossEncapsRoundtrip(
    const std::string &subtest_id,
    const std::string &keygen_label,
    const pqcfuzz_kem_adapter *keygen_adapter,
    const std::string &encaps_label,
    const pqcfuzz_kem_adapter *encaps_adapter) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = subtest_id;
  subtest.oracle_id = "mlkem_cross_exchange_roundtrip";
  subtest.expected_relation = "SAME_SHARED_SECRET";
  KEMKeyPair keypair = Keygen(keygen_adapter, keygen_label, &subtest);
  KEMSharedSecret encaps_ss;
  KEMCiphertext ciphertext;
  if (keypair.status == PQCFUZZ_OK) {
    ciphertext = Encaps(encaps_adapter, encaps_label, keypair.pk, &subtest, &encaps_ss);
  }
  KEMSharedSecret decaps_ss;
  if (ciphertext.status == PQCFUZZ_OK) {
    decaps_ss = Decaps(keygen_adapter, keygen_label, ciphertext.ct, keypair.sk, &subtest);
  }
  FinalizeRoundtrip(&subtest, encaps_ss, decaps_ss);
  return subtest;
}

OracleSubtestTrace CrossDecapsRoundtrip(
    const std::string &subtest_id,
    const std::string &source_label,
    const pqcfuzz_kem_adapter *source_adapter,
    const std::string &decaps_label,
    const pqcfuzz_kem_adapter *decaps_adapter) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = subtest_id;
  subtest.oracle_id = "mlkem_cross_exchange_roundtrip";
  subtest.expected_relation = "SAME_SHARED_SECRET";
  KEMKeyPair keypair = Keygen(source_adapter, source_label, &subtest);
  KEMSharedSecret encaps_ss;
  KEMCiphertext ciphertext;
  if (keypair.status == PQCFUZZ_OK) {
    ciphertext = Encaps(source_adapter, source_label, keypair.pk, &subtest, &encaps_ss);
  }
  KEMSharedSecret decaps_ss;
  if (ciphertext.status == PQCFUZZ_OK) {
    decaps_ss = Decaps(decaps_adapter, decaps_label, ciphertext.ct, keypair.sk, &subtest);
  }
  FinalizeRoundtrip(&subtest, encaps_ss, decaps_ss);
  return subtest;
}

OracleSubtestTrace TamperedCiphertext(
    const OracleExecutorConfig &config,
    std::vector<MutationRecord> *mutations) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = "tampered_ciphertext_negative";
  subtest.oracle_id = "mlkem_tampered_ciphertext_implicit_rejection";
  subtest.expected_relation = "REJECT_OR_DIFFERENT_SHARED_SECRET";
  KEMKeyPair keypair = Keygen(config.left, "left", &subtest);
  KEMSharedSecret encaps_ss;
  KEMCiphertext ciphertext;
  if (keypair.status == PQCFUZZ_OK) {
    ciphertext = Encaps(config.left, "left", keypair.pk, &subtest, &encaps_ss);
  }
  if (ciphertext.status != PQCFUZZ_OK) {
    FinalizeRoundtrip(&subtest, encaps_ss, {});
    return subtest;
  }

  std::vector<uint8_t> mutated = ciphertext.ct;
  auto records = MutateMlKemCiphertext(config.params, config.mutation, &mutated);
  mutations->insert(mutations->end(), records.begin(), records.end());
  KEMSharedSecret decaps_ss = Decaps(config.left, "left", mutated, keypair.sk, &subtest);
  if (decaps_ss.status == PQCFUZZ_REJECT || decaps_ss.status == PQCFUZZ_INVALID_INPUT) {
    subtest.passed = true;
    return subtest;
  }
  if (decaps_ss.status == PQCFUZZ_API_UNSUPPORTED) {
    subtest.skipped = true;
    subtest.passed = true;
    subtest.note = "adapter API unsupported";
    return subtest;
  }
  subtest.passed = decaps_ss.status == PQCFUZZ_OK && decaps_ss.ss != encaps_ss.ss;
  if (!subtest.passed) {
    subtest.note = "tampered ciphertext returned original shared secret";
  }
  return subtest;
}

void AddFindingsForFailures(KEMOracleTrace *trace) {
  for (const auto &subtest : trace->subtests) {
    for (const auto &call : subtest.calls) {
      if (call.status == PQCFUZZ_CRASH) {
        trace->findings.push_back({"memory_safety", "", "adapter call crashed"});
      } else if (call.status == PQCFUZZ_TIMEOUT) {
        trace->findings.push_back({"timeout", "", "adapter call timed out"});
      }
    }
    if (!subtest.passed && subtest.oracle_id == "mlkem_tampered_ciphertext_implicit_rejection") {
      trace->findings.push_back({"potential_crypto_vuln", "", subtest.note});
    } else if (!subtest.passed) {
      trace->findings.push_back({"confirmed_semantic_bug", "", subtest.note});
    }
  }
}

SIGKeyPair SigKeygen(const pqcfuzz_sig_adapter *adapter, const std::string &label, OracleSubtestTrace *subtest) {
  SIGKeyPair out;
  if (adapter == nullptr || adapter->keygen == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "keygen", out.status);
    return out;
  }
  out.pk.resize(adapter->pk_len);
  out.sk.resize(adapter->sk_len);
  out.status = adapter->keygen(out.pk.data(), out.sk.data());
  AddCall(subtest, label, "keygen", out.status);
  return out;
}

SIGSignature SigSign(
    const pqcfuzz_sig_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &context,
    const std::vector<uint8_t> &sk,
    OracleSubtestTrace *subtest) {
  SIGSignature out;
  if (adapter == nullptr || adapter->sign == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "sign", out.status);
    return out;
  }
  if (context.size() > 255 || sk.size() != adapter->sk_len) {
    out.status = PQCFUZZ_INVALID_INPUT;
    AddCall(subtest, label, "sign", out.status);
    return out;
  }
  out.sig.resize(adapter->sig_max_len);
  size_t sig_len = adapter->sig_max_len;
  const uint8_t *ctx = context.empty() ? nullptr : context.data();
  out.status = adapter->sign(out.sig.data(), &sig_len, message.data(), message.size(), sk.data(), ctx, context.size());
  if (out.status == PQCFUZZ_OK && sig_len <= adapter->sig_max_len) {
    out.sig.resize(sig_len);
  } else if (out.status == PQCFUZZ_OK) {
    out.status = PQCFUZZ_INVALID_INPUT;
    out.sig.clear();
  }
  AddCall(subtest, label, "sign", out.status);
  return out;
}

SIGVerifyResult SigVerify(
    const pqcfuzz_sig_adapter *adapter,
    const std::string &label,
    const std::vector<uint8_t> &signature,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &context,
    const std::vector<uint8_t> &pk,
    OracleSubtestTrace *subtest) {
  SIGVerifyResult out;
  if (adapter == nullptr || adapter->verify == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, label, "verify", out.status);
    return out;
  }
  if (context.size() > 255 || pk.size() != adapter->pk_len || signature.size() > adapter->sig_max_len) {
    out.status = PQCFUZZ_INVALID_INPUT;
    AddCall(subtest, label, "verify", out.status);
    return out;
  }
  const uint8_t *ctx = context.empty() ? nullptr : context.data();
  out.status = adapter->verify(signature.data(), signature.size(), message.data(), message.size(), pk.data(), ctx, context.size());
  out.accepted = out.status == PQCFUZZ_OK;
  AddBoolCall(subtest, label, "verify", out.status, out.accepted);
  return out;
}

void FinalizeVerifyTrue(OracleSubtestTrace *subtest, const SIGVerifyResult &verify_result) {
  if (IsUnsupportedOnly(*subtest)) {
    subtest->skipped = true;
    subtest->passed = true;
    subtest->note = "adapter API unsupported";
    return;
  }
  subtest->passed = verify_result.status == PQCFUZZ_OK && verify_result.accepted;
  if (!subtest->passed) {
    subtest->note = "valid signature did not verify";
  }
}

OracleSubtestTrace SigLocalSignVerify(
    const std::string &subtest_id,
    const std::string &oracle_id,
    const std::string &adapter_label,
    const pqcfuzz_sig_adapter *adapter,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &context) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = subtest_id;
  subtest.oracle_id = oracle_id;
  subtest.expected_relation = "VERIFY_TRUE";
  SIGKeyPair keypair = SigKeygen(adapter, adapter_label, &subtest);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = SigSign(adapter, adapter_label, message, context, keypair.sk, &subtest);
  }
  SIGVerifyResult verify_result;
  if (signature.status == PQCFUZZ_OK) {
    verify_result = SigVerify(adapter, adapter_label, signature.sig, message, context, keypair.pk, &subtest);
  }
  FinalizeVerifyTrue(&subtest, verify_result);
  return subtest;
}

OracleSubtestTrace SigCrossVerify(
    const std::string &subtest_id,
    const std::string &oracle_id,
    const std::string &source_label,
    const pqcfuzz_sig_adapter *source_adapter,
    const std::string &verify_label,
    const pqcfuzz_sig_adapter *verify_adapter,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &context) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = subtest_id;
  subtest.oracle_id = oracle_id;
  subtest.expected_relation = "VERIFY_TRUE";
  SIGKeyPair keypair = SigKeygen(source_adapter, source_label, &subtest);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = SigSign(source_adapter, source_label, message, context, keypair.sk, &subtest);
  }
  SIGVerifyResult verify_result;
  if (signature.status == PQCFUZZ_OK) {
    verify_result = SigVerify(verify_adapter, verify_label, signature.sig, message, context, keypair.pk, &subtest);
  }
  FinalizeVerifyTrue(&subtest, verify_result);
  return subtest;
}

bool LegalNegativeStatus(pqcfuzz_status status, bool allow_api_unsupported) {
  if (status == PQCFUZZ_REJECT || status == PQCFUZZ_INVALID_INPUT) {
    return true;
  }
  if (allow_api_unsupported && status == PQCFUZZ_API_UNSUPPORTED) {
    return true;
  }
  return false;
}

OracleSubtestTrace SigNegative(
    const SigOracleExecutorConfig &config,
    const std::string &subtest_id,
    const std::string &oracle_id,
    std::vector<MutationRecord> *mutations,
    bool mutate_signature,
    bool mutate_message,
    bool mutate_context,
    bool mutate_oid) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = subtest_id;
  subtest.oracle_id = oracle_id;
  subtest.expected_relation = mutate_signature ? "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT" :
      (mutate_context || mutate_oid ? "VERIFY_FALSE_OR_API_UNSUPPORTED" : "VERIFY_FALSE");

  SIGKeyPair keypair = SigKeygen(config.left, "left", &subtest);
  SIGSignature signature;
  std::vector<uint8_t> message = config.message;
  std::vector<uint8_t> context = config.context;
  std::vector<uint8_t> oid = config.oid.empty() ? std::vector<uint8_t>{0x06, 0x09, 0x60, 0x86, 0x48} : config.oid;
  if (keypair.status == PQCFUZZ_OK) {
    signature = SigSign(config.left, "left", message, context, keypair.sk, &subtest);
  }
  if (signature.status != PQCFUZZ_OK) {
    if (mutate_signature) {
      std::vector<uint8_t> planned_signature(config.is_slh_dsa ? config.slh_params.sig_max_len : config.params.sig_max_len);
      auto records = config.is_slh_dsa
          ? MutateSlhDsaSignature(config.slh_params, config.mutation, &planned_signature)
          : MutateMlDsaSignature(config.params, config.mutation, &planned_signature);
      mutations->insert(mutations->end(), records.begin(), records.end());
    } else if (mutate_message) {
      auto records = config.is_slh_dsa ? MutateSlhDsaMessage(config.mutation, &message)
                                       : MutateMlDsaMessage(config.mutation, &message);
      mutations->insert(mutations->end(), records.begin(), records.end());
    } else if (mutate_context) {
      auto records = config.is_slh_dsa ? MutateSlhDsaContext(config.mutation, &context)
                                       : MutateMlDsaContext(config.mutation, &context);
      mutations->insert(mutations->end(), records.begin(), records.end());
    }
    if (IsUnsupportedOnly(subtest)) {
      subtest.skipped = true;
      subtest.passed = true;
      subtest.note = "adapter API unsupported";
    } else {
      subtest.passed = false;
      subtest.note = "could not construct valid signature before mutation";
    }
    return subtest;
  }

  if (mutate_signature) {
    auto records = config.is_slh_dsa
        ? MutateSlhDsaSignature(config.slh_params, config.mutation, &signature.sig)
        : MutateMlDsaSignature(config.params, config.mutation, &signature.sig);
    mutations->insert(mutations->end(), records.begin(), records.end());
  }
  if (mutate_message) {
    auto records = config.is_slh_dsa ? MutateSlhDsaMessage(config.mutation, &message)
                                     : MutateMlDsaMessage(config.mutation, &message);
    mutations->insert(mutations->end(), records.begin(), records.end());
  }
  if (mutate_context) {
    auto records = config.is_slh_dsa ? MutateSlhDsaContext(config.mutation, &context)
                                     : MutateMlDsaContext(config.mutation, &context);
    mutations->insert(mutations->end(), records.begin(), records.end());
  }
  if (mutate_oid) {
    auto records = MutateMlDsaOid(config.mutation, &oid);
    mutations->insert(mutations->end(), records.begin(), records.end());
    context.insert(context.end(), oid.begin(), oid.end());
  }

  SIGVerifyResult verify_result = SigVerify(config.left, "left", signature.sig, message, context, keypair.pk, &subtest);
  const bool allow_api_unsupported = (mutate_context || mutate_oid) && config.left != nullptr && config.left->supports_context == 0;
  subtest.passed = LegalNegativeStatus(verify_result.status, allow_api_unsupported);
  if (!subtest.passed) {
    subtest.note = config.is_slh_dsa ? "mutated SLH-DSA input verified or produced an illegal status"
                                     : "mutated ML-DSA input verified or produced an illegal status";
  }
  return subtest;
}

void AddSigFindingsForFailures(KEMOracleTrace *trace) {
  for (const auto &subtest : trace->subtests) {
    for (const auto &call : subtest.calls) {
      if (call.status == PQCFUZZ_CRASH) {
        trace->findings.push_back({"memory_safety", "", "adapter call crashed"});
      } else if (call.status == PQCFUZZ_TIMEOUT) {
        trace->findings.push_back({"timeout", "", "adapter call timed out"});
      }
    }
    if (subtest.passed) {
      continue;
    }
    if (subtest.oracle_id.find("_mutated_signature_negative") != std::string::npos ||
        subtest.oracle_id.find("_mutated_message_negative") != std::string::npos ||
        subtest.oracle_id.find("_mutated_context_negative") != std::string::npos) {
      trace->findings.push_back({"potential_crypto_vuln", "", subtest.note});
    } else {
      trace->findings.push_back({"confirmed_semantic_bug", "", subtest.note});
    }
  }
}

}  // namespace

KEMOracleTrace ExecuteKemOracle(const OracleExecutorConfig &config) {
  KEMOracleTrace trace;
  trace.job_id = config.job_id;
  trace.pair_id = config.pair_id;
  trace.algorithm = config.algorithm;
  trace.oracle_id = config.oracle_id;

  if (config.oracle_id == "mlkem_tampered_ciphertext_implicit_rejection") {
    trace.subtests.push_back(TamperedCiphertext(config, &trace.mutations));
  } else if (config.oracle_id == "mlkem_cross_exchange_roundtrip") {
    if (config.exchange_contract.public_key_exchange && config.exchange_contract.ciphertext_exchange) {
      trace.subtests.push_back(CrossEncapsRoundtrip(
          "left_keygen_right_encaps_left_decaps", "left", config.left, "right", config.right));
      trace.subtests.push_back(CrossEncapsRoundtrip(
          "right_keygen_left_encaps_right_decaps", "right", config.right, "left", config.left));
    }
    if (config.exchange_contract.ciphertext_exchange && config.exchange_contract.secret_key_exchange &&
        config.exchange_contract.secret_key_format_compatible) {
      trace.subtests.push_back(CrossDecapsRoundtrip(
          "left_keygen_left_encaps_right_decaps", "left", config.left, "right", config.right));
      trace.subtests.push_back(CrossDecapsRoundtrip(
          "right_keygen_right_encaps_left_decaps", "right", config.right, "left", config.left));
    }
  } else {
    trace.subtests.push_back(LocalRoundtrip("left_keygen_left_encaps_left_decaps", "left", config.left));
    trace.subtests.push_back(LocalRoundtrip("right_keygen_right_encaps_right_decaps", "right", config.right));
  }

  AddFindingsForFailures(&trace);
  return trace;
}

KEMOracleTrace ExecuteSigOracle(const SigOracleExecutorConfig &config) {
  KEMOracleTrace trace;
  trace.job_id = config.job_id;
  trace.pair_id = config.pair_id;
  trace.algorithm = config.algorithm;
  trace.oracle_id = config.oracle_id;

  const bool is_slh = config.is_slh_dsa || config.oracle_id.rfind("slhdsa_", 0) == 0;
  const std::string local_oracle = is_slh ? "slhdsa_local_sign_verify" : "mldsa_local_sign_verify";
  const std::string cross_oracle = is_slh ? "slhdsa_cross_verify" : "mldsa_cross_verify";
  const std::string mutated_signature_oracle =
      is_slh ? "slhdsa_mutated_signature_negative" : "mldsa_mutated_signature_negative";
  const std::string mutated_message_oracle =
      is_slh ? "slhdsa_mutated_message_negative" : "mldsa_mutated_message_negative";
  const std::string mutated_context_oracle =
      is_slh ? "slhdsa_mutated_context_negative" : "mldsa_mutated_context_negative";
  const std::string oid_oracle = "mldsa_oid_field_mutation_sanity";
  const std::string local_trace_oracle =
      (config.oracle_id.find("_bad_randomness_sanity") != std::string::npos) ? config.oracle_id : local_oracle;

  if (config.oracle_id == cross_oracle) {
    if (config.exchange_contract.public_key_exchange && config.exchange_contract.signature_exchange) {
      trace.subtests.push_back(SigCrossVerify(
          "left_keygen_left_sign_right_verify", cross_oracle, "left", config.left, "right", config.right, config.message, config.context));
      trace.subtests.push_back(SigCrossVerify(
          "right_keygen_right_sign_left_verify", cross_oracle, "right", config.right, "left", config.left, config.message, config.context));
    }
  } else if (config.oracle_id == mutated_signature_oracle) {
    trace.subtests.push_back(SigNegative(config, "mutated_signature_negative", config.oracle_id, &trace.mutations, true, false, false, false));
  } else if (config.oracle_id == mutated_message_oracle) {
    trace.subtests.push_back(SigNegative(config, "mutated_message_negative", config.oracle_id, &trace.mutations, false, true, false, false));
  } else if (config.oracle_id == mutated_context_oracle) {
    trace.subtests.push_back(SigNegative(config, "mutated_context_negative", config.oracle_id, &trace.mutations, false, false, true, false));
  } else if (!is_slh && config.oracle_id == oid_oracle) {
    trace.subtests.push_back(SigNegative(config, "oid_field_mutation_sanity", config.oracle_id, &trace.mutations, false, false, false, true));
  } else {
    trace.subtests.push_back(SigLocalSignVerify(
        "left_keygen_left_sign_left_verify", local_trace_oracle, "left", config.left, config.message, config.context));
    trace.subtests.push_back(SigLocalSignVerify(
        "right_keygen_right_sign_right_verify", local_trace_oracle, "right", config.right, config.message, config.context));
  }

  for (const auto &mutation : trace.mutations) {
    if (!mutation.target.empty()) {
      trace.mutation_target = mutation.target;
      break;
    }
  }
  if (!trace.subtests.empty()) {
    const auto &subtest = trace.subtests.front();
    if (!subtest.calls.empty()) {
      trace.left_status = subtest.calls.front().status;
      trace.right_status = subtest.calls.back().status;
      trace.has_verify_result = subtest.calls.back().api == "verify";
      trace.verify_result = subtest.calls.back().status == PQCFUZZ_OK;
      trace.legal_negative_outcome = subtest.passed && config.oracle_id.find("_negative") != std::string::npos;
    }
  }
  AddSigFindingsForFailures(&trace);
  return trace;
}

std::string TraceToJson(const KEMOracleTrace &trace) {
  std::ostringstream out;
  out << "{\n";
  out << "  \"version\": 1,\n";
  out << "  \"oracle_suite\": \"" << JsonEscape(trace.oracle_suite) << "\",\n";
  out << "  \"relation_mode\": \"" << JsonEscape(trace.relation_mode) << "\",\n";
  out << "  \"job_id\": \"" << JsonEscape(trace.job_id) << "\",\n";
  out << "  \"pair_id\": \"" << JsonEscape(trace.pair_id) << "\",\n";
  out << "  \"algorithm\": \"" << JsonEscape(trace.algorithm) << "\",\n";
  out << "  \"oracle_id\": \"" << JsonEscape(trace.oracle_id) << "\",\n";
  if (!trace.field.empty()) {
    out << "  \"field\": \"" << JsonEscape(trace.field) << "\",\n";
  }
  if (!trace.expected_relation.empty()) {
    out << "  \"expected_relation\": \"" << JsonEscape(trace.expected_relation) << "\",\n";
  }
  if (!trace.observed_relation.empty()) {
    out << "  \"observed_relation\": \"" << JsonEscape(trace.observed_relation) << "\",\n";
  }
  if (!trace.finding_class.empty()) {
    out << "  \"finding_class\": \"" << JsonEscape(trace.finding_class) << "\",\n";
  }
  if (!trace.finding_subclass.empty()) {
    out << "  \"finding_subclass\": \"" << JsonEscape(trace.finding_subclass) << "\",\n";
  }
  out << "  \"mutation_target\": \"" << JsonEscape(trace.mutation_target) << "\",\n";
  out << "  \"left_status\": \"" << pqcfuzz_status_to_string(trace.left_status) << "\",\n";
  out << "  \"right_status\": \"" << pqcfuzz_status_to_string(trace.right_status) << "\",\n";
  out << "  \"verify_result\": " << (trace.verify_result ? "true" : "false") << ",\n";
  out << "  \"legal_negative_outcome\": " << (trace.legal_negative_outcome ? "true" : "false") << ",\n";
  if (!trace.baseline.output_sha256.empty() || trace.baseline.has_bool ||
      trace.baseline.status != PQCFUZZ_INVALID_INPUT) {
    out << "  \"baseline\": {\"status\":\"" << pqcfuzz_status_to_string(trace.baseline.status) << "\"";
    if (trace.baseline.has_bool) {
      out << ",\"accepted\":" << (trace.baseline.bool_value ? "true" : "false");
    }
    if (!trace.baseline.output_sha256.empty()) {
      out << ",\"output_sha256\":\"" << JsonEscape(trace.baseline.output_sha256) << "\"";
      out << ",\"output_size\":" << trace.baseline.output_size;
    }
    out << "},\n";
  }
  if (!trace.mutated.output_sha256.empty() || trace.mutated.has_bool ||
      trace.mutated.status != PQCFUZZ_INVALID_INPUT) {
    out << "  \"mutated\": {\"status\":\"" << pqcfuzz_status_to_string(trace.mutated.status) << "\"";
    if (trace.mutated.has_bool) {
      out << ",\"accepted\":" << (trace.mutated.bool_value ? "true" : "false");
    }
    if (!trace.mutated.output_sha256.empty()) {
      out << ",\"output_sha256\":\"" << JsonEscape(trace.mutated.output_sha256) << "\"";
      out << ",\"output_size\":" << trace.mutated.output_size;
    }
    out << "},\n";
  }
  out << "  \"subtests\": [\n";
  for (size_t i = 0; i < trace.subtests.size(); ++i) {
    const auto &subtest = trace.subtests[i];
    out << "    {\n";
    out << "      \"subtest_id\": \"" << JsonEscape(subtest.subtest_id) << "\",\n";
    out << "      \"oracle_id\": \"" << JsonEscape(subtest.oracle_id) << "\",\n";
    out << "      \"expected_relation\": \"" << JsonEscape(subtest.expected_relation) << "\",\n";
    out << "      \"passed\": " << (subtest.passed ? "true" : "false") << ",\n";
    out << "      \"skipped\": " << (subtest.skipped ? "true" : "false") << ",\n";
    out << "      \"note\": \"" << JsonEscape(subtest.note) << "\",\n";
    out << "      \"calls\": [";
    for (size_t j = 0; j < subtest.calls.size(); ++j) {
      const auto &call = subtest.calls[j];
      if (j != 0) {
        out << ", ";
      }
      out << "{\"adapter\":\"" << JsonEscape(call.adapter) << "\",\"api\":\"" << JsonEscape(call.api)
          << "\",\"status\":\"" << pqcfuzz_status_to_string(call.status) << "\"";
      if (call.has_bool_result) {
        out << ",\"accepted\":" << (call.bool_result ? "true" : "false");
      }
      out << "}";
    }
    out << "]\n";
    out << "    }" << (i + 1 == trace.subtests.size() ? "\n" : ",\n");
  }
  out << "  ],\n";
  out << "  \"mutations\": [\n";
  for (size_t i = 0; i < trace.mutations.size(); ++i) {
    const auto &mutation = trace.mutations[i];
    out << "    {\"operation\":\"" << JsonEscape(mutation.operation) << "\",\"target\":\""
        << JsonEscape(mutation.target) << "\",\"offset\":" << mutation.offset << ",\"length\":"
        << mutation.length << ",\"skipped\":" << (mutation.skipped ? "true" : "false")
        << ",\"reason\":\"" << JsonEscape(mutation.reason) << "\",\"field_parse_status\":\""
        << JsonEscape(mutation.field_parse_status) << "\"}"
        << (i + 1 == trace.mutations.size() ? "\n" : ",\n");
  }
  out << "  ],\n";
  out << "  \"findings\": [\n";
  for (size_t i = 0; i < trace.findings.size(); ++i) {
    const auto &finding = trace.findings[i];
    out << "    {\"class\":\"" << JsonEscape(finding.finding_class) << "\"";
    if (!finding.finding_subclass.empty()) {
      out << ",\"subclass\":\"" << JsonEscape(finding.finding_subclass) << "\"";
    }
    out << ",\"summary\":\"" << JsonEscape(finding.summary) << "\"}"
        << (i + 1 == trace.findings.size() ? "\n" : ",\n");
  }
  out << "  ]\n";
  out << "}\n";
  return out.str();
}

}  // namespace pqcfuzz

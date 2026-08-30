#include "oracles/oracle_executor.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "adapters/pqmagic/sig_adapter.h"
#include "adapters/rng_control.h"
#include "adapters/status.h"
#include "mutators/aigis_enc_mutator.h"
#include "mutators/aigis_sig_mutator.h"
#include "mutators/ml_dsa_mutator.h"
#include "mutators/slh_dsa_mutator.h"
#include "oracles/metamorphic_observation.h"

namespace pqcfuzz {
namespace {

std::string JsonEscape(const std::string &value) {
  std::ostringstream out;
  for (unsigned char ch : value) {
    switch (ch) {
      case '\\':
        out << "\\\\";
        break;
      case '"':
        out << "\\\"";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
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
        if (ch < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(ch) << std::dec;
        } else {
          out << static_cast<char>(ch);
        }
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
  // Precise adapter/target instrumentation is introduced in P0-04.  These
  // fields preserve the v2 executor's observable call boundary meanwhile.
  call.adapter_entered = status != PQCFUZZ_API_UNSUPPORTED;
  call.target_entered = status != PQCFUZZ_API_UNSUPPORTED;
  call.target_returned = status != PQCFUZZ_CRASH && status != PQCFUZZ_TIMEOUT;
  call.rejection_layer = status == PQCFUZZ_REJECT ? "target" : "";
  return call;
}

void AddCall(OracleSubtestTrace *subtest, const std::string &adapter, const std::string &api, pqcfuzz_status status) {
  subtest->calls.push_back(MakeCallTrace(adapter, api, status, false, false));
}

void AddExecutorRejection(OracleSubtestTrace *subtest, const std::string &adapter, const std::string &api, pqcfuzz_status status) {
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
    AddExecutorRejection(subtest, label, "encaps", out.status);
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
    AddExecutorRejection(subtest, label, "decaps", out.status);
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

std::vector<uint8_t> MakeRandomnessTape(const std::vector<uint8_t> &seed, const std::string &label) {
  std::vector<uint8_t> tape(256);
  uint32_t label_hash = 2166136261u;
  for (unsigned char byte : label) {
    label_hash ^= byte;
    label_hash *= 16777619u;
  }
  for (size_t i = 0; i < tape.size(); ++i) {
    const uint8_t seed_byte = seed.empty() ? static_cast<uint8_t>(i * 17u) : seed[i % seed.size()];
    const uint8_t label_byte = label.empty() ? 0x5a : static_cast<uint8_t>(label[i % label.size()]);
    const uint8_t hash_byte = static_cast<uint8_t>(label_hash >> ((i % 4u) * 8u));
    tape[i] = static_cast<uint8_t>(seed_byte ^ label_byte ^ hash_byte ^ (i * 29u));
  }
  return tape;
}

OracleSubtestTrace KemRandomnessSanity(
    const OracleExecutorConfig &config,
    RngInterventionTrace *rng_trace) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = "randomness_sanity";
  subtest.oracle_id = config.oracle_id;
  subtest.expected_relation = "DISTINCT_CIPHERTEXT_OR_SHARED_SECRET";
  KEMKeyPair keypair = Keygen(config.left, "left", &subtest);
  if (keypair.status == PQCFUZZ_API_UNSUPPORTED) {
    subtest.skipped = true;
    subtest.note = "adapter API unsupported";
    return subtest;
  }
  if (keypair.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct keypair before randomness control";
    return subtest;
  }
  const std::string baseline_label = config.oracle_id + "-encaps-baseline";
  const std::string mutated_label = config.oracle_id + "-encaps-mutated";
  const auto baseline_tape = MakeRandomnessTape(config.seed, baseline_label);
  const auto mutated_tape = MakeRandomnessTape(config.seed, mutated_label);
  rng_trace->baseline_tape_id = baseline_label;
  rng_trace->mutated_tape_id = mutated_label;
  rng_trace->baseline_tape_sha256 = Sha256Hex(baseline_tape);
  rng_trace->mutated_tape_sha256 = Sha256Hex(mutated_tape);
  rng_trace->tapes_distinct = baseline_tape != mutated_tape;
  KEMSharedSecret baseline_ss;
  KEMSharedSecret mutated_ss;
  KEMCiphertext baseline_ct;
  KEMCiphertext mutated_ct;
  {
    ScopedRngOverride rng({baseline_tape.data(), baseline_tape.size(), false});
    rng_trace->baseline_override_active = rng.active();
    baseline_ct = Encaps(config.left, "left", keypair.pk, &subtest, &baseline_ss);
    rng_trace->baseline_bytes_consumed = rng.bytes_consumed();
  }
  {
    ScopedRngOverride rng({mutated_tape.data(), mutated_tape.size(), false});
    rng_trace->mutated_override_active = rng.active();
    mutated_ct = Encaps(config.left, "left", keypair.pk, &subtest, &mutated_ss);
    rng_trace->mutated_bytes_consumed = rng.bytes_consumed();
  }
  if (!rng_trace->tapes_distinct || !rng_trace->baseline_override_active || !rng_trace->mutated_override_active ||
      rng_trace->baseline_bytes_consumed == 0 || rng_trace->mutated_bytes_consumed == 0) {
    subtest.skipped = true;
    subtest.note = "randomness intervention was not observed";
    return subtest;
  }
  if (baseline_ct.status != PQCFUZZ_OK || mutated_ct.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "encapsulation failed under randomness control";
    return subtest;
  }
  subtest.passed = baseline_ct.ct != mutated_ct.ct || baseline_ss.ss != mutated_ss.ss;
  if (!subtest.passed) {
    subtest.note = "distinct randomness produced identical encapsulation outputs";
  }
  return subtest;
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
    const std::string &oracle_id,
    const std::string &adapter_label,
    const pqcfuzz_kem_adapter *adapter) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = subtest_id;
  subtest.oracle_id = oracle_id;
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
    const std::string &oracle_id,
    const std::string &keygen_label,
    const pqcfuzz_kem_adapter *keygen_adapter,
    const std::string &encaps_label,
    const pqcfuzz_kem_adapter *encaps_adapter) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = subtest_id;
  subtest.oracle_id = oracle_id;
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
    const std::string &oracle_id,
    const std::string &source_label,
    const pqcfuzz_kem_adapter *source_adapter,
    const std::string &decaps_label,
    const pqcfuzz_kem_adapter *decaps_adapter) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = subtest_id;
  subtest.oracle_id = oracle_id;
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
  const bool ineffective = !records.empty() &&
      std::any_of(records.begin(), records.end(), [](const MutationRecord &record) { return !record.effective; });
  if (ineffective) {
    subtest.passed = true;
    subtest.skipped = true;
    subtest.note = "no_effect";
    return subtest;
  }
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

OracleSubtestTrace AigisTamperedCiphertext(
    const OracleExecutorConfig &config,
    std::vector<MutationRecord> *mutations) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = "tampered_ciphertext_negative";
  subtest.oracle_id = "aigisenc_tampered_ciphertext_implicit_rejection";
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
  auto records = MutateAigisEncCiphertext(config.aigis_params, config.mutation, &mutated);
  mutations->insert(mutations->end(), records.begin(), records.end());
  const bool ineffective = !records.empty() &&
      std::any_of(records.begin(), records.end(), [](const MutationRecord &record) { return !record.effective; });
  if (ineffective) {
    subtest.passed = true;
    subtest.skipped = true;
    subtest.note = "no_effect";
    return subtest;
  }
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

OracleSubtestTrace AigisEncSkNoncanonicalCoefficient(
    const OracleExecutorConfig &config,
    std::vector<MutationRecord> *mutations) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = "sk_noncanonical_coefficient";
  subtest.oracle_id = "aigisenc_sk_noncanonical_coefficient";
  // Hardened parser profile expectation: a secret key whose first s-vector
  // coefficient encodes q = 7681 (non-canonical) must be rejected before
  // decapsulation.  The supplied PQMagic snapshot has no such check.
  subtest.expected_relation = "REJECT_OR_INVALID_INPUT";
  KEMKeyPair keypair = Keygen(config.left, "left", &subtest);
  KEMSharedSecret encaps_ss;
  KEMCiphertext ciphertext;
  if (keypair.status == PQCFUZZ_OK) {
    ciphertext = Encaps(config.left, "left", keypair.pk, &subtest, &encaps_ss);
  }
  if (ciphertext.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct baseline encapsulation";
    return subtest;
  }

  std::vector<uint8_t> mutated_sk = keypair.sk;
  auto records = MutateAigisEncSkNoncanonicalCoefficient(config.aigis_params, &mutated_sk);
  mutations->insert(mutations->end(), records.begin(), records.end());
  const bool ineffective = !records.empty() &&
      std::any_of(records.begin(), records.end(), [](const MutationRecord &record) { return !record.effective; });
  if (ineffective) {
    subtest.passed = true;
    subtest.skipped = true;
    subtest.note = "no_effect";
    return subtest;
  }
  KEMSharedSecret decaps_ss = Decaps(config.left, "left", ciphertext.ct, mutated_sk, &subtest);
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
  // IMPLEMENTATION_OBSERVED (DeepSeek oracle doc 33.4): the implementation
  // accepts the non-canonical secret-key encoding and decapsulates normally.
  // HARDENING_GAP: a hardened parser profile should decode-error or enforce
  // exact re-encoding.  INCONCLUSIVE as a standards verdict.
  subtest.passed = false;
  subtest.note = "non-canonical secret-key coefficient accepted and decapsulation proceeded";
  return subtest;
}

void AddFindingsForFailures(KEMOracleTrace *trace) {
  for (const auto &subtest : trace->subtests) {
    for (const auto &call : subtest.calls) {
      if (call.status == PQCFUZZ_CRASH) {
        trace->findings.push_back({"memory_safety", "", "adapter call crashed", EvidenceKind::kProcess});
      } else if (call.status == PQCFUZZ_TIMEOUT) {
        trace->findings.push_back({"timeout", "", "adapter call timed out", EvidenceKind::kProcess});
      }
    }
    if (subtest.passed) {
      continue;
    }
    std::string finding_class = "confirmed_semantic_bug";
    std::string finding_subclass;
    if (subtest.oracle_id == "mlkem_tampered_ciphertext_implicit_rejection" ||
        subtest.oracle_id == "aigisenc_tampered_ciphertext_implicit_rejection" ||
        subtest.oracle_id == "aigisenc_sk_noncanonical_coefficient") {
      finding_class = "potential_crypto_vuln";
    }
    if (subtest.oracle_id == "aigisenc_sk_noncanonical_coefficient") {
      finding_subclass = "noncanonical_secret_key_accepted";
    }
    trace->findings.push_back({finding_class, finding_subclass, subtest.note});
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
    AddExecutorRejection(subtest, label, "sign", out.status);
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
    AddExecutorRejection(subtest, label, "verify", out.status);
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

OracleSubtestTrace SigRandomnessSanity(
    const SigOracleExecutorConfig &config,
    RngInterventionTrace *rng_trace) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = "randomness_sanity";
  subtest.oracle_id = config.oracle_id;
  subtest.expected_relation = "DISTINCT_SIGNATURE";
  if (config.left != nullptr && config.left->supports_deterministic_sign && !config.left->supports_seeded_sign) {
    subtest.skipped = true;
    subtest.note = "deterministic signing has no randomness control";
    return subtest;
  }
  SIGKeyPair keypair = SigKeygen(config.left, "left", &subtest);
  if (keypair.status == PQCFUZZ_API_UNSUPPORTED) {
    subtest.skipped = true;
    subtest.note = "adapter API unsupported";
    return subtest;
  }
  if (keypair.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct keypair before randomness control";
    return subtest;
  }
  const std::string baseline_label = config.oracle_id + "-sign-baseline";
  const std::string mutated_label = config.oracle_id + "-sign-mutated";
  const auto baseline_tape = MakeRandomnessTape(config.seed, baseline_label);
  const auto mutated_tape = MakeRandomnessTape(config.seed, mutated_label);
  rng_trace->baseline_tape_id = baseline_label;
  rng_trace->mutated_tape_id = mutated_label;
  rng_trace->baseline_tape_sha256 = Sha256Hex(baseline_tape);
  rng_trace->mutated_tape_sha256 = Sha256Hex(mutated_tape);
  rng_trace->tapes_distinct = baseline_tape != mutated_tape;
  SIGSignature baseline;
  SIGSignature mutated;
  {
    ScopedRngOverride rng({baseline_tape.data(), baseline_tape.size(), false});
    rng_trace->baseline_override_active = rng.active();
    baseline = SigSign(config.left, "left", config.message, config.context, keypair.sk, &subtest);
    rng_trace->baseline_bytes_consumed = rng.bytes_consumed();
  }
  {
    ScopedRngOverride rng({mutated_tape.data(), mutated_tape.size(), false});
    rng_trace->mutated_override_active = rng.active();
    mutated = SigSign(config.left, "left", config.message, config.context, keypair.sk, &subtest);
    rng_trace->mutated_bytes_consumed = rng.bytes_consumed();
  }
  if (!rng_trace->tapes_distinct || !rng_trace->baseline_override_active || !rng_trace->mutated_override_active ||
      rng_trace->baseline_bytes_consumed == 0 || rng_trace->mutated_bytes_consumed == 0) {
    subtest.skipped = true;
    subtest.note = "randomness intervention was not observed";
    return subtest;
  }
  if (baseline.status != PQCFUZZ_OK || mutated.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "signing failed under randomness control";
    return subtest;
  }
  subtest.passed = baseline.sig != mutated.sig;
  if (!subtest.passed) {
    subtest.note = "distinct randomness produced identical signatures";
  }
  return subtest;
}

void SetRandomnessTraceReachability(KEMOracleTrace *trace) {
  if (trace == nullptr || trace->subtests.empty() || trace->rng_interventions.empty()) {
    return;
  }
  const OracleSubtestTrace &subtest = trace->subtests.front();
  const RngInterventionTrace &rng = trace->rng_interventions.front();
  const bool calls_succeeded = !subtest.calls.empty() &&
      std::all_of(subtest.calls.begin(), subtest.calls.end(), [](const OracleCallTrace &call) {
        return call.status == PQCFUZZ_OK;
      });
  const bool observed = rng.tapes_distinct && rng.baseline_override_active && rng.mutated_override_active &&
      rng.baseline_bytes_consumed > 0 && rng.mutated_bytes_consumed > 0;
  trace->valid_setup = calls_succeeded;
  trace->baseline_setup_valid = calls_succeeded;
  trace->mutated_setup_valid = calls_succeeded;
  trace->intervention_supported = observed;
  trace->intervention_effective = observed;
  trace->relation_evaluable = calls_succeeded && observed && !subtest.skipped;
  if (subtest.skipped) {
    trace->diagnostic_event = subtest.note;
  }
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
  const size_t mutations_before = mutations == nullptr ? 0 : mutations->size();
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
      std::vector<uint8_t> planned_signature(
          config.is_slh_dsa ? config.slh_params.sig_max_len
          : config.is_aigis_sig ? config.aigis_sig_params.sig_max_len
          : config.params.sig_max_len);
      auto records = config.is_aigis_sig
          ? MutateAigisSigSignature(config.aigis_sig_params, config.mutation, &planned_signature)
          : config.is_slh_dsa
          ? MutateSlhDsaSignature(config.slh_params, config.mutation, &planned_signature)
          : MutateMlDsaSignature(config.params, config.mutation, &planned_signature);
      mutations->insert(mutations->end(), records.begin(), records.end());
    } else if (mutate_message) {
      auto records = config.is_aigis_sig
          ? MutateAigisSigMessage(config.mutation, &message)
          : config.is_slh_dsa ? MutateSlhDsaMessage(config.mutation, &message)
                              : MutateMlDsaMessage(config.mutation, &message);
      mutations->insert(mutations->end(), records.begin(), records.end());
    } else if (mutate_context) {
      auto records = config.is_aigis_sig
          ? MutateAigisSigContext(config.mutation, &context)
          : config.is_slh_dsa ? MutateSlhDsaContext(config.mutation, &context)
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
    auto records = config.is_aigis_sig
        ? MutateAigisSigSignature(config.aigis_sig_params, config.mutation, &signature.sig)
        : config.is_slh_dsa
        ? MutateSlhDsaSignature(config.slh_params, config.mutation, &signature.sig)
        : MutateMlDsaSignature(config.params, config.mutation, &signature.sig);
    mutations->insert(mutations->end(), records.begin(), records.end());
  }
  if (mutate_message) {
    auto records = config.is_aigis_sig
        ? MutateAigisSigMessage(config.mutation, &message)
        : config.is_slh_dsa ? MutateSlhDsaMessage(config.mutation, &message)
                            : MutateMlDsaMessage(config.mutation, &message);
    mutations->insert(mutations->end(), records.begin(), records.end());
  }
  if (mutate_context) {
    auto records = config.is_aigis_sig
        ? MutateAigisSigContext(config.mutation, &context)
        : config.is_slh_dsa ? MutateSlhDsaContext(config.mutation, &context)
                            : MutateMlDsaContext(config.mutation, &context);
    mutations->insert(mutations->end(), records.begin(), records.end());
  }
  if (mutate_oid) {
    auto records = MutateMlDsaOid(config.mutation, &oid);
    mutations->insert(mutations->end(), records.begin(), records.end());
    context.insert(context.end(), oid.begin(), oid.end());
  }

  SIGVerifyResult verify_result = SigVerify(config.left, "left", signature.sig, message, context, keypair.pk, &subtest);
  if (mutations != nullptr) {
    bool any_ineffective = false;
    for (size_t i = mutations_before; i < mutations->size(); ++i) {
      if (!(*mutations)[i].effective) {
        any_ineffective = true;
        break;
      }
    }
    if (any_ineffective) {
      subtest.passed = true;
      subtest.skipped = true;
      subtest.note = "no_effect";
      return subtest;
    }
  }
  const bool allow_api_unsupported = (mutate_context || mutate_oid) && config.left != nullptr && config.left->supports_context == 0;
  subtest.passed = LegalNegativeStatus(verify_result.status, allow_api_unsupported);
  if (!subtest.passed) {
    subtest.note = config.is_aigis_sig ? "mutated AIGIS-SIG input verified or produced an illegal status"
        : config.is_slh_dsa ? "mutated SLH-DSA input verified or produced an illegal status"
                            : "mutated ML-DSA input verified or produced an illegal status";
  }
  return subtest;
}

OracleSubtestTrace AigisSigExactLength(
    const SigOracleExecutorConfig &config,
    std::vector<MutationRecord> *mutations) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = "exact_length_negative";
  subtest.oracle_id = "aigissig_exact_length";
  // Hardened canonical profile expectation (DeepSeek doc 34.2, AS-SIG-EXACT-LEN):
  // the verifier shall require siglen == CRYPTO_BYTES and reject appended bytes.
  subtest.expected_relation = "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT";
  SIGKeyPair keypair = SigKeygen(config.left, "left", &subtest);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = SigSign(config.left, "left", config.message, config.context, keypair.sk, &subtest);
  }
  if (signature.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct valid signature before mutation";
    return subtest;
  }

  std::vector<uint8_t> extended = signature.sig;
  const std::vector<uint8_t> original = extended;
  extended.push_back(0xA5);
  MutationRecord record;
  record.operation = "append_byte";
  record.target = "signature";
  record.offset = original.size();
  record.length = 1;
  RecordMutationEffect(&record, original, extended);
  mutations->push_back(record);
  if (!record.effective) {
    subtest.passed = true;
    subtest.skipped = true;
    subtest.note = "no_effect";
    return subtest;
  }

  // Bypass the executor-level sig_max_len guard so the adapter receives the
  // oversized signature exactly as an external caller would.
  pqcfuzz_status status = PQCFUZZ_API_UNSUPPORTED;
  if (config.left != nullptr && config.left->verify != nullptr) {
    const uint8_t *ctx = config.context.empty() ? nullptr : config.context.data();
    status = config.left->verify(extended.data(), extended.size(), config.message.data(),
                                 config.message.size(), keypair.pk.data(), ctx, config.context.size());
  }
  AddBoolCall(&subtest, "left", "verify", status, status == PQCFUZZ_OK);
  subtest.passed = status == PQCFUZZ_REJECT || status == PQCFUZZ_INVALID_INPUT;
  if (!subtest.passed) {
    // IMPLEMENTATION_OBSERVED + HARDENING_GAP (doc 34.2): the snapshot's
    // verifier checks only siglen < CRYPTO_BYTES and accepts appended bytes.
    subtest.note = "appended signature byte accepted by verifier";
  }
  return subtest;
}

OracleSubtestTrace AigisSigUnusedSignBits(
    const SigOracleExecutorConfig &config,
    std::vector<MutationRecord> *mutations) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = "unused_sign_bits_negative";
  subtest.oracle_id = "aigissig_unused_sign_bits";
  // Hardened canonical profile expectation (doc 34.3, AS-SIG-UNUSED-SIGNBITS):
  // unused challenge sign bits must be zero or rejected.
  subtest.expected_relation = "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT";
  SIGKeyPair keypair = SigKeygen(config.left, "left", &subtest);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = SigSign(config.left, "left", config.message, config.context, keypair.sk, &subtest);
  }
  if (signature.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct valid signature before mutation";
    return subtest;
  }
  if (signature.sig.size() != config.aigis_sig_params.sig_max_len) {
    subtest.passed = false;
    subtest.note = "signature length does not match AIGIS-SIG profile";
    return subtest;
  }

  std::vector<uint8_t> mutated = signature.sig;
  const std::vector<uint8_t> original = mutated;
  // The eighth sign byte is the last byte of the challenge region; the top
  // four bits are unconsumed by unpack_sig (60 nonzero challenge coefficients).
  const size_t offset = config.aigis_sig_params.z_bytes + config.aigis_sig_params.hint_bytes +
      config.aigis_sig_params.c_bytes - 1;
  mutated[offset] |= 0x80;
  MutationRecord record;
  record.operation = "mutate_unused_sign_bits";
  record.target = "signature.c";
  record.offset = offset;
  record.length = 1;
  RecordMutationEffect(&record, original, mutated);
  mutations->push_back(record);
  if (!record.effective) {
    subtest.passed = true;
    subtest.skipped = true;
    subtest.note = "no_effect";
    return subtest;
  }

  SIGVerifyResult verify_result = SigVerify(config.left, "left", mutated, config.message, config.context, keypair.pk, &subtest);
  subtest.passed = verify_result.status == PQCFUZZ_REJECT || verify_result.status == PQCFUZZ_INVALID_INPUT;
  if (!subtest.passed) {
    // IMPLEMENTATION_OBSERVED + HARDENING_GAP (doc 34.3).
    subtest.note = "unused challenge sign bit accepted by verifier";
  }
  return subtest;
}

OracleSubtestTrace AigisSigCtx256FailureState(
    const SigOracleExecutorConfig &config,
    std::vector<MutationRecord> *mutations) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = "ctx256_failure_state";
  subtest.oracle_id = "aigissig_ctx256_failure_state";
  subtest.expected_relation = "REJECT_WITH_CONSISTENT_OUTPUT_LENGTH_STATE";
  SIGKeyPair keypair = SigKeygen(config.left, "left", &subtest);
  if (keypair.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct keypair";
    return subtest;
  }
  std::vector<uint8_t> ctx256(256, 0xCC);

  // Detached signer: must reject ctx_len > 255 and leave the caller-provided
  // siglen sentinel unchanged.
  std::vector<uint8_t> detached_sig(config.aigis_sig_params.sig_max_len, 0xA5);
  const std::vector<uint8_t> detached_original = detached_sig;
  size_t detached_sig_len = 0x12345678;
  pqcfuzz_status detached_status = PQCFUZZ_API_UNSUPPORTED;
  if (config.left != nullptr && config.left->sign != nullptr) {
    detached_status = config.left->sign(detached_sig.data(), &detached_sig_len, config.message.data(),
                                        config.message.size(), keypair.sk.data(), ctx256.data(), ctx256.size());
  }
  AddCall(&subtest, "left", "sign", detached_status);
  MutationRecord record;
  record.operation = "ctx_len_256_detached";
  record.target = "ctx";
  record.offset = 0;
  record.length = ctx256.size();
  RecordMutationEffect(&record, config.context, ctx256);
  mutations->push_back(record);
  const bool detached_conformant = detached_status == PQCFUZZ_REJECT &&
      detached_sig_len == 0x12345678 && detached_sig == detached_original;

  // Combined wrapper: pqmagic crypto_sign unconditionally executes
  // *smlen += mlen even when the detached signer failed (doc 34.5).
  const size_t sm_cap = config.aigis_sig_params.sig_max_len + config.message.size();
  std::vector<uint8_t> sm(sm_cap, 0xA5);
  size_t smlen = 0x12345678;
  int combined_rc = -1;
  if (config.left != nullptr) {
    combined_rc = pqcfuzz_pqmagic_sig_combined_sign(
        config.left->implementation_id, sm.data(), &smlen, config.message.data(),
        config.message.size(), ctx256.data(), ctx256.size(), keypair.sk.data());
  }
  pqcfuzz_status combined_status = pqcfuzz_normalize_return_code(combined_rc);
  AddCall(&subtest, "left", "combined_sign", combined_status);
  const bool combined_length_corrupted = combined_status == PQCFUZZ_REJECT &&
      smlen == 0x12345678 + config.message.size();

  subtest.passed = detached_conformant && !combined_length_corrupted;
  if (!subtest.passed) {
    if (!detached_conformant) {
      subtest.note = "detached sign failure state inconsistent (ctx_len 256)";
    } else {
      // IMPLEMENTATION_OBSERVED + HARDENING_GAP (doc 34.5, AS-SIG-CTX256-*):
      // failed combined signing still reports smlen including the message.
      subtest.note = "combined sign failure updates output length despite failure";
    }
  }
  return subtest;
}

OracleSubtestTrace AigisSigDeterminismProfile(
    const SigOracleExecutorConfig &config,
    std::vector<MutationRecord> *mutations) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = "determinism_profile";
  subtest.oracle_id = "aigissig_determinism_profile";
  subtest.expected_relation = "IDENTICAL_SIGNATURES";
  SIGKeyPair keypair = SigKeygen(config.left, "left", &subtest);
  SIGSignature first;
  SIGSignature second;
  if (keypair.status == PQCFUZZ_OK) {
    first = SigSign(config.left, "left", config.message, config.context, keypair.sk, &subtest);
  }
  if (first.status == PQCFUZZ_OK) {
    second = SigSign(config.left, "left", config.message, config.context, keypair.sk, &subtest);
  }
  if (first.status != PQCFUZZ_OK || second.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not produce signatures";
    return subtest;
  }
  subtest.passed = first.sig == second.sig;
  if (!subtest.passed) {
    MutationRecord record;
    record.operation = "repeated_signing";
    record.target = "signature";
    record.offset = 0;
    record.length = first.sig.size();
    RecordMutationEffect(&record, first.sig, second.sig);
    mutations->push_back(record);
    subtest.note = "same key, message, and context produced different signatures";
  }
  return subtest;
}

void SetFipsTraceReachability(KEMOracleTrace *trace) {
  if (trace == nullptr || trace->subtests.empty()) {
    return;
  }
  const OracleSubtestTrace &first = trace->subtests.front();
  const OracleSubtestTrace &last = trace->subtests.back();
  if (!first.calls.empty()) {
    trace->baseline_adapter_entered = first.calls.front().adapter_entered;
    trace->baseline_target_entered = first.calls.front().target_entered;
  }
  if (!last.calls.empty()) {
    trace->mutated_adapter_entered = last.calls.back().adapter_entered;
    trace->mutated_target_entered = last.calls.back().target_entered;
  }
  trace->relation_evaluable = trace->baseline_target_entered && trace->mutated_target_entered;
}

void AddSigFindingsForFailures(KEMOracleTrace *trace) {
  for (const auto &subtest : trace->subtests) {
    for (const auto &call : subtest.calls) {
      if (call.status == PQCFUZZ_CRASH) {
        trace->findings.push_back({"memory_safety", "", "adapter call crashed", EvidenceKind::kProcess});
      } else if (call.status == PQCFUZZ_TIMEOUT) {
        trace->findings.push_back({"timeout", "", "adapter call timed out", EvidenceKind::kProcess});
      }
    }
    if (subtest.passed) {
      continue;
    }
    if (subtest.oracle_id.find("_mutated_signature_negative") != std::string::npos ||
        subtest.oracle_id.find("_mutated_message_negative") != std::string::npos ||
        subtest.oracle_id.find("_mutated_context_negative") != std::string::npos ||
        subtest.oracle_id == "aigissig_exact_length" ||
        subtest.oracle_id == "aigissig_unused_sign_bits" ||
        subtest.oracle_id == "aigissig_ctx256_failure_state") {
      std::string finding_subclass;
      if (subtest.oracle_id == "aigissig_exact_length") {
        finding_subclass = "appended_signature_bytes_accepted";
      } else if (subtest.oracle_id == "aigissig_unused_sign_bits") {
        finding_subclass = "unused_sign_bit_malleable";
      } else if (subtest.oracle_id == "aigissig_ctx256_failure_state") {
        finding_subclass = "failure_output_length_state_inconsistent";
      }
      trace->findings.push_back({"potential_crypto_vuln", finding_subclass, subtest.note});
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

  if (config.oracle_id == "mlkem_bad_randomness_sanity" || config.oracle_id == "aigisenc_bad_randomness_sanity") {
    RngInterventionTrace rng_trace;
    trace.subtests.push_back(KemRandomnessSanity(config, &rng_trace));
    trace.rng_interventions.push_back(std::move(rng_trace));
    SetRandomnessTraceReachability(&trace);
  } else if (config.oracle_id == "mlkem_tampered_ciphertext_implicit_rejection") {
    trace.subtests.push_back(TamperedCiphertext(config, &trace.mutations));
  } else if (config.oracle_id == "aigisenc_tampered_ciphertext_implicit_rejection") {
    trace.subtests.push_back(AigisTamperedCiphertext(config, &trace.mutations));
  } else if (config.oracle_id == "aigisenc_sk_noncanonical_coefficient") {
    trace.subtests.push_back(AigisEncSkNoncanonicalCoefficient(config, &trace.mutations));
  } else if (config.oracle_id == "mlkem_cross_exchange_roundtrip" ||
             config.oracle_id == "aigisenc_cross_exchange_roundtrip") {
    const std::string cross_oracle = config.oracle_id;
    if (config.exchange_contract.public_key_exchange && config.exchange_contract.ciphertext_exchange) {
      trace.subtests.push_back(CrossEncapsRoundtrip(
          "left_keygen_right_encaps_left_decaps", cross_oracle, "left", config.left, "right", config.right));
      trace.subtests.push_back(CrossEncapsRoundtrip(
          "right_keygen_left_encaps_right_decaps", cross_oracle, "right", config.right, "left", config.left));
    }
    if (config.exchange_contract.ciphertext_exchange && config.exchange_contract.secret_key_exchange &&
        config.exchange_contract.secret_key_format_compatible) {
      trace.subtests.push_back(CrossDecapsRoundtrip(
          "left_keygen_left_encaps_right_decaps", cross_oracle, "left", config.left, "right", config.right));
      trace.subtests.push_back(CrossDecapsRoundtrip(
          "right_keygen_right_encaps_left_decaps", cross_oracle, "right", config.right, "left", config.left));
    }
  } else {
    const std::string local_oracle = config.is_aigis_enc ? "aigisenc_local_roundtrip" : "mlkem_local_roundtrip";
    trace.subtests.push_back(LocalRoundtrip("left_keygen_left_encaps_left_decaps", local_oracle, "left", config.left));
    trace.subtests.push_back(LocalRoundtrip("right_keygen_right_encaps_right_decaps", local_oracle, "right", config.right));
  }

  AddFindingsForFailures(&trace);
  SetFipsTraceReachability(&trace);
  return trace;
}

KEMOracleTrace ExecuteSigOracle(const SigOracleExecutorConfig &config) {
  KEMOracleTrace trace;
  trace.job_id = config.job_id;
  trace.pair_id = config.pair_id;
  trace.algorithm = config.algorithm;
  trace.oracle_id = config.oracle_id;

  const bool is_slh = config.is_slh_dsa || config.oracle_id.rfind("slhdsa_", 0) == 0;
  const bool is_aigis = config.is_aigis_sig || config.oracle_id.rfind("aigissig_", 0) == 0;
  const std::string local_oracle =
      is_aigis ? "aigissig_local_sign_verify" : (is_slh ? "slhdsa_local_sign_verify" : "mldsa_local_sign_verify");
  const std::string cross_oracle =
      is_aigis ? "aigissig_cross_verify" : (is_slh ? "slhdsa_cross_verify" : "mldsa_cross_verify");
  const std::string mutated_signature_oracle =
      is_aigis ? "aigissig_mutated_signature_negative" : (is_slh ? "slhdsa_mutated_signature_negative" : "mldsa_mutated_signature_negative");
  const std::string mutated_message_oracle =
      is_aigis ? "aigissig_mutated_message_negative" : (is_slh ? "slhdsa_mutated_message_negative" : "mldsa_mutated_message_negative");
  const std::string mutated_context_oracle =
      is_aigis ? "aigissig_mutated_context_negative" : (is_slh ? "slhdsa_mutated_context_negative" : "mldsa_mutated_context_negative");
  const std::string oid_oracle = "mldsa_oid_field_mutation_sanity";
  const std::string local_trace_oracle =
      (config.oracle_id.find("_bad_randomness_sanity") != std::string::npos) ? config.oracle_id : local_oracle;

  if ((config.oracle_id == "mldsa_bad_randomness_sanity" || config.oracle_id == "aigissig_bad_randomness_sanity")) {
    RngInterventionTrace rng_trace;
    trace.subtests.push_back(SigRandomnessSanity(config, &rng_trace));
    trace.rng_interventions.push_back(std::move(rng_trace));
    SetRandomnessTraceReachability(&trace);
  } else if (is_aigis && config.oracle_id == "aigissig_exact_length") {
    trace.subtests.push_back(AigisSigExactLength(config, &trace.mutations));
  } else if (is_aigis && config.oracle_id == "aigissig_unused_sign_bits") {
    trace.subtests.push_back(AigisSigUnusedSignBits(config, &trace.mutations));
  } else if (is_aigis && config.oracle_id == "aigissig_ctx256_failure_state") {
    trace.subtests.push_back(AigisSigCtx256FailureState(config, &trace.mutations));
  } else if (is_aigis && config.oracle_id == "aigissig_determinism_profile") {
    trace.subtests.push_back(AigisSigDeterminismProfile(config, &trace.mutations));
  } else if (config.oracle_id == cross_oracle) {
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
  SetFipsTraceReachability(&trace);
  return trace;
}

std::string TraceToJson(const KEMOracleTrace &trace) {
  std::ostringstream out;
  const OracleDisposition disposition = FinalizeDisposition(trace);
  auto finding_fingerprint = [](const OracleFindingTrace &finding) {
    if (!finding.fingerprint.empty()) {
      return finding.fingerprint;
    }
    uint64_t hash = 1469598103934665603ull;
    const std::string material = std::string(EvidenceKindName(finding.evidence_kind)) + "\n" + finding.finding_class +
                                 "\n" + finding.finding_subclass + "\n" + finding.summary;
    for (unsigned char byte : material) {
      hash ^= byte;
      hash *= 1099511628211ull;
    }
    std::ostringstream fingerprint;
    fingerprint << "fnv1a64:" << std::hex << std::setw(16) << std::setfill('0') << hash;
    return fingerprint.str();
  };
  out << "{\n";
  out << "  \"version\": 4,\n";
  out << "  \"oracle_semantics_version\": 4,\n";
  out << "  \"disposition\": \"" << OracleDispositionName(disposition) << "\",\n";
  out << "  \"oracle_suite\": \"" << JsonEscape(trace.oracle_suite) << "\",\n";
  out << "  \"relation_mode\": \"" << JsonEscape(trace.relation_mode) << "\",\n";
  out << "  \"job_id\": \"" << JsonEscape(trace.job_id) << "\",\n";
  out << "  \"pair_id\": \"" << JsonEscape(trace.pair_id) << "\",\n";
  out << "  \"algorithm\": \"" << JsonEscape(trace.algorithm) << "\",\n";
  out << "  \"configured_algorithm\": \"" << JsonEscape(trace.configured_algorithm) << "\",\n";
  out << "  \"adapter_algorithm\": \"" << JsonEscape(trace.adapter_algorithm) << "\",\n";
  out << "  \"project_id\": \"" << JsonEscape(trace.project_id) << "\",\n";
  out << "  \"implementation_id\": \"" << JsonEscape(trace.implementation_id) << "\",\n";
  out << "  \"adapter_abi\": {\"pk_len\":" << trace.adapter_pk_len
      << ",\"sk_len\":" << trace.adapter_sk_len << ",\"ct_len\":" << trace.adapter_ct_len
      << ",\"ss_len\":" << trace.adapter_ss_len << ",\"sig_max_len\":" << trace.adapter_sig_max_len << "},\n";
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
  out << "  \"mutation_target\": \"" << JsonEscape(trace.mutation_target) << "\",\n";
  out << "  \"left_status\": \"" << pqcfuzz_status_to_string(trace.left_status) << "\",\n";
  out << "  \"right_status\": \"" << pqcfuzz_status_to_string(trace.right_status) << "\",\n";
  out << "  \"verify_result\": " << (trace.verify_result ? "true" : "false") << ",\n";
  out << "  \"legal_negative_outcome\": " << (trace.legal_negative_outcome ? "true" : "false") << ",\n";
  out << "  \"baseline_setup_valid\": " << (trace.baseline_setup_valid ? "true" : "false") << ",\n";
  out << "  \"mutated_setup_valid\": " << (trace.mutated_setup_valid ? "true" : "false") << ",\n";
  out << "  \"baseline_adapter_entered\": " << (trace.baseline_adapter_entered ? "true" : "false") << ",\n";
  out << "  \"baseline_target_entered\": " << (trace.baseline_target_entered ? "true" : "false") << ",\n";
  out << "  \"mutated_adapter_entered\": " << (trace.mutated_adapter_entered ? "true" : "false") << ",\n";
  out << "  \"mutated_target_entered\": " << (trace.mutated_target_entered ? "true" : "false") << ",\n";
  out << "  \"relation_evaluable\": " << (trace.relation_evaluable ? "true" : "false") << ",\n";
  out << "  \"intervention_supported\": " << (trace.intervention_supported ? "true" : "false") << ",\n";
  out << "  \"intervention_effective\": " << (trace.intervention_effective ? "true" : "false") << ",\n";
  out << "  \"diagnostics\": [\n";
  size_t diagnostic_count = trace.diagnostics.size() + (trace.diagnostic_event.empty() ? 0 : 1);
  for (size_t i = 0; i < trace.diagnostics.size(); ++i) {
    const auto &diagnostic = trace.diagnostics[i];
    out << "    {\"code\":\"" << JsonEscape(diagnostic.code) << "\",\"stage\":\""
        << JsonEscape(diagnostic.stage) << "\",\"summary\":\"" << JsonEscape(diagnostic.summary) << "\"}"
        << (i + 1 == diagnostic_count ? "\n" : ",\n");
  }
  if (!trace.diagnostic_event.empty()) {
    out << "    {\"code\":\"" << JsonEscape(trace.diagnostic_event)
        << "\",\"stage\":\"executor\",\"summary\":\"" << JsonEscape(trace.diagnostic_event) << "\"}\n";
  }
  out << "  ],\n";
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
          << "\",\"status\":\"" << pqcfuzz_status_to_string(call.status) << "\""
          << ",\"executor_dispatched\":" << (call.executor_dispatched ? "true" : "false")
          << ",\"adapter_entered\":" << (call.adapter_entered ? "true" : "false")
          << ",\"target_entered\":" << (call.target_entered ? "true" : "false")
          << ",\"target_returned\":" << (call.target_returned ? "true" : "false")
          << ",\"rejection_layer\":\"" << JsonEscape(call.rejection_layer) << "\"";
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
        << ",\"effective\":" << (mutation.effective ? "true" : "false")
        << ",\"reason\":\"" << JsonEscape(mutation.reason) << "\",\"field_parse_status\":\""
        << JsonEscape(mutation.field_parse_status) << "\",\"original_length\":" << mutation.original_length
        << ",\"mutated_length\":" << mutation.mutated_length
        << ",\"original_sha256\":\"" << JsonEscape(mutation.original_sha256)
        << "\",\"mutated_sha256\":\"" << JsonEscape(mutation.mutated_sha256) << "\"}"
        << (i + 1 == trace.mutations.size() ? "\n" : ",\n");
  }
  out << "  ],\n";
  out << "  \"rng_interventions\": [\n";
  for (size_t i = 0; i < trace.rng_interventions.size(); ++i) {
    const auto &rng = trace.rng_interventions[i];
    out << "    {\"baseline_tape_id\":\"" << JsonEscape(rng.baseline_tape_id)
        << "\",\"mutated_tape_id\":\"" << JsonEscape(rng.mutated_tape_id)
        << "\",\"baseline_tape_sha256\":\"" << JsonEscape(rng.baseline_tape_sha256)
        << "\",\"mutated_tape_sha256\":\"" << JsonEscape(rng.mutated_tape_sha256)
        << "\",\"tapes_distinct\":" << (rng.tapes_distinct ? "true" : "false")
        << ",\"baseline_override_active\":" << (rng.baseline_override_active ? "true" : "false")
        << ",\"mutated_override_active\":" << (rng.mutated_override_active ? "true" : "false")
        << ",\"baseline_bytes_consumed\":" << rng.baseline_bytes_consumed
        << ",\"mutated_bytes_consumed\":" << rng.mutated_bytes_consumed << "}"
        << (i + 1 == trace.rng_interventions.size() ? "\n" : ",\n");
  }
  out << "  ],\n";
  out << "  \"findings\": [\n";
  for (size_t i = 0; i < trace.findings.size(); ++i) {
    const auto &finding = trace.findings[i];
    out << "    {\"evidence_kind\":\"" << EvidenceKindName(finding.evidence_kind) << "\",\"class\":\""
        << JsonEscape(finding.finding_class) << "\",\"subclass\":\"" << JsonEscape(finding.finding_subclass)
        << "\",\"summary\":\"" << JsonEscape(finding.summary) << "\",\"source_phase\":\""
        << JsonEscape(finding.source_phase) << "\",\"fingerprint\":\""
        << JsonEscape(finding_fingerprint(finding)) << "\"}"
        << (i + 1 == trace.findings.size() ? "\n" : ",\n");
  }
  out << "  ]\n";
  out << "}\n";
  return out.str();
}

}  // namespace pqcfuzz

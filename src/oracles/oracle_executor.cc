#include "oracles/oracle_executor.h"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <utility>

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

constexpr size_t kFailureSentinelLength = 0x12345678u;
constexpr uint8_t kFailureSentinelFill = 0xA5;

// Runs a detached signing call under the failure-state sentinel contract
// (design doc Section 25): the caller buffer is prefilled, the output length
// carries a poison value, and the helper reports whether the target exposed
// partial output or mutated the length despite failing.
struct SignFailureSentinel {
  pqcfuzz_status status = PQCFUZZ_API_UNSUPPORTED;
  size_t signature_length = kFailureSentinelLength;
  bool buffer_unchanged = true;
};

SignFailureSentinel RunSignWithFailureSentinel(
    const pqcfuzz_sig_adapter *adapter,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &secret_key,
    const uint8_t *context,
    size_t context_len) {
  SignFailureSentinel result;
  if (adapter == nullptr || adapter->sign == nullptr) {
    return result;
  }
  std::vector<uint8_t> buffer(adapter->sig_max_len, kFailureSentinelFill);
  size_t signature_len = kFailureSentinelLength;
  result.status = adapter->sign(
      buffer.data(), &signature_len, message.data(), message.size(), secret_key.data(), context, context_len);
  result.signature_length = signature_len;
  for (uint8_t byte : buffer) {
    if (byte != kFailureSentinelFill) {
      result.buffer_unchanged = false;
      break;
    }
  }
  return result;
}

void PopulateControls(const std::string &oracle_id, KEMOracleTrace *trace) {
  if (trace == nullptr) {
    return;
  }
  if (oracle_id == "mlkem_implicit_rejection_relations" ||
      oracle_id == "aigisenc_implicit_rejection_relations") {
    trace->controls.baseline_repeat_equal = true;
    trace->controls.positive_control = "valid ciphertext decapsulates to the encapsulated secret";
    trace->controls.negative_control =
        "invalid-ciphertext fallback changes when the rejection secret changes";
  } else if (oracle_id.find("_verify_exact_lengths") != std::string::npos) {
    trace->controls.positive_control = "the exact-length signature verifies";
    trace->controls.negative_control = "each boundary mutation changes the signature length";
    trace->controls.false_positive_controls.push_back("an ineffective length mutation is recorded as no_effect");
  } else if (oracle_id.find("_ctx_boundaries") != std::string::npos) {
    trace->controls.positive_control = "valid context lengths sign and verify";
    trace->controls.negative_control = "a mismatched context does not verify";
  } else if (oracle_id.find("_hint_canonicality") != std::string::npos) {
    trace->controls.positive_control = "the unmodified signature verifies";
    trace->controls.negative_control = "each hint mutation changes the hint bytes";
  } else if (oracle_id == "mlkem_ek_canonicality") {
    trace->controls.positive_control = "the unmodified encapsulation key encapsulates";
    trace->controls.negative_control = "each mutation encodes a boundary coefficient value";
  } else if (oracle_id == "mlkem_raw_length_boundary") {
    trace->controls.positive_control = "a baseline encaps/decaps roundtrip succeeds";
    trace->controls.negative_control = "the record is not persisted as a security finding";
  }
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

using CtMutatorFn = std::vector<MutationRecord> (*)(
    const void *params, const std::vector<uint8_t> &plan, std::vector<uint8_t> *ciphertext);
using PkMutatorFn = std::vector<MutationRecord> (*)(
    const void *params, const std::vector<uint8_t> &plan, std::vector<uint8_t> *public_key);
using SigMutatorFn = std::vector<MutationRecord> (*)(
    const void *params, const std::vector<uint8_t> &plan, std::vector<uint8_t> *signature);
using BytesMutatorFn = std::vector<MutationRecord> (*)(
    const std::vector<uint8_t> &plan, std::vector<uint8_t> *buffer);

struct KemFamilyTraits {
  const char *name;
  const char *prefix;
  bool (*get_params)(const std::string &algorithm, void *params_out);
  CtMutatorFn mutate_ct;
  PkMutatorFn mutate_pk;
};

struct SigFamilyTraits {
  const char *name;
  const char *prefix;
  bool (*get_params)(const std::string &algorithm, void *params_out);
  size_t (*sig_max_len)(const void *params);
  SigMutatorFn mutate_sig;
  BytesMutatorFn mutate_msg;
  BytesMutatorFn mutate_ctx;
};

const KemFamilyTraits *KemTraitsFor(const std::string &algorithm) {
  static const KemFamilyTraits kTraits[] = {
      {"ML-KEM", "mlkem",
       [](const std::string &algorithm, void *out) {
         return GetMlKemParams(algorithm, static_cast<MlKemParams *>(out));
       },
       [](const void *params, const std::vector<uint8_t> &plan, std::vector<uint8_t> *ct) {
         return MutateMlKemCiphertext(*static_cast<const MlKemParams *>(params), plan, ct);
       },
       [](const void *params, const std::vector<uint8_t> &plan, std::vector<uint8_t> *pk) {
         return MutateMlKemPublicKey(*static_cast<const MlKemParams *>(params), plan, pk);
       }},
      {"AIGIS-ENC", "aigisenc",
       [](const std::string &algorithm, void *out) {
         return GetAigisEncParams(algorithm, static_cast<AigisEncParams *>(out));
       },
       [](const void *params, const std::vector<uint8_t> &plan, std::vector<uint8_t> *ct) {
         return MutateAigisEncCiphertext(*static_cast<const AigisEncParams *>(params), plan, ct);
       },
       [](const void *params, const std::vector<uint8_t> &plan, std::vector<uint8_t> *pk) {
         return MutateAigisEncPublicKey(*static_cast<const AigisEncParams *>(params), plan, pk);
       }},
  };
  for (const auto &traits : kTraits) {
    if (traits.get_params(algorithm, nullptr)) {
      return &traits;
    }
  }
  return nullptr;
}

const SigFamilyTraits *SigTraitsFor(const std::string &algorithm) {
  static const SigFamilyTraits kTraits[] = {
      {"ML-DSA", "mldsa",
       [](const std::string &algorithm, void *out) {
         return GetMlDsaParams(algorithm, static_cast<MlDsaParams *>(out));
       },
       [](const void *params) { return static_cast<const MlDsaParams *>(params)->sig_max_len; },
       [](const void *params, const std::vector<uint8_t> &plan, std::vector<uint8_t> *sig) {
         return MutateMlDsaSignature(*static_cast<const MlDsaParams *>(params), plan, sig);
       },
       MutateMlDsaMessage, MutateMlDsaContext},
      {"SLH-DSA", "slhdsa",
       [](const std::string &algorithm, void *out) {
         return GetSlhDsaParams(algorithm, static_cast<SlhDsaParams *>(out));
       },
       [](const void *params) { return static_cast<const SlhDsaParams *>(params)->sig_max_len; },
       [](const void *params, const std::vector<uint8_t> &plan, std::vector<uint8_t> *sig) {
         return MutateSlhDsaSignature(*static_cast<const SlhDsaParams *>(params), plan, sig);
       },
       MutateSlhDsaMessage, MutateSlhDsaContext},
      {"AIGIS-SIG", "aigissig",
       [](const std::string &algorithm, void *out) {
         return GetAigisSigParams(algorithm, static_cast<AigisSigParams *>(out));
       },
       [](const void *params) { return static_cast<const AigisSigParams *>(params)->sig_max_len; },
       [](const void *params, const std::vector<uint8_t> &plan, std::vector<uint8_t> *sig) {
         return MutateAigisSigSignature(*static_cast<const AigisSigParams *>(params), plan, sig);
       },
       MutateAigisSigMessage, MutateAigisSigContext},
  };
  for (const auto &traits : kTraits) {
    if (traits.get_params(algorithm, nullptr)) {
      return &traits;
    }
  }
  return nullptr;
}

// Specialized per-scheme probes (AIGIS doc cases).  Forward-declared here so
// the dispatch tables below can reference them.
OracleSubtestTrace AigisEncSkNoncanonicalCoefficient(
    const OracleExecutorConfig &config, std::vector<MutationRecord> *mutations);
OracleSubtestTrace AigisSigExactLength(
    const SigOracleExecutorConfig &config, std::vector<MutationRecord> *mutations);
OracleSubtestTrace AigisSigUnusedSignBits(
    const SigOracleExecutorConfig &config, std::vector<MutationRecord> *mutations);
OracleSubtestTrace AigisSigCtx256FailureState(
    const SigOracleExecutorConfig &config, std::vector<MutationRecord> *mutations);
OracleSubtestTrace AigisSigDeterminismProfile(
    const SigOracleExecutorConfig &config, std::vector<MutationRecord> *mutations);

using KemSpecialHandler = OracleSubtestTrace (*)(const OracleExecutorConfig &, std::vector<MutationRecord> *);
using SigSpecialHandler = OracleSubtestTrace (*)(const SigOracleExecutorConfig &, std::vector<MutationRecord> *);

const KemSpecialHandler *FindKemSpecialHandler(const std::string &oracle_id) {
  static const std::pair<std::string, KemSpecialHandler> kHandlers[] = {
      {"aigisenc_sk_noncanonical_coefficient", AigisEncSkNoncanonicalCoefficient},
  };
  for (const auto &entry : kHandlers) {
    if (entry.first == oracle_id) {
      return &entry.second;
    }
  }
  return nullptr;
}

const SigSpecialHandler *FindSigSpecialHandler(const std::string &oracle_id) {
  static const std::pair<std::string, SigSpecialHandler> kHandlers[] = {
      {"aigissig_exact_length", AigisSigExactLength},
      {"aigissig_unused_sign_bits", AigisSigUnusedSignBits},
      {"aigissig_ctx256_failure_state", AigisSigCtx256FailureState},
      {"aigissig_determinism_profile", AigisSigDeterminismProfile},
  };
  for (const auto &entry : kHandlers) {
    if (entry.first == oracle_id) {
      return &entry.second;
    }
  }
  return nullptr;
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

OracleSubtestTrace KemTamperedCiphertext(
    const OracleExecutorConfig &config,
    const std::string &oracle_id,
    const void *params,
    CtMutatorFn mutate_ct,
    std::vector<MutationRecord> *mutations) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = "tampered_ciphertext_negative";
  subtest.oracle_id = oracle_id;
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
  auto records = mutate_ct(params, config.mutation, &mutated);
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
  AigisEncParams aigis_params{};
  if (!GetAigisEncParams(config.algorithm, &aigis_params)) {
    subtest.passed = false;
    subtest.note = "AIGIS-ENC parameters unavailable";
    return subtest;
  }
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
  auto records = MutateAigisEncSkNoncanonicalCoefficient(aigis_params, &mutated_sk);
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

bool KemRejectionSecretRegion(const std::string &algorithm, size_t *offset, size_t *length) {
  MlKemParams mlkem{};
  if (GetMlKemParams(algorithm, &mlkem)) {
    *offset = mlkem.z_offset;
    *length = mlkem.z_len;
    return mlkem.z_len > 0;
  }
  AigisEncParams aigis{};
  if (GetAigisEncParams(algorithm, &aigis)) {
    *offset = aigis.z_offset;
    *length = aigis.z_len;
    return aigis.z_len > 0;
  }
  return false;
}

std::vector<OracleSubtestTrace> KemImplicitRejectionRelations(
    const OracleExecutorConfig &config,
    const std::string &oracle_id,
    const void *params,
    CtMutatorFn mutate_ct,
    std::vector<MutationRecord> *mutations) {
  OracleSubtestTrace stability;
  stability.subtest_id = "implicit_rejection_stability";
  stability.oracle_id = oracle_id;
  stability.expected_relation = "STABLE_FALLBACK_FOR_REPEATED_INVALID_CIPHERTEXT";

  OracleSubtestTrace z_separation;
  z_separation.subtest_id = "implicit_rejection_z_separation";
  z_separation.oracle_id = oracle_id;
  z_separation.expected_relation = "CHANGED_FALLBACK_AND_UNCHANGED_VALID_DECAPS";

  OracleSubtestTrace status_shape;
  status_shape.subtest_id = "implicit_rejection_public_status_shape";
  status_shape.oracle_id = oracle_id;
  status_shape.expected_relation = "NO_PUBLIC_REJECT_FLAG";

  KEMKeyPair keypair = Keygen(config.left, "left", &stability);
  KEMSharedSecret baseline_ss;
  KEMCiphertext ciphertext;
  if (keypair.status == PQCFUZZ_OK) {
    ciphertext = Encaps(config.left, "left", keypair.pk, &stability, &baseline_ss);
  }
  if (ciphertext.status != PQCFUZZ_OK) {
    const std::string note = IsUnsupportedOnly(stability) ? "adapter API unsupported"
                                                          : "could not construct baseline encapsulation";
    for (OracleSubtestTrace *subtest : {&stability, &z_separation, &status_shape}) {
      subtest->skipped = IsUnsupportedOnly(stability);
      subtest->passed = IsUnsupportedOnly(stability);
      subtest->note = note;
    }
    return {stability, z_separation, status_shape};
  }

  std::vector<uint8_t> mutated_ct = ciphertext.ct;
  auto ct_records = mutate_ct(params, config.mutation, &mutated_ct);
  mutations->insert(mutations->end(), ct_records.begin(), ct_records.end());
  const bool ct_ineffective = !ct_records.empty() &&
      std::any_of(ct_records.begin(), ct_records.end(), [](const MutationRecord &record) { return !record.effective; });
  if (ct_ineffective) {
    for (OracleSubtestTrace *subtest : {&stability, &z_separation, &status_shape}) {
      subtest->passed = true;
      subtest->skipped = true;
      subtest->note = "no_effect";
    }
    return {stability, z_separation, status_shape};
  }

  KEMSharedSecret first_bad = Decaps(config.left, "left", mutated_ct, keypair.sk, &stability);
  KEMSharedSecret second_bad = Decaps(config.left, "left", mutated_ct, keypair.sk, &stability);
  const bool repeated_invalid = first_bad.status == PQCFUZZ_OK && second_bad.status == PQCFUZZ_OK;
  stability.passed = first_bad.status == second_bad.status &&
      (first_bad.status != PQCFUZZ_OK || first_bad.ss == second_bad.ss);
  if (!stability.passed) {
    stability.note = "repeated decapsulation of the same invalid ciphertext was not stable";
  } else if (!repeated_invalid) {
    stability.note = "decapsulation rejected the invalid ciphertext instead of implicit rejection";
  }

  const bool neutral_mutation = first_bad.status == PQCFUZZ_OK && baseline_ss.status == PQCFUZZ_OK &&
      first_bad.ss == baseline_ss.ss;
  if (neutral_mutation) {
    z_separation.passed = true;
    z_separation.skipped = true;
    z_separation.note = "mutation did not change the derived secret; rejection relation not exercised";
  }

  status_shape.passed = first_bad.status == baseline_ss.status &&
      (first_bad.status != PQCFUZZ_OK || first_bad.ss.size() == baseline_ss.ss.size());
  if (!status_shape.passed) {
    status_shape.note = "invalid and valid decapsulation exposed different public status or output length";
  }

  size_t z_offset = 0;
  size_t z_len = 0;
  if (z_separation.skipped) {
    // The relation could not be exercised with this mutation.
  } else if (!KemRejectionSecretRegion(config.algorithm, &z_offset, &z_len) || z_offset + z_len > keypair.sk.size()) {
    z_separation.passed = true;
    z_separation.skipped = true;
    z_separation.note = "rejection secret region unknown for this profile";
  } else {
    std::vector<uint8_t> mutated_sk = keypair.sk;
    const std::vector<uint8_t> original_sk = mutated_sk;
    for (size_t i = 0; i < z_len; ++i) {
      mutated_sk[z_offset + i] ^= static_cast<uint8_t>(0xA5u ^ (i * 31u));
    }
    MutationRecord z_record;
    z_record.operation = "mutate_rejection_secret";
    z_record.target = "secret_key.z";
    z_record.offset = z_offset;
    z_record.length = z_len;
    z_record.field_parse_status = "implicit rejection secret region";
    RecordMutationEffect(&z_record, original_sk, mutated_sk);
    mutations->push_back(z_record);
    if (!z_record.effective) {
      z_separation.passed = true;
      z_separation.skipped = true;
      z_separation.note = "no_effect";
    } else {
      KEMSharedSecret changed_bad = Decaps(config.left, "left", mutated_ct, mutated_sk, &z_separation);
      KEMSharedSecret changed_valid = Decaps(config.left, "left", ciphertext.ct, mutated_sk, &z_separation);
      const bool fallback_changed = changed_bad.status != PQCFUZZ_OK || first_bad.status != PQCFUZZ_OK ||
          changed_bad.ss != first_bad.ss;
      const bool valid_unchanged = changed_valid.status == baseline_ss.status &&
          (changed_valid.status != PQCFUZZ_OK || changed_valid.ss == baseline_ss.ss);
      z_separation.passed = fallback_changed && valid_unchanged;
      if (!z_separation.passed) {
        z_separation.note = !fallback_changed
            ? "changed rejection secret left the invalid-ciphertext fallback unchanged"
            : "changed rejection secret changed valid decapsulation";
      }
    }
  }

  return {stability, z_separation, status_shape};
}

void AddFindingsForFailures(KEMOracleTrace *trace) {
  for (const auto &subtest : trace->subtests) {
    for (const auto &call : subtest.calls) {
      if (call.status == PQCFUZZ_CRASH) {
        trace->findings.push_back(MakeFinding(
            trace->oracle_id, "memory_safety", "", "adapter call crashed", EvidenceKind::kProcess));
      } else if (call.status == PQCFUZZ_TIMEOUT) {
        trace->findings.push_back(MakeFinding(
            trace->oracle_id, "timeout", "", "adapter call timed out", EvidenceKind::kProcess));
      }
    }
    if (subtest.passed) {
      continue;
    }
    std::string finding_class = "confirmed_semantic_bug";
    std::string finding_subclass;
    if (subtest.oracle_id == "mlkem_tampered_ciphertext_implicit_rejection" ||
        subtest.oracle_id == "aigisenc_tampered_ciphertext_implicit_rejection" ||
        subtest.oracle_id == "mlkem_implicit_rejection_relations" ||
        subtest.oracle_id == "aigisenc_implicit_rejection_relations" ||
        subtest.oracle_id == "mlkem_ek_canonicality" ||
        subtest.oracle_id.find("_rng_failure") != std::string::npos ||
        subtest.oracle_id == "aigisenc_sk_noncanonical_coefficient") {
      finding_class = "potential_crypto_vuln";
    }
    if (subtest.oracle_id == "aigisenc_sk_noncanonical_coefficient") {
      finding_subclass = "noncanonical_secret_key_accepted";
    } else if (subtest.oracle_id == "mlkem_implicit_rejection_relations" ||
               subtest.oracle_id == "aigisenc_implicit_rejection_relations" ||
               subtest.oracle_id == "mlkem_ek_canonicality" ||
               subtest.oracle_id.find("_rng_failure") != std::string::npos) {
      finding_subclass = subtest.subtest_id;
    }
    trace->findings.push_back(
        MakeFinding(subtest.oracle_id, finding_class, finding_subclass, subtest.note, EvidenceKind::kSemantic));
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
  if ((context.size() > 255 && (adapter->sign_accepts_extended_context == 0)) || sk.size() != adapter->sk_len) {
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
  const bool target_checks_length = adapter->verify_checks_length != 0;
  if ((context.size() > 255 && (adapter->verify_accepts_extended_context == 0)) ||
      pk.size() != adapter->pk_len || (!target_checks_length && signature.size() > adapter->sig_max_len)) {
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
    const SigFamilyTraits &traits,
    const void *params,
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
      std::vector<uint8_t> planned_signature(traits.sig_max_len(params));
      auto records = traits.mutate_sig(params, config.mutation, &planned_signature);
      mutations->insert(mutations->end(), records.begin(), records.end());
    } else if (mutate_message) {
      auto records = traits.mutate_msg(config.mutation, &message);
      mutations->insert(mutations->end(), records.begin(), records.end());
    } else if (mutate_context) {
      auto records = traits.mutate_ctx(config.mutation, &context);
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
    auto records = traits.mutate_sig(params, config.mutation, &signature.sig);
    mutations->insert(mutations->end(), records.begin(), records.end());
  }
  if (mutate_message) {
    auto records = traits.mutate_msg(config.mutation, &message);
    mutations->insert(mutations->end(), records.begin(), records.end());
  }
  if (mutate_context) {
    auto records = traits.mutate_ctx(config.mutation, &context);
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
    subtest.note = "mutated " + std::string(traits.name) + " input verified or produced an illegal status";
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
  AigisSigParams aigis_sig_params{};
  if (!GetAigisSigParams(config.algorithm, &aigis_sig_params)) {
    subtest.passed = false;
    subtest.note = "AIGIS-SIG parameters unavailable";
    return subtest;
  }
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
  if (signature.sig.size() != aigis_sig_params.sig_max_len) {
    subtest.passed = false;
    subtest.note = "signature length does not match AIGIS-SIG profile";
    return subtest;
  }

  std::vector<uint8_t> mutated = signature.sig;
  const std::vector<uint8_t> original = mutated;
  // The eighth sign byte is the last byte of the challenge region; the top
  // four bits are unconsumed by unpack_sig (60 nonzero challenge coefficients).
  const size_t offset = aigis_sig_params.z_bytes + aigis_sig_params.hint_bytes +
      aigis_sig_params.c_bytes - 1;
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
  AigisSigParams aigis_sig_params{};
  if (!GetAigisSigParams(config.algorithm, &aigis_sig_params)) {
    subtest.passed = false;
    subtest.note = "AIGIS-SIG parameters unavailable";
    return subtest;
  }
  SIGKeyPair keypair = SigKeygen(config.left, "left", &subtest);
  if (keypair.status != PQCFUZZ_OK) {
    subtest.passed = false;
    subtest.note = "could not construct keypair";
    return subtest;
  }
  std::vector<uint8_t> ctx256(256, 0xCC);

  // Detached signer: must reject ctx_len > 255 and leave the caller-provided
  // siglen sentinel and buffer unchanged (design doc Section 25).
  const SignFailureSentinel detached =
      RunSignWithFailureSentinel(config.left, config.message, keypair.sk, ctx256.data(), ctx256.size());
  AddCall(&subtest, "left", "sign", detached.status);
  MutationRecord record;
  record.operation = "ctx_len_256_detached";
  record.target = "ctx";
  record.offset = 0;
  record.length = ctx256.size();
  RecordMutationEffect(&record, config.context, ctx256);
  mutations->push_back(record);
  const bool detached_conformant = detached.status == PQCFUZZ_REJECT &&
      detached.signature_length == kFailureSentinelLength && detached.buffer_unchanged;

  // Combined wrapper: pqmagic crypto_sign unconditionally executes
  // *smlen += mlen even when the detached signer failed (doc 34.5).
  const size_t sm_cap = aigis_sig_params.sig_max_len + config.message.size();
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
  // Doc 34.4: do not assume every configuration is deterministic without
  // checking the declared capability.  Randomized profiles legitimately
  // produce different signatures for the same message.
  if (config.left == nullptr || config.left->supports_deterministic_sign == 0) {
    subtest.skipped = true;
    subtest.passed = true;
    subtest.note = "profile is not declared deterministic; repeated signing may differ";
    return subtest;
  }
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

std::vector<OracleSubtestTrace> SigExactLengthBoundaryOracle(
    const SigOracleExecutorConfig &config,
    const std::string &oracle_id,
    const SigFamilyTraits &traits,
    const void *params,
    std::vector<MutationRecord> *mutations) {
  OracleSubtestTrace setup;
  setup.subtest_id = "exact_length_setup";
  setup.oracle_id = oracle_id;
  SIGKeyPair keypair = SigKeygen(config.left, "left", &setup);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = SigSign(config.left, "left", config.message, config.context, keypair.sk, &setup);
  }
  const bool baseline_ok = signature.status == PQCFUZZ_OK;
  const bool target_checks_length = config.left != nullptr && config.left->verify_checks_length != 0;

  if (!baseline_ok || !target_checks_length) {
    OracleSubtestTrace subtest;
    subtest.subtest_id = "exact_length_boundary";
    subtest.oracle_id = oracle_id;
    subtest.expected_relation = "VERIFY_FALSE_FOR_NON_EXACT_LENGTH";
    if (!baseline_ok) {
      subtest.passed = false;
      subtest.note = "could not construct valid signature before mutation";
    } else {
      subtest.not_applicable = true;
      subtest.passed = true;
      subtest.note = "raw verify boundary has no length parameter; exact-length enforcement belongs to the wrapper (doc 19)";
    }
    return {subtest};
  }

  auto make_case = [&](const std::string &subtest_id, const std::string &description,
                       const std::vector<uint8_t> &candidate) {
    OracleSubtestTrace subtest;
    subtest.subtest_id = subtest_id;
    subtest.oracle_id = oracle_id;
    subtest.expected_relation = "VERIFY_FALSE_FOR_NON_EXACT_LENGTH";
    MutationRecord record;
    record.operation = "boundary_length";
    record.target = "signature";
    record.offset = std::min(candidate.size(), signature.sig.size());
    record.length = candidate.size() > signature.sig.size() ? candidate.size() - signature.sig.size()
                                                          : signature.sig.size() - candidate.size();
    RecordMutationEffect(&record, signature.sig, candidate);
    mutations->push_back(record);
    const uint8_t *ctx = config.context.empty() ? nullptr : config.context.data();
    pqcfuzz_status status = config.left->verify == nullptr
        ? PQCFUZZ_API_UNSUPPORTED
        : config.left->verify(candidate.data(), candidate.size(), config.message.data(), config.message.size(),
                              keypair.pk.data(), ctx, config.context.size());
    AddBoolCall(&subtest, "left", "verify", status, status == PQCFUZZ_OK);
    subtest.passed = status == PQCFUZZ_REJECT || status == PQCFUZZ_INVALID_INPUT;
    if (!subtest.passed) {
      subtest.note = description + ": non-exact signature length was accepted";
    }
    return subtest;
  };

  std::vector<uint8_t> empty;
  std::vector<uint8_t> short_signature = signature.sig;
  if (!short_signature.empty()) {
    short_signature.pop_back();
  }
  std::vector<uint8_t> long_zero = signature.sig;
  long_zero.push_back(0x00);
  std::vector<uint8_t> long_nonzero = signature.sig;
  long_nonzero.push_back(0xA5);
  std::vector<uint8_t> oversized = signature.sig;
  oversized.insert(oversized.end(), 16, 0xA5);

  return {
      make_case("exact_length_empty", "empty signature", empty),
      make_case("exact_length_short", "L-1 signature", short_signature),
      make_case("exact_length_long_zero", "L+1 signature with 0x00", long_zero),
      make_case("exact_length_long_nonzero", "L+1 signature with 0xA5", long_nonzero),
      make_case("exact_length_oversized", "oversized signature", oversized),
  };
}

std::vector<OracleSubtestTrace> SigContextBoundaryOracle(
    const SigOracleExecutorConfig &config,
    const std::string &oracle_id,
    std::vector<MutationRecord> *mutations) {
  (void)mutations;
  OracleSubtestTrace setup;
  setup.subtest_id = "ctx_boundary_setup";
  setup.oracle_id = oracle_id;
  SIGKeyPair keypair = SigKeygen(config.left, "left", &setup);
  const bool baseline_ok = keypair.status == PQCFUZZ_OK;
  const bool supports_context = config.left != nullptr && config.left->supports_context != 0;
  const bool extended_context = config.left != nullptr && config.left->sign_accepts_extended_context != 0;

  if (!baseline_ok || !supports_context) {
    OracleSubtestTrace subtest;
    subtest.subtest_id = "ctx_boundaries";
    subtest.oracle_id = oracle_id;
    subtest.expected_relation = "VERIFY_FALSE_OR_API_UNSUPPORTED";
    if (!baseline_ok) {
      subtest.passed = false;
      subtest.note = "could not construct keypair before context boundary";
    } else {
      subtest.not_applicable = true;
      subtest.passed = true;
      subtest.note = "adapter has no context API";
    }
    return {subtest};
  }

  std::vector<OracleSubtestTrace> subtests;
  for (size_t context_len : {static_cast<size_t>(0), static_cast<size_t>(1), static_cast<size_t>(254),
                             static_cast<size_t>(255)}) {
    OracleSubtestTrace subtest;
    subtest.subtest_id = "ctx_length_" + std::to_string(context_len);
    subtest.oracle_id = oracle_id;
    subtest.expected_relation = "SIGN_AND_VERIFY_WITH_VALID_CONTEXT";
    std::vector<uint8_t> context(context_len, 0xC3);
    SIGSignature signature = SigSign(config.left, "left", config.message, context, keypair.sk, &subtest);
    if (signature.status == PQCFUZZ_API_UNSUPPORTED) {
      subtest.not_applicable = true;
      subtest.passed = true;
      subtest.note = "adapter rejected the context boundary as unsupported";
    } else {
      SIGVerifyResult verify_result;
      if (signature.status == PQCFUZZ_OK) {
        verify_result = SigVerify(config.left, "left", signature.sig, config.message, context, keypair.pk, &subtest);
      }
      subtest.passed = signature.status == PQCFUZZ_OK && verify_result.status == PQCFUZZ_OK && verify_result.accepted;
      if (!subtest.passed) {
        subtest.note = "a valid context length did not sign and verify";
      }
    }
    subtests.push_back(subtest);
  }

  OracleSubtestTrace oversized;
  oversized.subtest_id = "ctx_length_256";
  oversized.oracle_id = oracle_id;
  oversized.expected_relation = "REJECT_CONTEXT_LENGTH_256";
  if (!extended_context) {
    oversized.not_applicable = true;
    oversized.passed = true;
    oversized.note = "adapter does not receive extended context at this boundary";
  } else {
    std::vector<uint8_t> context(256, 0xC3);
    std::vector<uint8_t> signature_buffer(config.left->sig_max_len, 0xA5);
    size_t signature_len = signature_buffer.size();
    pqcfuzz_status status = config.left->sign == nullptr
        ? PQCFUZZ_API_UNSUPPORTED
        : config.left->sign(signature_buffer.data(), &signature_len, config.message.data(), config.message.size(),
                            keypair.sk.data(), context.data(), context.size());
    AddCall(&oversized, "left", "sign", status);
    oversized.passed = status == PQCFUZZ_REJECT || status == PQCFUZZ_INVALID_INPUT;
    if (!oversized.passed) {
      oversized.note = "ctx_len=256 was accepted at the signing boundary";
    }
  }
  subtests.push_back(oversized);

  OracleSubtestTrace mismatch;
  mismatch.subtest_id = "ctx_mismatch_rejected";
  mismatch.oracle_id = oracle_id;
  mismatch.expected_relation = "VERIFY_FALSE_FOR_DIFFERENT_CONTEXT";
  const std::vector<uint8_t> signing_context = {0x01};
  const std::vector<uint8_t> verifying_context = {0x02};
  SIGSignature signature = SigSign(config.left, "left", config.message, signing_context, keypair.sk, &mismatch);
  SIGVerifyResult verify_result;
  if (signature.status == PQCFUZZ_OK) {
    verify_result = SigVerify(config.left, "left", signature.sig, config.message, verifying_context, keypair.pk, &mismatch);
  }
  mismatch.passed = signature.status == PQCFUZZ_OK && verify_result.status != PQCFUZZ_OK;
  if (!mismatch.passed) {
    mismatch.note = "a signature verified under a different context";
  }
  subtests.push_back(mismatch);
  return subtests;
}

std::vector<OracleSubtestTrace> MlDsaHintCanonicalityOracle(
    const SigOracleExecutorConfig &config,
    const MlDsaParams &params,
    std::vector<MutationRecord> *mutations) {
  OracleSubtestTrace setup;
  setup.subtest_id = "hint_canonicality_setup";
  setup.oracle_id = "mldsa_hint_canonicality";
  SIGKeyPair keypair = SigKeygen(config.left, "left", &setup);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = SigSign(config.left, "left", config.message, config.context, keypair.sk, &setup);
  }
  bool baseline_ok = false;
  if (signature.status == PQCFUZZ_OK) {
    SIGVerifyResult baseline = SigVerify(config.left, "left", signature.sig, config.message, config.context, keypair.pk, &setup);
    baseline_ok = baseline.status == PQCFUZZ_OK && baseline.accepted;
  }

  auto run = [&](const std::string &subtest_id, MlDsaHintMutation mutation) {
    OracleSubtestTrace subtest;
    subtest.subtest_id = subtest_id;
    subtest.oracle_id = "mldsa_hint_canonicality";
    subtest.expected_relation = "VERIFY_FALSE_FOR_NONCANONICAL_HINT";
    if (!baseline_ok) {
      subtest.passed = false;
      subtest.note = "valid signature did not verify before hint mutation";
      return subtest;
    }
    std::vector<uint8_t> candidate = signature.sig;
    auto records = MutateMlDsaHintCanonical(params, mutation, &candidate);
    mutations->insert(mutations->end(), records.begin(), records.end());
    const bool ineffective = records.empty() ||
        std::any_of(records.begin(), records.end(), [](const MutationRecord &record) {
          return !record.effective || record.skipped;
        });
    if (ineffective) {
      subtest.passed = true;
      subtest.skipped = true;
      subtest.note = "no_effect";
      return subtest;
    }
    SIGVerifyResult verify_result = SigVerify(config.left, "left", candidate, config.message, config.context, keypair.pk, &subtest);
    subtest.passed = verify_result.status == PQCFUZZ_REJECT || verify_result.status == PQCFUZZ_INVALID_INPUT;
    if (!subtest.passed) {
      subtest.note = "non-canonical hint encoding verified";
    }
    return subtest;
  };

  return {
      run("hint_count_rollback", MlDsaHintMutation::kCountRollback),
      run("hint_count_overflow", MlDsaHintMutation::kCountOverflow),
      run("hint_non_increasing", MlDsaHintMutation::kNonIncreasingIndex),
      run("hint_trailing_non_zero", MlDsaHintMutation::kTrailingNonZero),
  };
}

OracleSubtestTrace KemRawLengthBoundary(const OracleExecutorConfig &config) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = "raw_length_boundary";
  subtest.oracle_id = config.oracle_id;
  subtest.expected_relation = "NOT_APPLICABLE_FOR_FIXED_POINTER_API";
  KEMKeyPair keypair = Keygen(config.left, "left", &subtest);
  KEMSharedSecret encaps_ss;
  KEMCiphertext ciphertext;
  if (keypair.status == PQCFUZZ_OK) {
    ciphertext = Encaps(config.left, "left", keypair.pk, &subtest, &encaps_ss);
  }
  if (ciphertext.status != PQCFUZZ_OK) {
    subtest.passed = IsUnsupportedOnly(subtest);
    subtest.skipped = IsUnsupportedOnly(subtest);
    subtest.note = IsUnsupportedOnly(subtest) ? "adapter API unsupported" : "baseline encapsulation failed";
    return subtest;
  }
  KEMSharedSecret decaps_ss = Decaps(config.left, "left", ciphertext.ct, keypair.sk, &subtest);
  if (!SameSecret(encaps_ss, decaps_ss)) {
    subtest.passed = false;
    subtest.note = "baseline roundtrip failed";
    return subtest;
  }
  subtest.not_applicable = true;
  subtest.passed = true;
  subtest.note = "raw fixed-pointer API has no ciphertext length parameter; exact-length enforcement belongs to a "
                 "length-aware wrapper (DeepSeek doc Section 19)";
  return subtest;
}

std::vector<OracleSubtestTrace> KemEkCanonicality(
    const OracleExecutorConfig &config,
    const MlKemParams &params,
    std::vector<MutationRecord> *mutations) {
  auto make_subtest = [&](const std::string &subtest_id, const std::string &expected_relation) {
    OracleSubtestTrace subtest;
    subtest.subtest_id = subtest_id;
    subtest.oracle_id = "mlkem_ek_canonicality";
    subtest.expected_relation = expected_relation;
    return subtest;
  };
  OracleSubtestTrace setup = make_subtest("ek_canonical_setup", "BASELINE_ENCAPSULATION");
  KEMKeyPair keypair = Keygen(config.left, "left", &setup);
  KEMSharedSecret baseline_ss;
  KEMCiphertext baseline_ct;
  if (keypair.status == PQCFUZZ_OK) {
    baseline_ct = Encaps(config.left, "left", keypair.pk, &setup, &baseline_ss);
  }
  const bool baseline_ok = baseline_ct.status == PQCFUZZ_OK;
  const std::string baseline_note = IsUnsupportedOnly(setup) ? "adapter API unsupported"
                                                             : "could not construct baseline encapsulation";

  std::vector<size_t> positions;
  for (size_t poly = 0; poly < params.k; ++poly) {
    for (size_t coefficient : {static_cast<size_t>(0), static_cast<size_t>(127), static_cast<size_t>(128),
                               static_cast<size_t>(255)}) {
      positions.push_back(poly * 256 + coefficient);
    }
  }

  auto run_value = [&](const std::string &subtest_id, uint16_t value, bool expect_accepted) {
    OracleSubtestTrace subtest = make_subtest(
        subtest_id, expect_accepted ? "ENCAPS_ACCEPTS_CANONICAL_BOUNDARY" : "ENCAPS_REJECTS_NONCANONICAL_COEFFICIENT");
    if (!baseline_ok) {
      subtest.passed = IsUnsupportedOnly(setup);
      subtest.skipped = IsUnsupportedOnly(setup);
      subtest.note = baseline_note;
      return subtest;
    }
    size_t changed = 0;
    size_t rejected = 0;
    size_t accepted = 0;
    for (size_t position : positions) {
      std::vector<uint8_t> mutated_pk = keypair.pk;
      if (!EncodeMlKemCoefficient12(&mutated_pk, position, value)) {
        continue;
      }
      if (mutated_pk == keypair.pk) {
        continue;
      }
      MutationRecord record;
      record.operation = "encode_coefficient_12bit";
      record.target = "public_key.t";
      record.offset = (position / 2) * 3;
      record.length = 3;
      record.field_parse_status = "12-bit coefficient boundary value";
      RecordMutationEffect(&record, keypair.pk, mutated_pk);
      mutations->push_back(record);
      ++changed;
      KEMCiphertext ciphertext = Encaps(config.left, "left", mutated_pk, &subtest, nullptr);
      if (ciphertext.status == PQCFUZZ_OK) {
        ++accepted;
      } else {
        ++rejected;
      }
    }
    if (changed == 0) {
      subtest.passed = true;
      subtest.skipped = true;
      subtest.note = "no_effect";
      return subtest;
    }
    subtest.passed = expect_accepted ? rejected == 0 : accepted == 0;
    if (!subtest.passed) {
      subtest.note = expect_accepted
          ? std::to_string(rejected) + " of " + std::to_string(changed) + " canonical boundary coefficients were rejected"
          : std::to_string(accepted) + " of " + std::to_string(changed) + " non-canonical coefficients were accepted";
    }
    return subtest;
  };

  // FIPS 203 ML-KEM modulus q = 3329; q - 1 is canonical, q..4095 are not.
  constexpr uint16_t kMlKemQ = 3329;
  return {
      run_value("ek_canonical_q_minus_1", static_cast<uint16_t>(kMlKemQ - 1), true),
      run_value("ek_canonical_q", kMlKemQ, false),
      run_value("ek_canonical_q_plus_1", static_cast<uint16_t>(kMlKemQ + 1), false),
      run_value("ek_canonical_max_4095", static_cast<uint16_t>(4095), false),
  };
}

std::vector<OracleSubtestTrace> MlDsaZNormBoundaryOracle(
    const SigOracleExecutorConfig &config,
    const std::string &oracle_id,
    const MlDsaParams &params,
    std::vector<MutationRecord> *mutations) {
  OracleSubtestTrace setup;
  setup.subtest_id = "z_norm_setup";
  setup.oracle_id = oracle_id;
  SIGKeyPair keypair = SigKeygen(config.left, "left", &setup);
  SIGSignature signature;
  if (keypair.status == PQCFUZZ_OK) {
    signature = SigSign(config.left, "left", config.message, config.context, keypair.sk, &setup);
  }
  bool baseline_ok = false;
  if (signature.status == PQCFUZZ_OK) {
    SIGVerifyResult baseline =
        SigVerify(config.left, "left", signature.sig, config.message, config.context, keypair.pk, &setup);
    baseline_ok = baseline.status == PQCFUZZ_OK && baseline.accepted;
  }

  auto run = [&](const std::string &subtest_id, MlDsaZNormMutation mutation, bool expect_rejection) {
    OracleSubtestTrace subtest;
    subtest.subtest_id = subtest_id;
    subtest.oracle_id = oracle_id;
    subtest.expected_relation = expect_rejection ? "VERIFY_FALSE_FOR_OUT_OF_NORM_Z" : "RESPONSE_BOUNDARY_OBSERVATION";
    if (!baseline_ok) {
      subtest.passed = false;
      subtest.note = "valid signature did not verify before z-boundary mutation";
      return subtest;
    }
    std::vector<uint8_t> candidate = signature.sig;
    auto records = MutateMlDsaZNormBoundary(params, mutation, &candidate);
    mutations->insert(mutations->end(), records.begin(), records.end());
    const bool ineffective = records.empty() ||
        std::any_of(records.begin(), records.end(), [](const MutationRecord &record) {
          return !record.effective || record.skipped;
        });
    if (ineffective) {
      subtest.passed = true;
      subtest.skipped = true;
      subtest.note = "no_effect";
      return subtest;
    }
    SIGVerifyResult verify_result =
        SigVerify(config.left, "left", candidate, config.message, config.context, keypair.pk, &subtest);
    const bool accepted = verify_result.status == PQCFUZZ_OK && verify_result.accepted;
    if (expect_rejection) {
      subtest.passed = !accepted;
      if (!subtest.passed) {
        subtest.note = "out-of-norm z coefficient verified";
      }
    } else {
      // The signature relation is intentionally broken by any z change, so a
      // rejection is expected even on the valid boundary.  This subtest is a
      // structural observation, not a conformance gate.
      subtest.passed = true;
      subtest.note = accepted ? "valid-boundary coefficient accepted by verifier"
                              : "valid-boundary coefficient rejected (signature relation broken)";
    }
    return subtest;
  };

  return {
      run("z_norm_valid_boundary", MlDsaZNormMutation::kValidBoundary, false),
      run("z_norm_over_boundary", MlDsaZNormMutation::kOverBoundary, true),
      run("z_norm_negative_over_boundary", MlDsaZNormMutation::kNegativeOverBoundary, true),
  };
}

std::vector<OracleSubtestTrace> MlDsaRndDeterminismOracle(
    const SigOracleExecutorConfig &config,
    const std::string &oracle_id,
    std::vector<MutationRecord> *mutations) {
  (void)mutations;
  OracleSubtestTrace setup;
  setup.subtest_id = "rnd_determinism_setup";
  setup.oracle_id = oracle_id;
  SIGKeyPair keypair = SigKeygen(config.left, "left", &setup);
  if (keypair.status != PQCFUZZ_OK) {
    OracleSubtestTrace failed;
    failed.subtest_id = "rnd_determinism_setup";
    failed.oracle_id = oracle_id;
    failed.passed = false;
    failed.note = "could not construct keypair before randomness control";
    return {failed};
  }

  std::vector<uint8_t> zero_tape(32, 0x00);
  std::vector<uint8_t> tape_a(32, 0x11);
  std::vector<uint8_t> tape_b(32, 0x22);

  auto sign_with_tape = [&](const std::vector<uint8_t> &tape, OracleSubtestTrace *subtest) {
    ScopedRngOverride rng({tape.data(), tape.size(), false});
    return SigSign(config.left, "left", config.message, config.context, keypair.sk, subtest);
  };

  SIGSignature first;
  SIGSignature second;
  {
    first = sign_with_tape(zero_tape, &setup);
    second = sign_with_tape(zero_tape, &setup);
  }

  std::vector<OracleSubtestTrace> subtests;

  OracleSubtestTrace reproducible;
  reproducible.subtest_id = "zero_rnd_reproducibility";
  reproducible.oracle_id = oracle_id;
  reproducible.expected_relation = "IDENTICAL_SIGNATURES_FOR_FIXED_RND";
  if (first.status == PQCFUZZ_API_UNSUPPORTED || second.status == PQCFUZZ_API_UNSUPPORTED) {
    reproducible.not_applicable = true;
    reproducible.passed = true;
    reproducible.note = "adapter API unsupported";
  } else if (first.status != PQCFUZZ_OK || second.status != PQCFUZZ_OK) {
    reproducible.passed = false;
    reproducible.note = "signing failed under fixed-rnd control";
  } else {
    reproducible.passed = first.sig == second.sig;
    if (!reproducible.passed) {
      reproducible.note = "fixed zero rnd produced different signatures";
    }
  }
  subtests.push_back(reproducible);

  OracleSubtestTrace zero_verifies;
  zero_verifies.subtest_id = "zero_rnd_verifies";
  zero_verifies.oracle_id = oracle_id;
  zero_verifies.expected_relation = "VERIFY_TRUE";
  if (first.status == PQCFUZZ_API_UNSUPPORTED) {
    zero_verifies.not_applicable = true;
    zero_verifies.passed = true;
    zero_verifies.note = "adapter API unsupported";
  } else if (first.status != PQCFUZZ_OK) {
    zero_verifies.passed = false;
    zero_verifies.note = "fixed-rnd signing failed";
  } else {
    SIGVerifyResult verify_result =
        SigVerify(config.left, "left", first.sig, config.message, config.context, keypair.pk, &zero_verifies);
    zero_verifies.passed = verify_result.status == PQCFUZZ_OK && verify_result.accepted;
    if (!zero_verifies.passed) {
      zero_verifies.note = "fixed-rnd signature did not verify";
    }
  }
  subtests.push_back(zero_verifies);

  const bool deterministic_signer =
      config.left != nullptr && config.left->supports_deterministic_sign != 0 &&
      config.left->supports_seeded_sign == 0;
  OracleSubtestTrace varies;
  varies.subtest_id = "fresh_rnd_varies";
  varies.oracle_id = oracle_id;
  varies.expected_relation = "DISTINCT_SIGNATURES_FOR_DISTINCT_RND";
  OracleSubtestTrace verify_a;
  verify_a.subtest_id = "fresh_rnd_verifies";
  verify_a.oracle_id = oracle_id;
  verify_a.expected_relation = "VERIFY_TRUE";
  if (deterministic_signer) {
    varies.not_applicable = true;
    varies.passed = true;
    varies.note = "deterministic profile ignores ambient randomness";
    verify_a.not_applicable = true;
    verify_a.passed = true;
    verify_a.note = "deterministic profile ignores ambient randomness";
  } else {
    SIGSignature sig_a = sign_with_tape(tape_a, &varies);
    SIGSignature sig_b = sign_with_tape(tape_b, &varies);
    if (sig_a.status != PQCFUZZ_OK || sig_b.status != PQCFUZZ_OK) {
      varies.passed = false;
      varies.note = "signing failed under distinct-rnd control";
      verify_a.passed = false;
      verify_a.note = "signing failed under distinct-rnd control";
    } else {
      varies.passed = sig_a.sig != sig_b.sig;
      if (!varies.passed) {
        varies.note = "distinct randomness produced identical signatures";
      }
      SIGVerifyResult verify_result =
          SigVerify(config.left, "left", sig_a.sig, config.message, config.context, keypair.pk, &verify_a);
      verify_a.passed = verify_result.status == PQCFUZZ_OK && verify_result.accepted;
      if (!verify_a.passed) {
        verify_a.note = "fresh-rnd signature did not verify";
      }
    }
  }
  subtests.push_back(varies);
  subtests.push_back(verify_a);
  return subtests;
}

std::vector<OracleSubtestTrace> SigNotApplicableOracle(
    const SigOracleExecutorConfig &config,
    const std::string &oracle_id,
    const std::string &note) {
  (void)config;
  OracleSubtestTrace subtest;
  subtest.subtest_id = "not_applicable";
  subtest.oracle_id = oracle_id;
  subtest.expected_relation = "API_UNSUPPORTED";
  subtest.not_applicable = true;
  subtest.passed = true;
  subtest.note = note;
  return {subtest};
}

// Injects a reported RNG failure for one call.  Void RNG APIs cannot surface
// a failure status, so the oracle also observes whether the injected failure
// reached the RNG layer at all.
struct RngFailureProbe {
  pqcfuzz_status status = PQCFUZZ_API_UNSUPPORTED;
  bool failure_observed = false;
};

template <typename Callable>
RngFailureProbe RunWithReportedRngFailure(Callable &&call) {
  RngFailureProbe probe;
  uint8_t dummy = 0;
  pqcfuzz_rng_reset_failure_observed();
  {
    ScopedRngOverride rng({&dummy, 1, false, RngTape::Mode::kReportedFailure});
    probe.status = call();
  }
  probe.failure_observed = pqcfuzz_rng_failure_observed();
  return probe;
}

bool RngFailureSubtestPassed(OracleSubtestTrace *subtest, const RngFailureProbe &probe, const char *what) {
  if (!probe.failure_observed) {
    subtest->not_applicable = true;
    subtest->passed = true;
    subtest->note = std::string("adapter RNG layer did not observe the injected failure for ") + what;
    return true;
  }
  if (probe.status != PQCFUZZ_OK) {
    subtest->passed = true;
    return true;
  }
  subtest->passed = false;
  subtest->note = std::string("injected RNG failure still produced output from ") + what;
  return false;
}

std::vector<OracleSubtestTrace> KemRngFailureOracle(
    const OracleExecutorConfig &config,
    const std::string &oracle_id) {
  std::vector<OracleSubtestTrace> subtests;

  OracleSubtestTrace keygen;
  keygen.subtest_id = "rng_failure_keygen";
  keygen.oracle_id = oracle_id;
  keygen.expected_relation = "NO_OUTPUT_ON_REPORTED_RNG_FAILURE";
  if (config.left == nullptr || config.left->keygen == nullptr) {
    keygen.not_applicable = true;
    keygen.passed = true;
    keygen.note = "adapter API unsupported";
  } else {
    const RngFailureProbe probe = RunWithReportedRngFailure([&]() {
      return Keygen(config.left, "left", &keygen).status;
    });
    RngFailureSubtestPassed(&keygen, probe, "key generation");
  }
  subtests.push_back(keygen);

  OracleSubtestTrace encaps;
  encaps.subtest_id = "rng_failure_encaps";
  encaps.oracle_id = oracle_id;
  encaps.expected_relation = "NO_OUTPUT_ON_REPORTED_RNG_FAILURE";
  KEMKeyPair keypair = Keygen(config.left, "left", &encaps);
  const bool keypair_ok = keypair.status == PQCFUZZ_OK;
  if (!keypair_ok) {
    encaps.passed = IsUnsupportedOnly(encaps);
    encaps.skipped = IsUnsupportedOnly(encaps);
    encaps.note = IsUnsupportedOnly(encaps) ? "adapter API unsupported" : "baseline key generation failed";
  } else {
    const RngFailureProbe probe = RunWithReportedRngFailure([&]() {
      KEMSharedSecret shared_secret;
      return Encaps(config.left, "left", keypair.pk, &encaps, &shared_secret).status;
    });
    RngFailureSubtestPassed(&encaps, probe, "encapsulation");
  }
  subtests.push_back(encaps);
  return subtests;
}

std::vector<OracleSubtestTrace> SigRngFailureOracle(
    const SigOracleExecutorConfig &config,
    const std::string &oracle_id) {
  std::vector<OracleSubtestTrace> subtests;

  OracleSubtestTrace keygen;
  keygen.subtest_id = "rng_failure_keygen";
  keygen.oracle_id = oracle_id;
  keygen.expected_relation = "NO_OUTPUT_ON_REPORTED_RNG_FAILURE";
  if (config.left == nullptr || config.left->keygen == nullptr) {
    keygen.not_applicable = true;
    keygen.passed = true;
    keygen.note = "adapter API unsupported";
  } else {
    const RngFailureProbe probe = RunWithReportedRngFailure([&]() { return SigKeygen(config.left, "left", &keygen).status; });
    RngFailureSubtestPassed(&keygen, probe, "key generation");
  }
  subtests.push_back(keygen);

  OracleSubtestTrace sign;
  sign.subtest_id = "rng_failure_sign";
  sign.oracle_id = oracle_id;
  sign.expected_relation = "NO_OUTPUT_ON_REPORTED_RNG_FAILURE";
  SIGKeyPair keypair = SigKeygen(config.left, "left", &sign);
  if (keypair.status != PQCFUZZ_OK) {
    sign.passed = IsUnsupportedOnly(sign);
    sign.skipped = IsUnsupportedOnly(sign);
    sign.note = IsUnsupportedOnly(sign) ? "adapter API unsupported" : "baseline key generation failed";
  } else {
    const RngFailureProbe probe = RunWithReportedRngFailure([&]() {
      return SigSign(config.left, "left", config.message, config.context, keypair.sk, &sign).status;
    });
    RngFailureSubtestPassed(&sign, probe, "signing");
  }
  subtests.push_back(sign);
  return subtests;
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
        trace->findings.push_back(MakeFinding(
            trace->oracle_id, "memory_safety", "", "adapter call crashed", EvidenceKind::kProcess));
      } else if (call.status == PQCFUZZ_TIMEOUT) {
        trace->findings.push_back(MakeFinding(
            trace->oracle_id, "timeout", "", "adapter call timed out", EvidenceKind::kProcess));
      }
    }
    if (subtest.passed) {
      continue;
    }
    if (subtest.oracle_id.find("_mutated_signature_negative") != std::string::npos ||
        subtest.oracle_id.find("_mutated_message_negative") != std::string::npos ||
        subtest.oracle_id.find("_mutated_context_negative") != std::string::npos ||
        subtest.oracle_id.find("_verify_exact_lengths") != std::string::npos ||
        subtest.oracle_id.find("_ctx_boundaries") != std::string::npos ||
        subtest.oracle_id.find("_hint_canonicality") != std::string::npos ||
        subtest.oracle_id.find("_z_norm_boundary") != std::string::npos ||
        subtest.oracle_id.find("_rnd_determinism") != std::string::npos ||
        subtest.oracle_id.find("_rng_failure") != std::string::npos ||
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
      } else if (subtest.oracle_id.find("_verify_exact_lengths") != std::string::npos ||
                 subtest.oracle_id.find("_ctx_boundaries") != std::string::npos ||
                 subtest.oracle_id.find("_hint_canonicality") != std::string::npos ||
                 subtest.oracle_id.find("_z_norm_boundary") != std::string::npos ||
                 subtest.oracle_id.find("_rnd_determinism") != std::string::npos ||
                 subtest.oracle_id.find("_rng_failure") != std::string::npos) {
        finding_subclass = subtest.subtest_id;
      }
      std::string finding_class = "potential_crypto_vuln";
      if (subtest.oracle_id.find("_rnd_determinism") != std::string::npos &&
          subtest.subtest_id != "fresh_rnd_varies") {
        // Fixed-rnd reproducibility failures are structural, not RNG-ignoring.
        finding_class = "confirmed_semantic_bug";
      }
      trace->findings.push_back(
          MakeFinding(subtest.oracle_id, finding_class, finding_subclass, subtest.note, EvidenceKind::kSemantic));
    } else {
      trace->findings.push_back(
          MakeFinding(subtest.oracle_id, "confirmed_semantic_bug", "", subtest.note, EvidenceKind::kSemantic));
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

  const KemFamilyTraits *traits = KemTraitsFor(config.algorithm);
  if (traits == nullptr) {
    trace.diagnostic_event = "unknown KEM algorithm family";
    trace.relation_evaluable = false;
    return trace;
  }
  const std::string bad_rng_oracle = std::string(traits->prefix) + "_bad_randomness_sanity";
  const std::string tampered_oracle = std::string(traits->prefix) + "_tampered_ciphertext_implicit_rejection";
  const std::string relations_oracle = std::string(traits->prefix) + "_implicit_rejection_relations";
  const std::string cross_oracle = std::string(traits->prefix) + "_cross_exchange_roundtrip";
  const std::string raw_length_oracle = std::string(traits->prefix) + "_raw_length_boundary";
  const std::string ek_canonical_oracle = "mlkem_ek_canonicality";
  const std::string rng_failure_oracle = std::string(traits->prefix) + "_rng_failure";
  const std::string local_oracle = std::string(traits->prefix) + "_local_roundtrip";

  if (config.oracle_id == bad_rng_oracle) {
    RngInterventionTrace rng_trace;
    trace.subtests.push_back(KemRandomnessSanity(config, &rng_trace));
    trace.rng_interventions.push_back(std::move(rng_trace));
    SetRandomnessTraceReachability(&trace);
  } else if (const KemSpecialHandler *handler = FindKemSpecialHandler(config.oracle_id)) {
    trace.subtests.push_back((*handler)(config, &trace.mutations));
  } else if (config.oracle_id == relations_oracle) {
    // Type-erased params view selected by the family traits.
    MlKemParams mlkem_params{};
    AigisEncParams aigis_params{};
    const void *params = nullptr;
    if (std::string(traits->name) == "AIGIS-ENC") {
      GetAigisEncParams(config.algorithm, &aigis_params);
      params = &aigis_params;
    } else {
      GetMlKemParams(config.algorithm, &mlkem_params);
      params = &mlkem_params;
    }
    auto subtests = KemImplicitRejectionRelations(config, relations_oracle, params, traits->mutate_ct, &trace.mutations);
    trace.subtests.insert(trace.subtests.end(), subtests.begin(), subtests.end());
  } else if (config.oracle_id == tampered_oracle) {
    // Type-erased params view selected by the family traits.
    MlKemParams mlkem_params{};
    AigisEncParams aigis_params{};
    const void *params = nullptr;
    if (std::string(traits->name) == "AIGIS-ENC") {
      GetAigisEncParams(config.algorithm, &aigis_params);
      params = &aigis_params;
    } else {
      GetMlKemParams(config.algorithm, &mlkem_params);
      params = &mlkem_params;
    }
    trace.subtests.push_back(
        KemTamperedCiphertext(config, tampered_oracle, params, traits->mutate_ct, &trace.mutations));
  } else if (config.oracle_id == cross_oracle) {
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
  } else if (config.oracle_id == raw_length_oracle) {
    trace.subtests.push_back(KemRawLengthBoundary(config));
  } else if (config.oracle_id == ek_canonical_oracle && std::string(traits->name) == "ML-KEM") {
    MlKemParams mlkem_params{};
    GetMlKemParams(config.algorithm, &mlkem_params);
    auto subtests = KemEkCanonicality(config, mlkem_params, &trace.mutations);
    trace.subtests.insert(trace.subtests.end(), subtests.begin(), subtests.end());
  } else if (config.oracle_id == rng_failure_oracle) {
    auto subtests = KemRngFailureOracle(config, config.oracle_id);
    trace.subtests.insert(trace.subtests.end(), subtests.begin(), subtests.end());
  } else {
    trace.subtests.push_back(LocalRoundtrip("left_keygen_left_encaps_left_decaps", local_oracle, "left", config.left));
    trace.subtests.push_back(LocalRoundtrip("right_keygen_right_encaps_right_decaps", local_oracle, "right", config.right));
  }

  AddFindingsForFailures(&trace);
  SetFipsTraceReachability(&trace);
  PopulateControls(trace.oracle_id, &trace);
  return trace;
}

KEMOracleTrace ExecuteSigOracle(const SigOracleExecutorConfig &config) {
  KEMOracleTrace trace;
  trace.job_id = config.job_id;
  trace.pair_id = config.pair_id;
  trace.algorithm = config.algorithm;
  trace.oracle_id = config.oracle_id;

  const SigFamilyTraits *traits = SigTraitsFor(config.algorithm);
  if (traits == nullptr) {
    trace.diagnostic_event = "unknown signature algorithm family";
    trace.relation_evaluable = false;
    return trace;
  }
  const std::string bad_rng_oracle = std::string(traits->prefix) + "_bad_randomness_sanity";
  const std::string local_oracle = std::string(traits->prefix) + "_local_sign_verify";
  const std::string cross_oracle = std::string(traits->prefix) + "_cross_verify";
  const std::string mutated_signature_oracle = std::string(traits->prefix) + "_mutated_signature_negative";
  const std::string mutated_message_oracle = std::string(traits->prefix) + "_mutated_message_negative";
  const std::string mutated_context_oracle = std::string(traits->prefix) + "_mutated_context_negative";
  const std::string oid_oracle = "mldsa_oid_field_mutation_sanity";
  const std::string exact_length_oracle = std::string(traits->prefix) + "_verify_exact_lengths";
  const std::string ctx_boundary_oracle = std::string(traits->prefix) + "_ctx_boundaries";
  const std::string z_norm_oracle = std::string(traits->prefix) + "_z_norm_boundary";
  const std::string rnd_determinism_oracle = std::string(traits->prefix) + "_rnd_determinism";
  const std::string pure_prehash_oracle = std::string(traits->prefix) + "_pure_prehash_separation";
  const std::string ph_oid_oracle = std::string(traits->prefix) + "_ph_oid_separation";
  const std::string rng_failure_oracle = std::string(traits->prefix) + "_rng_failure";
  const std::string local_trace_oracle =
      (config.oracle_id.find("_bad_randomness_sanity") != std::string::npos) ? config.oracle_id : local_oracle;

  // Type-erased params view selected by the family traits.
  MlDsaParams dsa_params{};
  SlhDsaParams slh_params{};
  AigisSigParams aigis_params{};
  const void *params = nullptr;
  if (std::string(traits->name) == "SLH-DSA") {
    GetSlhDsaParams(config.algorithm, &slh_params);
    params = &slh_params;
  } else if (std::string(traits->name) == "AIGIS-SIG") {
    GetAigisSigParams(config.algorithm, &aigis_params);
    params = &aigis_params;
  } else {
    GetMlDsaParams(config.algorithm, &dsa_params);
    params = &dsa_params;
  }

  if (config.oracle_id == bad_rng_oracle) {
    RngInterventionTrace rng_trace;
    trace.subtests.push_back(SigRandomnessSanity(config, &rng_trace));
    trace.rng_interventions.push_back(std::move(rng_trace));
    SetRandomnessTraceReachability(&trace);
  } else if (const SigSpecialHandler *handler = FindSigSpecialHandler(config.oracle_id)) {
    trace.subtests.push_back((*handler)(config, &trace.mutations));
  } else if (config.oracle_id == cross_oracle) {
    if (config.exchange_contract.public_key_exchange && config.exchange_contract.signature_exchange) {
      trace.subtests.push_back(SigCrossVerify(
          "left_keygen_left_sign_right_verify", cross_oracle, "left", config.left, "right", config.right, config.message, config.context));
      trace.subtests.push_back(SigCrossVerify(
          "right_keygen_right_sign_left_verify", cross_oracle, "right", config.right, "left", config.left, config.message, config.context));
    }
  } else if (config.oracle_id == mutated_signature_oracle) {
    trace.subtests.push_back(
        SigNegative(config, "mutated_signature_negative", config.oracle_id, *traits, params, &trace.mutations, true, false, false, false));
  } else if (config.oracle_id == mutated_message_oracle) {
    trace.subtests.push_back(
        SigNegative(config, "mutated_message_negative", config.oracle_id, *traits, params, &trace.mutations, false, true, false, false));
  } else if (config.oracle_id == mutated_context_oracle) {
    trace.subtests.push_back(
        SigNegative(config, "mutated_context_negative", config.oracle_id, *traits, params, &trace.mutations, false, false, true, false));
  } else if (config.oracle_id == exact_length_oracle) {
    auto subtests = SigExactLengthBoundaryOracle(config, config.oracle_id, *traits, params, &trace.mutations);
    trace.subtests.insert(trace.subtests.end(), subtests.begin(), subtests.end());
  } else if (config.oracle_id == ctx_boundary_oracle) {
    auto subtests = SigContextBoundaryOracle(config, config.oracle_id, &trace.mutations);
    trace.subtests.insert(trace.subtests.end(), subtests.begin(), subtests.end());
  } else if (config.oracle_id == "mldsa_hint_canonicality" && std::string(traits->name) == "ML-DSA") {
    MlDsaParams dsa_params{};
    GetMlDsaParams(config.algorithm, &dsa_params);
    auto subtests = MlDsaHintCanonicalityOracle(config, dsa_params, &trace.mutations);
    trace.subtests.insert(trace.subtests.end(), subtests.begin(), subtests.end());
  } else if (config.oracle_id == z_norm_oracle && std::string(traits->name) == "ML-DSA") {
    MlDsaParams dsa_params{};
    GetMlDsaParams(config.algorithm, &dsa_params);
    auto subtests = MlDsaZNormBoundaryOracle(config, config.oracle_id, dsa_params, &trace.mutations);
    trace.subtests.insert(trace.subtests.end(), subtests.begin(), subtests.end());
  } else if (config.oracle_id == rnd_determinism_oracle && std::string(traits->name) == "ML-DSA") {
    auto subtests = MlDsaRndDeterminismOracle(config, config.oracle_id, &trace.mutations);
    trace.subtests.insert(trace.subtests.end(), subtests.begin(), subtests.end());
  } else if (config.oracle_id == rng_failure_oracle) {
    auto subtests = SigRngFailureOracle(config, config.oracle_id);
    trace.subtests.insert(trace.subtests.end(), subtests.begin(), subtests.end());
  } else if (config.oracle_id == pure_prehash_oracle || config.oracle_id == ph_oid_oracle) {
    auto subtests = SigNotApplicableOracle(
        config, config.oracle_id,
        "no prehash interface is exposed by the selected adapter; pure/prehash and OID "
        "domain separation require a HashML-DSA or prehash-capable API (doc Sections 29.8/30.7)");
    trace.subtests.insert(trace.subtests.end(), subtests.begin(), subtests.end());
  } else if (std::string(traits->name) == "ML-DSA" && config.oracle_id == oid_oracle) {
    trace.subtests.push_back(
        SigNegative(config, "oid_field_mutation_sanity", config.oracle_id, *traits, params, &trace.mutations, false, false, false, true));
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
  PopulateControls(trace.oracle_id, &trace);
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
  out << "  \"version\": 5,\n";
  out << "  \"oracle_semantics_version\": 5,\n";
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
    out << "      \"not_applicable\": " << (subtest.not_applicable ? "true" : "false") << ",\n";
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
        << JsonEscape(finding_fingerprint(finding)) << "\",\"verdict\":\""
        << VerdictName(finding.verdict) << "\",\"evidence_class\":\""
        << EvidenceClassName(finding.evidence_class) << "\",\"conditional_verdict\":\""
        << JsonEscape(finding.conditional_verdict) << "\",\"claim\":\"" << JsonEscape(finding.claim)
        << "\",\"source_reference\":\"" << JsonEscape(finding.source_reference) << "\",\"limitations\":[";
    for (size_t j = 0; j < finding.limitations.size(); ++j) {
      if (j != 0) {
        out << ", ";
      }
      out << "\"" << JsonEscape(finding.limitations[j]) << "\"";
    }
    out << "]}"
        << (i + 1 == trace.findings.size() ? "\n" : ",\n");
  }
  out << "  ],\n";
  out << "  \"controls\": {\"baseline_repeat_equal\": "
      << (trace.controls.baseline_repeat_equal ? "true" : "false")
      << ",\"positive_control\":\"" << JsonEscape(trace.controls.positive_control)
      << "\",\"negative_control\":\"" << JsonEscape(trace.controls.negative_control)
      << "\",\"false_positive_controls\":[";
  for (size_t i = 0; i < trace.controls.false_positive_controls.size(); ++i) {
    if (i != 0) {
      out << ", ";
    }
    out << "\"" << JsonEscape(trace.controls.false_positive_controls[i]) << "\"";
  }
  out << "],\"false_negative_controls\":[";
  for (size_t i = 0; i < trace.controls.false_negative_controls.size(); ++i) {
    if (i != 0) {
      out << ", ";
    }
    out << "\"" << JsonEscape(trace.controls.false_negative_controls[i]) << "\"";
  }
  out << "]}\n";
  out << "}\n";
  return out.str();
}

}  // namespace pqcfuzz

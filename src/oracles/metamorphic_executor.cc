#include "oracles/metamorphic_executor.h"

#include <algorithm>
#include <sstream>
#include <string>

#include "adapters/rng_control.h"
#include "mutators/maul.h"
#include "oracles/metamorphic_observation.h"
#include "oracles/metamorphic_spec.h"

namespace pqcfuzz {
namespace {

void AddCall(OracleSubtestTrace *subtest, const std::string &api, pqcfuzz_status status) {
  OracleCallTrace call;
  call.adapter = "left";
  call.api = api;
  call.status = status;
  call.executor_dispatched = true;
  call.adapter_entered = status != PQCFUZZ_API_UNSUPPORTED;
  call.target_entered = status != PQCFUZZ_API_UNSUPPORTED;
  call.target_returned = status != PQCFUZZ_CRASH && status != PQCFUZZ_TIMEOUT;
  call.rejection_layer = status == PQCFUZZ_REJECT ? "target" : "";
  subtest->calls.push_back(call);
}

void AddBoolCall(OracleSubtestTrace *subtest, const std::string &api, pqcfuzz_status status, bool accepted) {
  OracleCallTrace call;
  call.adapter = "left";
  call.api = api;
  call.status = status;
  call.has_bool_result = true;
  call.bool_result = accepted;
  call.executor_dispatched = true;
  call.adapter_entered = status != PQCFUZZ_API_UNSUPPORTED;
  call.target_entered = status != PQCFUZZ_API_UNSUPPORTED;
  call.target_returned = status != PQCFUZZ_CRASH && status != PQCFUZZ_TIMEOUT;
  call.rejection_layer = status == PQCFUZZ_REJECT ? "target" : "";
  subtest->calls.push_back(call);
}

KEMKeyPair Keygen(const pqcfuzz_kem_adapter *adapter, OracleSubtestTrace *subtest) {
  KEMKeyPair out;
  if (adapter == nullptr || adapter->keygen == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, "keygen", out.status);
    return out;
  }
  out.pk.resize(adapter->pk_len);
  out.sk.resize(adapter->sk_len);
  out.status = adapter->keygen(out.pk.data(), out.sk.data());
  AddCall(subtest, "keygen", out.status);
  return out;
}

KEMCiphertext Encaps(
    const pqcfuzz_kem_adapter *adapter,
    const std::vector<uint8_t> &pk,
    OracleSubtestTrace *subtest,
    KEMSharedSecret *shared_secret) {
  KEMCiphertext out;
  if (adapter == nullptr || adapter->encaps == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    if (shared_secret != nullptr) {
      shared_secret->status = out.status;
    }
    AddCall(subtest, "encaps", out.status);
    return out;
  }
  if (pk.size() != adapter->pk_len) {
    out.status = PQCFUZZ_INVALID_INPUT;
    if (shared_secret != nullptr) {
      shared_secret->status = out.status;
    }
    AddCall(subtest, "encaps", out.status);
    return out;
  }
  out.ct.resize(adapter->ct_len);
  if (shared_secret != nullptr) {
    shared_secret->ss.resize(adapter->ss_len);
    shared_secret->status = adapter->encaps(out.ct.data(), shared_secret->ss.data(), pk.data());
    out.status = shared_secret->status;
  } else {
    std::vector<uint8_t> ignored(adapter->ss_len);
    out.status = adapter->encaps(out.ct.data(), ignored.data(), pk.data());
  }
  AddCall(subtest, "encaps", out.status);
  return out;
}

KEMSharedSecret Decaps(
    const pqcfuzz_kem_adapter *adapter,
    const std::vector<uint8_t> &ct,
    const std::vector<uint8_t> &sk,
    OracleSubtestTrace *subtest) {
  KEMSharedSecret out;
  if (adapter == nullptr || adapter->decaps == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, "decaps", out.status);
    return out;
  }
  if (ct.size() != adapter->ct_len || sk.size() != adapter->sk_len) {
    out.status = PQCFUZZ_INVALID_INPUT;
    AddCall(subtest, "decaps", out.status);
    return out;
  }
  out.ss.resize(adapter->ss_len);
  out.status = adapter->decaps(out.ss.data(), ct.data(), sk.data());
  AddCall(subtest, "decaps", out.status);
  return out;
}

SIGKeyPair SigKeygen(const pqcfuzz_sig_adapter *adapter, OracleSubtestTrace *subtest) {
  SIGKeyPair out;
  if (adapter == nullptr || adapter->keygen == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, "keygen", out.status);
    return out;
  }
  out.pk.resize(adapter->pk_len);
  out.sk.resize(adapter->sk_len);
  out.status = adapter->keygen(out.pk.data(), out.sk.data());
  AddCall(subtest, "keygen", out.status);
  return out;
}

SIGSignature Sign(
    const pqcfuzz_sig_adapter *adapter,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &context,
    const std::vector<uint8_t> &sk,
    OracleSubtestTrace *subtest) {
  SIGSignature out;
  if (adapter == nullptr || adapter->sign == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddCall(subtest, "sign", out.status);
    return out;
  }
  if (context.size() > 255 || sk.size() != adapter->sk_len) {
    out.status = PQCFUZZ_INVALID_INPUT;
    AddCall(subtest, "sign", out.status);
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
  AddCall(subtest, "sign", out.status);
  return out;
}

SIGVerifyResult Verify(
    const pqcfuzz_sig_adapter *adapter,
    const std::vector<uint8_t> &signature,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &context,
    const std::vector<uint8_t> &pk,
    OracleSubtestTrace *subtest) {
  SIGVerifyResult out;
  if (adapter == nullptr || adapter->verify == nullptr) {
    out.status = PQCFUZZ_API_UNSUPPORTED;
    AddBoolCall(subtest, "verify", out.status, false);
    return out;
  }
  if (context.size() > 255 || pk.size() != adapter->pk_len || signature.size() > adapter->sig_max_len) {
    out.status = PQCFUZZ_INVALID_INPUT;
    AddBoolCall(subtest, "verify", out.status, false);
    return out;
  }
  const uint8_t *ctx = context.empty() ? nullptr : context.data();
  out.status = adapter->verify(signature.data(), signature.size(), message.data(), message.size(), pk.data(), ctx, context.size());
  out.accepted = out.status == PQCFUZZ_OK;
  AddBoolCall(subtest, "verify", out.status, out.accepted);
  return out;
}

Observation BytesObservation(pqcfuzz_status status, const std::vector<uint8_t> &bytes) {
  Observation observation;
  observation.status = status;
  observation.bytes = bytes;
  observation.crashed = status == PQCFUZZ_CRASH;
  observation.timed_out = status == PQCFUZZ_TIMEOUT;
  observation.unsupported = status == PQCFUZZ_API_UNSUPPORTED;
  return observation;
}

Observation BoolObservation(const SIGVerifyResult &verify) {
  Observation observation;
  observation.status = verify.status;
  observation.has_bool = true;
  observation.bool_value = verify.accepted;
  observation.bytes = {static_cast<uint8_t>(verify.accepted ? 1 : 0)};
  observation.crashed = verify.status == PQCFUZZ_CRASH;
  observation.timed_out = verify.status == PQCFUZZ_TIMEOUT;
  observation.unsupported = verify.status == PQCFUZZ_API_UNSUPPORTED;
  return observation;
}

std::vector<uint8_t> PublicAndSecretDigest(const std::vector<uint8_t> &public_key, const std::vector<uint8_t> &secret_key) {
  std::vector<uint8_t> out = public_key;
  const std::string digest = Sha256Hex(secret_key);
  out.insert(out.end(), digest.begin(), digest.end());
  return out;
}

std::vector<uint8_t> MakeTape(const std::vector<uint8_t> &seed, const std::string &label, bool all_zero) {
  std::vector<uint8_t> tape(256, 0);
  if (all_zero) {
    return tape;
  }
  // Labels such as "*-baseline" and "*-mutated" share a long textual
  // prefix.  Mixing a digest of the complete label into every byte prevents
  // short RNG consumers from receiving identical control tapes.
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

KEMOracleTrace BaseTrace(const std::string &job_id, const std::string &pair_id, const std::string &algorithm, const MetamorphicSpec &spec) {
  KEMOracleTrace trace;
  trace.oracle_suite = "metamorphic";
  trace.relation_mode = "single-target";
  trace.job_id = job_id;
  trace.pair_id = pair_id;
  trace.algorithm = algorithm;
  trace.configured_algorithm = algorithm;
  trace.oracle_id = spec.oracle_id;
  trace.field = spec.field;
  trace.mutation_target = spec.field;
  trace.expected_relation = spec.expected_relation;
  return trace;
}

void RecordMutationEvidence(
    MutationRecord *record,
    const std::vector<uint8_t> &original,
    const std::vector<uint8_t> &mutated) {
  if (record == nullptr) {
    return;
  }
  RecordMutationEffect(record, original, mutated);
  record->original_sha256 = Sha256Hex(original);
  record->mutated_sha256 = Sha256Hex(mutated);
}

std::string NonEvaluableDiagnostic(
    const Observation &baseline,
    const Observation &mutated,
    const MutationRecord *mutation,
    const std::string &reason);

void FinalizeNoEffect(
    KEMOracleTrace *trace,
    OracleSubtestTrace *subtest,
    const MetamorphicSpec &spec,
    const Observation &baseline,
    MutationRecord *mutation) {
  trace->observed_relation = "OBSERVED_INTERVENTION_NOT_EFFECTIVE";
  trace->baseline = ToObservationTrace(baseline);
  trace->mutated = ToObservationTrace(baseline);
  trace->valid_setup = baseline.status == PQCFUZZ_OK;
  trace->baseline_setup_valid = baseline.status == PQCFUZZ_OK;
  trace->mutated_setup_valid = baseline.status == PQCFUZZ_OK;
  trace->relation_evaluable = false;
  trace->intervention_effective = false;
  trace->diagnostic_event = NonEvaluableDiagnostic(baseline, baseline, mutation, "no_effect");
  trace->diagnostics.push_back({"non_evaluable", "metamorphic_relation", trace->diagnostic_event});
  subtest->skipped = true;
  subtest->passed = true;
  subtest->note = "no_effect";
  trace->mutations.push_back(*mutation);
  trace->subtests.push_back(*subtest);
}

void FinalizeRngInterventionNotObserved(
    KEMOracleTrace *trace,
    OracleSubtestTrace *subtest,
    const Observation &baseline,
    const Observation &mutated,
    const std::string &reason) {
  trace->observed_relation = "OBSERVED_INTERVENTION_NOT_OBSERVED";
  trace->baseline = ToObservationTrace(baseline);
  trace->mutated = ToObservationTrace(mutated);
  trace->valid_setup = baseline.status == PQCFUZZ_OK && mutated.status == PQCFUZZ_OK;
  trace->baseline_setup_valid = baseline.status == PQCFUZZ_OK;
  trace->mutated_setup_valid = mutated.status == PQCFUZZ_OK;
  trace->relation_evaluable = false;
  trace->intervention_supported = false;
  trace->intervention_effective = false;
  trace->relation_evaluable = false;
  trace->diagnostic_event = NonEvaluableDiagnostic(baseline, mutated, nullptr, reason);
  trace->diagnostics.push_back({"non_evaluable", "rng_intervention", trace->diagnostic_event});
  subtest->skipped = true;
  subtest->passed = true;
  subtest->note = reason;
  trace->subtests.push_back(*subtest);
}

bool RequireDistinctRngTapes(
    KEMOracleTrace *trace,
    OracleSubtestTrace *subtest,
    const RngInterventionTrace &rng_trace) {
  if (rng_trace.tapes_distinct) {
    return true;
  }
  trace->rng_interventions.push_back(rng_trace);
  trace->observed_relation = "OBSERVED_INTERVENTION_NOT_EFFECTIVE";
  trace->intervention_supported = false;
  trace->intervention_effective = false;
  trace->relation_evaluable = false;
  trace->diagnostic_event = "reason=rng_tapes_not_distinct;baseline_status=INVALID_INPUT;mutated_status=INVALID_INPUT;"
                            "mutation_operation=none;target=none;operation=none;original_len=0;mutated_len=0";
  trace->diagnostics.push_back({"non_evaluable", "rng_intervention", trace->diagnostic_event});
  subtest->skipped = true;
  subtest->passed = true;
  subtest->note = "rng_tapes_not_distinct";
  trace->subtests.push_back(*subtest);
  return false;
}

std::string FindingClassFor(const std::string &expected, ObservedRelation observed) {
  if (observed == ObservedRelation::kObservedCrash) {
    return "crash";
  }
  if (observed == ObservedRelation::kObservedHang) {
    return "hang";
  }
  if (observed == ObservedRelation::kObservedUnsupported) {
    return "unsupported";
  }
  if (expected == "EXPECT_DIFFERENT" && observed == ObservedRelation::kObservedEqual) {
    return "malleability";
  }
  if (expected == "EXPECT_EQUAL" && observed == ObservedRelation::kObservedDifferent) {
    return "non_malleability";
  }
  return "";
}

bool IsEvaluableObservation(const Observation &observation) {
  // A verify oracle deliberately drives the mutated input to rejection.  That
  // is a valid, security-relevant observation rather than a setup failure.
  return observation.status == PQCFUZZ_OK ||
         (observation.has_bool && observation.status == PQCFUZZ_REJECT);
}

const char *StatusName(pqcfuzz_status status) {
  switch (status) {
    case PQCFUZZ_OK:
      return "OK";
    case PQCFUZZ_REJECT:
      return "REJECT";
    case PQCFUZZ_INVALID_INPUT:
      return "INVALID_INPUT";
    case PQCFUZZ_CRASH:
      return "CRASH";
    case PQCFUZZ_TIMEOUT:
      return "TIMEOUT";
    case PQCFUZZ_API_UNSUPPORTED:
      return "API_UNSUPPORTED";
  }
  return "INVALID_INPUT";
}

bool HasUnsupportedObservation(const Observation &baseline, const Observation &mutated) {
  return baseline.unsupported || mutated.unsupported ||
         baseline.status == PQCFUZZ_API_UNSUPPORTED ||
         mutated.status == PQCFUZZ_API_UNSUPPORTED;
}

std::string MutationDiagnostics(const MutationRecord *mutation) {
  if (mutation == nullptr) {
    return "mutation_operation=none;target=none;operation=none;original_len=0;mutated_len=0";
  }
  std::ostringstream out;
  out << "mutation_operation=" << (mutation->operation.empty() ? "unknown" : mutation->operation)
      << ";target=" << (mutation->target.empty() ? "unknown" : mutation->target)
      << ";operation=" << (mutation->operation.empty() ? "unknown" : mutation->operation)
      << ";original_len=" << mutation->original_length
      << ";mutated_len=" << mutation->mutated_length;
  if (!mutation->field_parse_status.empty()) {
    out << ";field_parse_status=" << mutation->field_parse_status;
  }
  if (!mutation->reason.empty()) {
    out << ";mutation_reason=" << mutation->reason;
  }
  return out.str();
}

std::string NonEvaluableDiagnostic(
    const Observation &baseline,
    const Observation &mutated,
    const MutationRecord *mutation,
    const std::string &reason) {
  std::ostringstream out;
  if (!reason.empty()) {
    out << "reason=" << reason << ';';
  }
  out << "baseline_status=" << StatusName(baseline.status)
      << ";mutated_status=" << StatusName(mutated.status)
      << ';' << MutationDiagnostics(mutation);
  return out.str();
}

void FinalizeTrace(
    KEMOracleTrace *trace,
    OracleSubtestTrace *subtest,
    const MetamorphicSpec &spec,
    const Observation &baseline,
    const Observation &mutated,
    const MutationRecord *mutation) {
  const ObservedRelation observed = CompareObservations(baseline, mutated);
  trace->observed_relation = ObservedRelationName(observed);
  trace->baseline = ToObservationTrace(baseline);
  trace->mutated = ToObservationTrace(mutated);
  if (mutation != nullptr) {
    trace->mutations.push_back(*mutation);
    trace->intervention_effective = mutation->effective;
  }
  trace->valid_setup = IsEvaluableObservation(baseline) && IsEvaluableObservation(mutated);
  trace->baseline_setup_valid = IsEvaluableObservation(baseline);
  trace->mutated_setup_valid = IsEvaluableObservation(mutated);
  trace->relation_evaluable = trace->baseline_setup_valid && trace->mutated_setup_valid && trace->intervention_supported &&
                              trace->intervention_effective;
  if (!trace->relation_evaluable) {
    trace->diagnostic_event = NonEvaluableDiagnostic(baseline, mutated, mutation, "relation_not_evaluable");
    trace->diagnostics.push_back(
        {"non_evaluable", "metamorphic_relation", trace->diagnostic_event});
  }

  const std::string finding_class = FindingClassFor(spec.expected_relation, observed);
  if (finding_class == "unsupported") {
    subtest->skipped = true;
    subtest->passed = true;
    subtest->note = "adapter API unsupported";
  } else if (!finding_class.empty()) {
    subtest->passed = false;
    subtest->note = spec.finding_subclass;
  } else {
    subtest->passed = true;
  }
  trace->subtests.push_back(*subtest);

  if (!finding_class.empty()) {
    trace->finding_class = finding_class;
    trace->finding_subclass = spec.finding_subclass;
    trace->findings.push_back({finding_class, spec.finding_subclass, finding_class + ": " + spec.finding_subclass});
  }
}

void FinalizeSetupFailure(
    KEMOracleTrace *trace,
    OracleSubtestTrace *subtest,
    const Observation &setup_failure,
    const std::string &note) {
  trace->observed_relation = "OBSERVED_SETUP_FAILED";
  trace->baseline = ToObservationTrace(setup_failure);
  trace->mutated = ToObservationTrace(setup_failure);
  subtest->skipped = true;
  subtest->passed = true;
  subtest->note = note;
  trace->valid_setup = false;
  trace->baseline_setup_valid = false;
  trace->mutated_setup_valid = false;
  trace->relation_evaluable = false;
  trace->diagnostic_event = NonEvaluableDiagnostic(setup_failure, setup_failure, nullptr, note);
  trace->diagnostics.push_back({"non_evaluable", "setup", trace->diagnostic_event});
  trace->subtests.push_back(*subtest);
}

OracleSubtestTrace MakeSubtest(const MetamorphicSpec &spec) {
  OracleSubtestTrace subtest;
  subtest.subtest_id = spec.oracle_id;
  subtest.oracle_id = spec.oracle_id;
  subtest.expected_relation = spec.expected_relation;
  return subtest;
}

}  // namespace

KEMOracleTrace ExecuteMetamorphicKemOracle(const MetamorphicKemConfig &config) {
  const MetamorphicSpec *spec = FindMetamorphicSpec(config.oracle_id);
  if (spec == nullptr || spec->primitive_type != "kem") {
    KEMOracleTrace trace;
    trace.oracle_suite = "metamorphic";
    trace.relation_mode = "single-target";
    trace.job_id = config.job_id;
    trace.pair_id = config.pair_id;
    trace.algorithm = config.algorithm;
    trace.oracle_id = config.oracle_id;
    trace.finding_class = "unsupported";
    trace.findings.push_back({"unsupported", "unknown_oracle", "unknown metamorphic KEM oracle"});
    return trace;
  }

  KEMOracleTrace trace = BaseTrace(config.job_id, config.pair_id, config.algorithm, *spec);
  OracleSubtestTrace subtest = MakeSubtest(*spec);
  Observation baseline;
  Observation mutated;
  Observation setup_failure;
  bool observations_ready = false;
  bool setup_failed = false;
  std::string setup_failure_note;
  MutationRecord mutation_record;
  if (config.oracle_id == "kem_keygen_badrng") {
    const auto baseline_tape = MakeTape(config.seed, "kem-keygen-baseline", false);
    const auto mutated_tape = MakeTape(config.seed, "kem-keygen-mutated", false);
    RngInterventionTrace rng_trace;
    rng_trace.baseline_tape_id = "kem-keygen-baseline";
    rng_trace.mutated_tape_id = "kem-keygen-mutated";
    rng_trace.baseline_tape_sha256 = Sha256Hex(baseline_tape);
    rng_trace.mutated_tape_sha256 = Sha256Hex(mutated_tape);
    rng_trace.tapes_distinct = baseline_tape != mutated_tape;
    if (!RequireDistinctRngTapes(&trace, &subtest, rng_trace)) return trace;
    KEMKeyPair baseline_keypair;
    KEMKeyPair mutated_keypair;
    {
      ScopedRngOverride rng({baseline_tape.data(), baseline_tape.size(), true});
      rng_trace.baseline_override_active = rng.active();
      baseline_keypair = Keygen(config.target, &subtest);
      rng_trace.baseline_bytes_consumed = rng.bytes_consumed();
    }
    {
      ScopedRngOverride rng({mutated_tape.data(), mutated_tape.size(), true});
      rng_trace.mutated_override_active = rng.active();
      mutated_keypair = Keygen(config.target, &subtest);
      rng_trace.mutated_bytes_consumed = rng.bytes_consumed();
    }
    baseline = BytesObservation(baseline_keypair.status, PublicAndSecretDigest(baseline_keypair.pk, baseline_keypair.sk));
    mutated = BytesObservation(mutated_keypair.status, PublicAndSecretDigest(mutated_keypair.pk, mutated_keypair.sk));
    trace.rng_interventions.push_back(rng_trace);
    if (!HasUnsupportedObservation(baseline, mutated)) {
      if (!rng_trace.tapes_distinct || !rng_trace.baseline_override_active || !rng_trace.mutated_override_active) {
        FinalizeRngInterventionNotObserved(&trace, &subtest, baseline, mutated, "rng_override_unavailable");
        return trace;
      }
      if (rng_trace.baseline_bytes_consumed == 0 || rng_trace.mutated_bytes_consumed == 0) {
        FinalizeRngInterventionNotObserved(&trace, &subtest, baseline, mutated, "intervention_not_observed");
        return trace;
      }
    }
    observations_ready = true;
  } else {
    KEMKeyPair keypair = Keygen(config.target, &subtest);
    KEMSharedSecret encaps_ss;
    KEMCiphertext ciphertext;
    if (keypair.status == PQCFUZZ_OK) {
      if (config.oracle_id == "kem_encaps_badrng") {
        const auto baseline_tape = MakeTape(config.seed, "kem-encaps-baseline", false);
        const auto mutated_tape = MakeTape(config.seed, "kem-encaps-mutated", false);
        RngInterventionTrace rng_trace;
        rng_trace.baseline_tape_id = "kem-encaps-baseline";
        rng_trace.mutated_tape_id = "kem-encaps-mutated";
        rng_trace.baseline_tape_sha256 = Sha256Hex(baseline_tape);
        rng_trace.mutated_tape_sha256 = Sha256Hex(mutated_tape);
        rng_trace.tapes_distinct = baseline_tape != mutated_tape;
        if (!RequireDistinctRngTapes(&trace, &subtest, rng_trace)) return trace;
        KEMSharedSecret mutated_ss;
        KEMCiphertext mutated_ct;
        {
          ScopedRngOverride rng({baseline_tape.data(), baseline_tape.size(), true});
          rng_trace.baseline_override_active = rng.active();
          ciphertext = Encaps(config.target, keypair.pk, &subtest, &encaps_ss);
          rng_trace.baseline_bytes_consumed = rng.bytes_consumed();
        }
        {
          ScopedRngOverride rng({mutated_tape.data(), mutated_tape.size(), true});
          rng_trace.mutated_override_active = rng.active();
          mutated_ct = Encaps(config.target, keypair.pk, &subtest, &mutated_ss);
          rng_trace.mutated_bytes_consumed = rng.bytes_consumed();
        }
        std::vector<uint8_t> baseline_bytes = ciphertext.ct;
        baseline_bytes.insert(baseline_bytes.end(), encaps_ss.ss.begin(), encaps_ss.ss.end());
        std::vector<uint8_t> mutated_bytes = mutated_ct.ct;
        mutated_bytes.insert(mutated_bytes.end(), mutated_ss.ss.begin(), mutated_ss.ss.end());
        baseline = BytesObservation(ciphertext.status, baseline_bytes);
        mutated = BytesObservation(mutated_ct.status, mutated_bytes);
        trace.rng_interventions.push_back(rng_trace);
        if (!HasUnsupportedObservation(baseline, mutated)) {
          if (!rng_trace.tapes_distinct || !rng_trace.baseline_override_active || !rng_trace.mutated_override_active) {
            FinalizeRngInterventionNotObserved(&trace, &subtest, baseline, mutated, "rng_override_unavailable");
            return trace;
          }
          if (rng_trace.baseline_bytes_consumed == 0 || rng_trace.mutated_bytes_consumed == 0) {
            FinalizeRngInterventionNotObserved(&trace, &subtest, baseline, mutated, "intervention_not_observed");
            return trace;
          }
        }
        observations_ready = true;
      } else {
        ciphertext = Encaps(config.target, keypair.pk, &subtest, &encaps_ss);
        if (ciphertext.status == PQCFUZZ_API_UNSUPPORTED) {
          baseline = BytesObservation(ciphertext.status, {});
          mutated = baseline;
          observations_ready = true;
        } else if (ciphertext.status != PQCFUZZ_OK) {
          setup_failure = BytesObservation(ciphertext.status, {});
          setup_failure_note = "setup encaps failed";
          setup_failed = true;
        }
      }
    } else if (keypair.status == PQCFUZZ_API_UNSUPPORTED) {
      baseline = BytesObservation(keypair.status, {});
      mutated = baseline;
      observations_ready = true;
    } else {
      setup_failure = BytesObservation(keypair.status, {});
      setup_failure_note = "setup keygen failed";
      setup_failed = true;
    }

    if (config.oracle_id == "kem_encaps_pk" && keypair.status == PQCFUZZ_OK && ciphertext.status == PQCFUZZ_OK) {
      MaulResult maul = MaulBytesFixedSize(keypair.pk, config.mutation, "public_key");
      mutation_record = maul.record;
      RecordMutationEvidence(&mutation_record, keypair.pk, maul.mutated);
      std::vector<uint8_t> baseline_bytes = ciphertext.ct;
      baseline_bytes.insert(baseline_bytes.end(), encaps_ss.ss.begin(), encaps_ss.ss.end());
      baseline = BytesObservation(ciphertext.status, baseline_bytes);
      if (!mutation_record.effective) {
        FinalizeNoEffect(&trace, &subtest, *spec, baseline, &mutation_record);
        return trace;
      }
      KEMSharedSecret mutated_ss;
      KEMCiphertext mutated_ct = Encaps(config.target, maul.mutated, &subtest, &mutated_ss);
      std::vector<uint8_t> mutated_bytes = mutated_ct.ct;
      mutated_bytes.insert(mutated_bytes.end(), mutated_ss.ss.begin(), mutated_ss.ss.end());
      baseline = BytesObservation(ciphertext.status, baseline_bytes);
      mutated = BytesObservation(mutated_ct.status, mutated_bytes);
      observations_ready = true;
    } else if (config.oracle_id == "kem_encaps_pk_0" && keypair.status == PQCFUZZ_OK && ciphertext.status == PQCFUZZ_OK) {
      std::vector<uint8_t> zero_pk(keypair.pk.size(), 0);
      mutation_record.operation = "replace_with_all_zero";
      mutation_record.target = "public_key";
      mutation_record.length = zero_pk.size();
      mutation_record.field_parse_status = "generic_byte_field";
      RecordMutationEvidence(&mutation_record, keypair.pk, zero_pk);
      std::vector<uint8_t> baseline_bytes = ciphertext.ct;
      baseline_bytes.insert(baseline_bytes.end(), encaps_ss.ss.begin(), encaps_ss.ss.end());
      baseline = BytesObservation(ciphertext.status, baseline_bytes);
      if (!mutation_record.effective) {
        FinalizeNoEffect(&trace, &subtest, *spec, baseline, &mutation_record);
        return trace;
      }
      KEMSharedSecret mutated_ss;
      KEMCiphertext mutated_ct = Encaps(config.target, zero_pk, &subtest, &mutated_ss);
      std::vector<uint8_t> mutated_bytes = mutated_ct.ct;
      mutated_bytes.insert(mutated_bytes.end(), mutated_ss.ss.begin(), mutated_ss.ss.end());
      baseline = BytesObservation(ciphertext.status, baseline_bytes);
      mutated = BytesObservation(mutated_ct.status, mutated_bytes);
      observations_ready = true;
    } else if (config.oracle_id == "kem_decaps_c" && ciphertext.status == PQCFUZZ_OK) {
      KEMSharedSecret baseline_decaps = Decaps(config.target, ciphertext.ct, keypair.sk, &subtest);
      MaulResult maul = MaulBytesFixedSize(ciphertext.ct, config.mutation, "ciphertext");
      mutation_record = maul.record;
      RecordMutationEvidence(&mutation_record, ciphertext.ct, maul.mutated);
      baseline = BytesObservation(baseline_decaps.status, baseline_decaps.ss);
      if (!mutation_record.effective) {
        FinalizeNoEffect(&trace, &subtest, *spec, baseline, &mutation_record);
        return trace;
      }
      KEMSharedSecret mutated_decaps = Decaps(config.target, maul.mutated, keypair.sk, &subtest);
      mutated = BytesObservation(mutated_decaps.status, mutated_decaps.ss);
      observations_ready = true;
    } else if (config.oracle_id == "kem_decaps_sk" && ciphertext.status == PQCFUZZ_OK) {
      KEMSharedSecret baseline_decaps = Decaps(config.target, ciphertext.ct, keypair.sk, &subtest);
      MaulResult maul = MaulBytesFixedSize(keypair.sk, config.mutation, "secret_key");
      mutation_record = maul.record;
      RecordMutationEvidence(&mutation_record, keypair.sk, maul.mutated);
      baseline = BytesObservation(baseline_decaps.status, baseline_decaps.ss);
      if (!mutation_record.effective) {
        FinalizeNoEffect(&trace, &subtest, *spec, baseline, &mutation_record);
        return trace;
      }
      KEMSharedSecret mutated_decaps = Decaps(config.target, ciphertext.ct, maul.mutated, &subtest);
      mutated = BytesObservation(mutated_decaps.status, mutated_decaps.ss);
      observations_ready = true;
    }
  }

  if (!observations_ready && setup_failed) {
    FinalizeSetupFailure(&trace, &subtest, setup_failure, setup_failure_note);
    return trace;
  }
  FinalizeTrace(&trace, &subtest, *spec, baseline, mutated, mutation_record.target.empty() ? nullptr : &mutation_record);
  return trace;
}

KEMOracleTrace ExecuteMetamorphicSigOracle(const MetamorphicSigConfig &config) {
  const MetamorphicSpec *spec = FindMetamorphicSpec(config.oracle_id);
  if (spec == nullptr || spec->primitive_type != "sig") {
    KEMOracleTrace trace;
    trace.oracle_suite = "metamorphic";
    trace.relation_mode = "single-target";
    trace.job_id = config.job_id;
    trace.pair_id = config.pair_id;
    trace.algorithm = config.algorithm;
    trace.oracle_id = config.oracle_id;
    trace.finding_class = "unsupported";
    trace.findings.push_back({"unsupported", "unknown_oracle", "unknown metamorphic SIG oracle"});
    return trace;
  }

  KEMOracleTrace trace = BaseTrace(config.job_id, config.pair_id, config.algorithm, *spec);
  OracleSubtestTrace subtest = MakeSubtest(*spec);
  Observation baseline;
  Observation mutated;
  Observation setup_failure;
  bool observations_ready = false;
  bool setup_failed = false;
  std::string setup_failure_note;
  MutationRecord mutation_record;
  const std::vector<uint8_t> message = config.message.empty()
                                          ? std::vector<uint8_t>{'P', 'Q', 'C', 'F', 'u', 'z', 'z'}
                                          : config.message;
  if (config.oracle_id == "sig_keygen_badrng") {
    const auto baseline_tape = MakeTape(config.seed, "sig-keygen-baseline", false);
    const auto mutated_tape = MakeTape(config.seed, "sig-keygen-mutated", false);
    RngInterventionTrace rng_trace;
    rng_trace.baseline_tape_id = "sig-keygen-baseline";
    rng_trace.mutated_tape_id = "sig-keygen-mutated";
    rng_trace.baseline_tape_sha256 = Sha256Hex(baseline_tape);
    rng_trace.mutated_tape_sha256 = Sha256Hex(mutated_tape);
    rng_trace.tapes_distinct = baseline_tape != mutated_tape;
    if (!RequireDistinctRngTapes(&trace, &subtest, rng_trace)) return trace;
    SIGKeyPair baseline_keypair;
    SIGKeyPair mutated_keypair;
    {
      ScopedRngOverride rng({baseline_tape.data(), baseline_tape.size(), true});
      rng_trace.baseline_override_active = rng.active();
      baseline_keypair = SigKeygen(config.target, &subtest);
      rng_trace.baseline_bytes_consumed = rng.bytes_consumed();
    }
    {
      ScopedRngOverride rng({mutated_tape.data(), mutated_tape.size(), true});
      rng_trace.mutated_override_active = rng.active();
      mutated_keypair = SigKeygen(config.target, &subtest);
      rng_trace.mutated_bytes_consumed = rng.bytes_consumed();
    }
    baseline = BytesObservation(baseline_keypair.status, PublicAndSecretDigest(baseline_keypair.pk, baseline_keypair.sk));
    mutated = BytesObservation(mutated_keypair.status, PublicAndSecretDigest(mutated_keypair.pk, mutated_keypair.sk));
    trace.rng_interventions.push_back(rng_trace);
    if (!HasUnsupportedObservation(baseline, mutated)) {
      if (!rng_trace.tapes_distinct || !rng_trace.baseline_override_active || !rng_trace.mutated_override_active) {
        FinalizeRngInterventionNotObserved(&trace, &subtest, baseline, mutated, "rng_override_unavailable");
        return trace;
      }
      if (rng_trace.baseline_bytes_consumed == 0 || rng_trace.mutated_bytes_consumed == 0) {
        FinalizeRngInterventionNotObserved(&trace, &subtest, baseline, mutated, "intervention_not_observed");
        return trace;
      }
    }
    observations_ready = true;
  } else {
    SIGKeyPair keypair = SigKeygen(config.target, &subtest);
    SIGSignature signature;
    if (keypair.status == PQCFUZZ_OK) {
      if (config.oracle_id == "sig_sign_badrng") {
        if (config.target != nullptr && config.target->supports_deterministic_sign && !config.target->supports_seeded_sign) {
          baseline = BytesObservation(PQCFUZZ_API_UNSUPPORTED, {});
          mutated = baseline;
          observations_ready = true;
        } else {
          const auto baseline_tape = MakeTape(config.seed, "sig-sign-baseline", false);
          const auto mutated_tape = MakeTape(config.seed, "sig-sign-mutated", false);
          RngInterventionTrace rng_trace;
          rng_trace.baseline_tape_id = "sig-sign-baseline";
          rng_trace.mutated_tape_id = "sig-sign-mutated";
          rng_trace.baseline_tape_sha256 = Sha256Hex(baseline_tape);
          rng_trace.mutated_tape_sha256 = Sha256Hex(mutated_tape);
          rng_trace.tapes_distinct = baseline_tape != mutated_tape;
          if (!RequireDistinctRngTapes(&trace, &subtest, rng_trace)) return trace;
          SIGSignature mutated_signature;
          {
            ScopedRngOverride rng({baseline_tape.data(), baseline_tape.size(), true});
            rng_trace.baseline_override_active = rng.active();
            signature = Sign(config.target, message, config.context, keypair.sk, &subtest);
            rng_trace.baseline_bytes_consumed = rng.bytes_consumed();
          }
          {
            ScopedRngOverride rng({mutated_tape.data(), mutated_tape.size(), true});
            rng_trace.mutated_override_active = rng.active();
            mutated_signature = Sign(config.target, message, config.context, keypair.sk, &subtest);
            rng_trace.mutated_bytes_consumed = rng.bytes_consumed();
          }
          baseline = BytesObservation(signature.status, signature.sig);
          mutated = BytesObservation(mutated_signature.status, mutated_signature.sig);
          trace.rng_interventions.push_back(rng_trace);
          if (!HasUnsupportedObservation(baseline, mutated)) {
            if (!rng_trace.tapes_distinct || !rng_trace.baseline_override_active || !rng_trace.mutated_override_active) {
              FinalizeRngInterventionNotObserved(&trace, &subtest, baseline, mutated, "rng_override_unavailable");
              return trace;
            }
            if (rng_trace.baseline_bytes_consumed == 0 || rng_trace.mutated_bytes_consumed == 0) {
              FinalizeRngInterventionNotObserved(&trace, &subtest, baseline, mutated, "intervention_not_observed");
              return trace;
            }
          }
          observations_ready = true;
        }
      } else {
        signature = Sign(config.target, message, config.context, keypair.sk, &subtest);
        if (signature.status == PQCFUZZ_API_UNSUPPORTED) {
          baseline = BytesObservation(signature.status, {});
          mutated = baseline;
          observations_ready = true;
        } else if (signature.status != PQCFUZZ_OK) {
          setup_failure = BytesObservation(signature.status, {});
          setup_failure_note = "setup sign failed";
          setup_failed = true;
        }
      }
    } else if (keypair.status == PQCFUZZ_API_UNSUPPORTED) {
      baseline = BytesObservation(keypair.status, {});
      mutated = baseline;
      observations_ready = true;
    } else {
      setup_failure = BytesObservation(keypair.status, {});
      setup_failure_note = "setup keygen failed";
      setup_failed = true;
    }

    if (config.oracle_id == "sig_sign_m" && signature.status == PQCFUZZ_OK) {
      MaulResult maul = MaulBytesFixedSize(message, config.mutation, "message");
      mutation_record = maul.record;
      RecordMutationEvidence(&mutation_record, message, maul.mutated);
      baseline = BytesObservation(signature.status, signature.sig);
      if (!mutation_record.effective) {
        FinalizeNoEffect(&trace, &subtest, *spec, baseline, &mutation_record);
        return trace;
      }
      SIGSignature mutated_signature = Sign(config.target, maul.mutated, config.context, keypair.sk, &subtest);
      mutated = BytesObservation(mutated_signature.status, mutated_signature.sig);
      observations_ready = true;
    } else if (config.oracle_id == "sig_sign_sk" && signature.status == PQCFUZZ_OK) {
      MaulResult maul = MaulBytesFixedSize(keypair.sk, config.mutation, "secret_key");
      mutation_record = maul.record;
      RecordMutationEvidence(&mutation_record, keypair.sk, maul.mutated);
      baseline = BytesObservation(signature.status, signature.sig);
      if (!mutation_record.effective) {
        FinalizeNoEffect(&trace, &subtest, *spec, baseline, &mutation_record);
        return trace;
      }
      SIGSignature mutated_signature = Sign(config.target, message, config.context, maul.mutated, &subtest);
      mutated = BytesObservation(mutated_signature.status, mutated_signature.sig);
      observations_ready = true;
    } else if (config.oracle_id == "sig_verify_m" && signature.status == PQCFUZZ_OK) {
      SIGVerifyResult baseline_verify = Verify(config.target, signature.sig, message, config.context, keypair.pk, &subtest);
      MaulResult maul = MaulBytesFixedSize(message, config.mutation, "message");
      mutation_record = maul.record;
      RecordMutationEvidence(&mutation_record, message, maul.mutated);
      baseline = BoolObservation(baseline_verify);
      if (!mutation_record.effective) {
        FinalizeNoEffect(&trace, &subtest, *spec, baseline, &mutation_record);
        return trace;
      }
      SIGVerifyResult mutated_verify = Verify(config.target, signature.sig, maul.mutated, config.context, keypair.pk, &subtest);
      mutated = BoolObservation(mutated_verify);
      observations_ready = true;
    } else if (config.oracle_id == "sig_verify_sig" && signature.status == PQCFUZZ_OK) {
      SIGVerifyResult baseline_verify = Verify(config.target, signature.sig, message, config.context, keypair.pk, &subtest);
      MaulResult maul = MaulBytesFixedSize(signature.sig, config.mutation, "signature");
      mutation_record = maul.record;
      RecordMutationEvidence(&mutation_record, signature.sig, maul.mutated);
      baseline = BoolObservation(baseline_verify);
      if (!mutation_record.effective) {
        FinalizeNoEffect(&trace, &subtest, *spec, baseline, &mutation_record);
        return trace;
      }
      SIGVerifyResult mutated_verify = Verify(config.target, maul.mutated, message, config.context, keypair.pk, &subtest);
      mutated = BoolObservation(mutated_verify);
      observations_ready = true;
    } else if (config.oracle_id == "sig_verify_pk" && signature.status == PQCFUZZ_OK) {
      SIGVerifyResult baseline_verify = Verify(config.target, signature.sig, message, config.context, keypair.pk, &subtest);
      MaulResult maul = MaulBytesFixedSize(keypair.pk, config.mutation, "public_key");
      mutation_record = maul.record;
      RecordMutationEvidence(&mutation_record, keypair.pk, maul.mutated);
      baseline = BoolObservation(baseline_verify);
      if (!mutation_record.effective) {
        FinalizeNoEffect(&trace, &subtest, *spec, baseline, &mutation_record);
        return trace;
      }
      SIGVerifyResult mutated_verify = Verify(config.target, signature.sig, message, config.context, maul.mutated, &subtest);
      mutated = BoolObservation(mutated_verify);
      observations_ready = true;
    }
  }

  if (!observations_ready && setup_failed) {
    FinalizeSetupFailure(&trace, &subtest, setup_failure, setup_failure_note);
    return trace;
  }
  FinalizeTrace(&trace, &subtest, *spec, baseline, mutated, mutation_record.target.empty() ? nullptr : &mutation_record);
  return trace;
}

}  // namespace pqcfuzz

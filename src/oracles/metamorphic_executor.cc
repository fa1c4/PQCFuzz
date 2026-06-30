#include "oracles/metamorphic_executor.h"

#include <algorithm>
#include <string>

#include "adapters/rng_control.h"
#include "mutators/maul.h"
#include "oracles/metamorphic_observation.h"
#include "oracles/metamorphic_spec.h"

namespace pqcfuzz {
namespace {

void AddCall(OracleSubtestTrace *subtest, const std::string &api, pqcfuzz_status status) {
  subtest->calls.push_back({"left", api, status, false, false});
}

void AddBoolCall(OracleSubtestTrace *subtest, const std::string &api, pqcfuzz_status status, bool accepted) {
  subtest->calls.push_back({"left", api, status, true, accepted});
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
  for (size_t i = 0; i < tape.size(); ++i) {
    const uint8_t seed_byte = seed.empty() ? static_cast<uint8_t>(i * 17u) : seed[i % seed.size()];
    const uint8_t label_byte = label.empty() ? 0x5a : static_cast<uint8_t>(label[i % label.size()]);
    tape[i] = static_cast<uint8_t>(seed_byte ^ label_byte ^ (i * 29u));
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
  trace.oracle_id = spec.oracle_id;
  trace.field = spec.field;
  trace.mutation_target = spec.field;
  trace.expected_relation = spec.expected_relation;
  return trace;
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
  MutationRecord mutation_record;
  const bool reused_seed = !config.mutation.empty() && (config.mutation[0] & 1u) != 0;

  if (config.oracle_id == "kem_keygen_badrng") {
    const auto baseline_tape = MakeTape(config.seed, "kem-keygen-baseline", false);
    const auto mutated_tape = MakeTape(config.seed, "kem-keygen-mutated", !reused_seed);
    KEMKeyPair baseline_keypair;
    KEMKeyPair mutated_keypair;
    {
      ScopedRngOverride rng({baseline_tape.data(), baseline_tape.size(), true});
      baseline_keypair = Keygen(config.target, &subtest);
    }
    {
      ScopedRngOverride rng({(reused_seed ? baseline_tape : mutated_tape).data(), (reused_seed ? baseline_tape : mutated_tape).size(), true});
      mutated_keypair = Keygen(config.target, &subtest);
    }
    baseline = BytesObservation(baseline_keypair.status, PublicAndSecretDigest(baseline_keypair.pk, baseline_keypair.sk));
    mutated = BytesObservation(mutated_keypair.status, PublicAndSecretDigest(mutated_keypair.pk, mutated_keypair.sk));
  } else {
    KEMKeyPair keypair = Keygen(config.target, &subtest);
    KEMSharedSecret encaps_ss;
    KEMCiphertext ciphertext;
    if (keypair.status == PQCFUZZ_OK) {
      if (config.oracle_id == "kem_encaps_badrng") {
        const auto baseline_tape = MakeTape(config.seed, "kem-encaps-baseline", false);
        const auto mutated_tape = MakeTape(config.seed, "kem-encaps-mutated", !reused_seed);
        KEMSharedSecret mutated_ss;
        KEMCiphertext mutated_ct;
        {
          ScopedRngOverride rng({baseline_tape.data(), baseline_tape.size(), true});
          ciphertext = Encaps(config.target, keypair.pk, &subtest, &encaps_ss);
        }
        {
          ScopedRngOverride rng({(reused_seed ? baseline_tape : mutated_tape).data(), (reused_seed ? baseline_tape : mutated_tape).size(), true});
          mutated_ct = Encaps(config.target, keypair.pk, &subtest, &mutated_ss);
        }
        std::vector<uint8_t> baseline_bytes = ciphertext.ct;
        baseline_bytes.insert(baseline_bytes.end(), encaps_ss.ss.begin(), encaps_ss.ss.end());
        std::vector<uint8_t> mutated_bytes = mutated_ct.ct;
        mutated_bytes.insert(mutated_bytes.end(), mutated_ss.ss.begin(), mutated_ss.ss.end());
        baseline = BytesObservation(ciphertext.status, baseline_bytes);
        mutated = BytesObservation(mutated_ct.status, mutated_bytes);
      } else {
        ciphertext = Encaps(config.target, keypair.pk, &subtest, &encaps_ss);
      }
    }

    if (config.oracle_id == "kem_encaps_pk" && keypair.status == PQCFUZZ_OK && ciphertext.status == PQCFUZZ_OK) {
      MaulResult maul = MaulBytes(keypair.pk, config.mutation, "public_key");
      mutation_record = maul.record;
      KEMSharedSecret mutated_ss;
      KEMCiphertext mutated_ct = Encaps(config.target, maul.mutated, &subtest, &mutated_ss);
      std::vector<uint8_t> baseline_bytes = ciphertext.ct;
      baseline_bytes.insert(baseline_bytes.end(), encaps_ss.ss.begin(), encaps_ss.ss.end());
      std::vector<uint8_t> mutated_bytes = mutated_ct.ct;
      mutated_bytes.insert(mutated_bytes.end(), mutated_ss.ss.begin(), mutated_ss.ss.end());
      baseline = BytesObservation(ciphertext.status, baseline_bytes);
      mutated = BytesObservation(mutated_ct.status, mutated_bytes);
    } else if (config.oracle_id == "kem_encaps_pk_0" && keypair.status == PQCFUZZ_OK && ciphertext.status == PQCFUZZ_OK) {
      std::vector<uint8_t> zero_pk(keypair.pk.size(), 0);
      mutation_record.operation = "replace_with_all_zero";
      mutation_record.target = "public_key";
      mutation_record.length = zero_pk.size();
      KEMSharedSecret mutated_ss;
      KEMCiphertext mutated_ct = Encaps(config.target, zero_pk, &subtest, &mutated_ss);
      std::vector<uint8_t> baseline_bytes = ciphertext.ct;
      baseline_bytes.insert(baseline_bytes.end(), encaps_ss.ss.begin(), encaps_ss.ss.end());
      std::vector<uint8_t> mutated_bytes = mutated_ct.ct;
      mutated_bytes.insert(mutated_bytes.end(), mutated_ss.ss.begin(), mutated_ss.ss.end());
      baseline = BytesObservation(ciphertext.status, baseline_bytes);
      mutated = BytesObservation(mutated_ct.status, mutated_bytes);
    } else if (config.oracle_id == "kem_decaps_c" && ciphertext.status == PQCFUZZ_OK) {
      KEMSharedSecret baseline_decaps = Decaps(config.target, ciphertext.ct, keypair.sk, &subtest);
      MaulResult maul = MaulBytes(ciphertext.ct, config.mutation, "ciphertext");
      mutation_record = maul.record;
      KEMSharedSecret mutated_decaps = Decaps(config.target, maul.mutated, keypair.sk, &subtest);
      baseline = BytesObservation(baseline_decaps.status, baseline_decaps.ss);
      mutated = BytesObservation(mutated_decaps.status, mutated_decaps.ss);
    } else if (config.oracle_id == "kem_decaps_sk" && ciphertext.status == PQCFUZZ_OK) {
      KEMSharedSecret baseline_decaps = Decaps(config.target, ciphertext.ct, keypair.sk, &subtest);
      MaulResult maul = MaulBytes(keypair.sk, config.mutation, "secret_key");
      mutation_record = maul.record;
      KEMSharedSecret mutated_decaps = Decaps(config.target, ciphertext.ct, maul.mutated, &subtest);
      baseline = BytesObservation(baseline_decaps.status, baseline_decaps.ss);
      mutated = BytesObservation(mutated_decaps.status, mutated_decaps.ss);
    } else if (baseline.status == PQCFUZZ_INVALID_INPUT && mutated.status == PQCFUZZ_INVALID_INPUT) {
      baseline = BytesObservation(keypair.status == PQCFUZZ_OK ? ciphertext.status : keypair.status, {});
      mutated = baseline;
    }
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
  MutationRecord mutation_record;
  const std::vector<uint8_t> message = config.message.empty()
                                          ? std::vector<uint8_t>{'P', 'Q', 'C', 'F', 'u', 'z', 'z'}
                                          : config.message;
  const bool reused_seed = !config.mutation.empty() && (config.mutation[0] & 1u) != 0;

  if (config.oracle_id == "sig_keygen_badrng") {
    const auto baseline_tape = MakeTape(config.seed, "sig-keygen-baseline", false);
    const auto mutated_tape = MakeTape(config.seed, "sig-keygen-mutated", !reused_seed);
    SIGKeyPair baseline_keypair;
    SIGKeyPair mutated_keypair;
    {
      ScopedRngOverride rng({baseline_tape.data(), baseline_tape.size(), true});
      baseline_keypair = SigKeygen(config.target, &subtest);
    }
    {
      ScopedRngOverride rng({(reused_seed ? baseline_tape : mutated_tape).data(), (reused_seed ? baseline_tape : mutated_tape).size(), true});
      mutated_keypair = SigKeygen(config.target, &subtest);
    }
    baseline = BytesObservation(baseline_keypair.status, PublicAndSecretDigest(baseline_keypair.pk, baseline_keypair.sk));
    mutated = BytesObservation(mutated_keypair.status, PublicAndSecretDigest(mutated_keypair.pk, mutated_keypair.sk));
  } else {
    SIGKeyPair keypair = SigKeygen(config.target, &subtest);
    SIGSignature signature;
    if (keypair.status == PQCFUZZ_OK) {
      if (config.oracle_id == "sig_sign_badrng") {
        if (config.target != nullptr && config.target->supports_deterministic_sign && !config.target->supports_seeded_sign) {
          baseline = BytesObservation(PQCFUZZ_API_UNSUPPORTED, {});
          mutated = baseline;
        } else {
          const auto baseline_tape = MakeTape(config.seed, "sig-sign-baseline", false);
          const auto mutated_tape = MakeTape(config.seed, "sig-sign-mutated", !reused_seed);
          SIGSignature mutated_signature;
          {
            ScopedRngOverride rng({baseline_tape.data(), baseline_tape.size(), true});
            signature = Sign(config.target, message, config.context, keypair.sk, &subtest);
          }
          {
            ScopedRngOverride rng({(reused_seed ? baseline_tape : mutated_tape).data(), (reused_seed ? baseline_tape : mutated_tape).size(), true});
            mutated_signature = Sign(config.target, message, config.context, keypair.sk, &subtest);
          }
          baseline = BytesObservation(signature.status, signature.sig);
          mutated = BytesObservation(mutated_signature.status, mutated_signature.sig);
        }
      } else {
        signature = Sign(config.target, message, config.context, keypair.sk, &subtest);
      }
    }

    if (config.oracle_id == "sig_sign_m" && signature.status == PQCFUZZ_OK) {
      MaulResult maul = MaulBytes(message, config.mutation, "message");
      mutation_record = maul.record;
      SIGSignature mutated_signature = Sign(config.target, maul.mutated, config.context, keypair.sk, &subtest);
      baseline = BytesObservation(signature.status, signature.sig);
      mutated = BytesObservation(mutated_signature.status, mutated_signature.sig);
    } else if (config.oracle_id == "sig_sign_sk" && signature.status == PQCFUZZ_OK) {
      MaulResult maul = MaulBytes(keypair.sk, config.mutation, "secret_key");
      mutation_record = maul.record;
      SIGSignature mutated_signature = Sign(config.target, message, config.context, maul.mutated, &subtest);
      baseline = BytesObservation(signature.status, signature.sig);
      mutated = BytesObservation(mutated_signature.status, mutated_signature.sig);
    } else if (config.oracle_id == "sig_verify_m" && signature.status == PQCFUZZ_OK) {
      SIGVerifyResult baseline_verify = Verify(config.target, signature.sig, message, config.context, keypair.pk, &subtest);
      MaulResult maul = MaulBytes(message, config.mutation, "message");
      mutation_record = maul.record;
      SIGVerifyResult mutated_verify = Verify(config.target, signature.sig, maul.mutated, config.context, keypair.pk, &subtest);
      baseline = BoolObservation(baseline_verify);
      mutated = BoolObservation(mutated_verify);
    } else if (config.oracle_id == "sig_verify_sig" && signature.status == PQCFUZZ_OK) {
      SIGVerifyResult baseline_verify = Verify(config.target, signature.sig, message, config.context, keypair.pk, &subtest);
      MaulResult maul = MaulBytes(signature.sig, config.mutation, "signature");
      mutation_record = maul.record;
      SIGVerifyResult mutated_verify = Verify(config.target, maul.mutated, message, config.context, keypair.pk, &subtest);
      baseline = BoolObservation(baseline_verify);
      mutated = BoolObservation(mutated_verify);
    } else if (config.oracle_id == "sig_verify_pk" && signature.status == PQCFUZZ_OK) {
      SIGVerifyResult baseline_verify = Verify(config.target, signature.sig, message, config.context, keypair.pk, &subtest);
      MaulResult maul = MaulBytes(keypair.pk, config.mutation, "public_key");
      mutation_record = maul.record;
      SIGVerifyResult mutated_verify = Verify(config.target, signature.sig, message, config.context, maul.mutated, &subtest);
      baseline = BoolObservation(baseline_verify);
      mutated = BoolObservation(mutated_verify);
    } else if (baseline.status == PQCFUZZ_INVALID_INPUT && mutated.status == PQCFUZZ_INVALID_INPUT) {
      baseline = BytesObservation(keypair.status == PQCFUZZ_OK ? signature.status : keypair.status, {});
      mutated = baseline;
    }
  }

  FinalizeTrace(&trace, &subtest, *spec, baseline, mutated, mutation_record.target.empty() ? nullptr : &mutation_record);
  return trace;
}

}  // namespace pqcfuzz

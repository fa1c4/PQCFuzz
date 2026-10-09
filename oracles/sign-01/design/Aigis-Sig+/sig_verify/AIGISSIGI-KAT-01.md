# AIGISSIGI-KAT-01: exact submitted-vector relation

- Claim: `AIGISSIGI-K` in `oracles/spec/sign-01-Aigis-Sig+.md`, source locator PDF p. 11 (algorithm context) and `Test_Vectors/KAT_SIG_Aigis-sig1.txt`.
- Property: S03 version 1. Pattern: P1 version 1.
- Extraction status: draft (`unverified_spec`).
- Scope/preconditions: `Aigis-Sig+-I` `sig_verify`, exact indexed public submitted KAT, archived source/KAT SHA and declared output/status semantics.
- Signature length: The submitted KAT's exact `Sn_Len` must match its bytes and be no larger than `sig_get_sn_len_bytes()`, which is an allocation bound for this instance (first record 2009 versus getter 2015).
- Baseline: A valid indexed submitted record (index 0 in smoke).
- Intervention: Switch to a different valid record (index 1 in smoke) while retaining instance and API; paired mutator records index change.
- Expected relation: Both records are accepted by sig_verify.
- Observables: Actual API reachability, status, output/length, parameter set and output canary for KEM.
- Positive control: Two distinct valid records pass through the real target API.
- Negative control: Repeating one record is ineffective and becomes `inconclusive`.
- Fault control: Change the observed acceptance/secret after a real call; the predicate must reject it.
- Required capabilities: submitted_kat, indexed_public_vector.
- Predicate: Require exact provenance/scope, successful reachable calls and expected status/secret on each indexed record; failure is candidate-only.
- Paired mutator: `implement/mutator/kat_aigissigi.py`.
- Limitations: Same-lineage submitted vectors, no negative-input or full-function coverage, no finite security proof.

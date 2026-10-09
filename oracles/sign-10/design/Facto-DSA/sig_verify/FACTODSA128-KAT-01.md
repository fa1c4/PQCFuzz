# FACTODSA128-KAT-01: exact submitted-vector relation

- Claim: `FACTODSA128-K` in `oracles/spec/sign-10-Facto-DSA.md`, source locator PDF p. 6 (algorithm context) and `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-128.txt`.
- Property: S03 version 1. Pattern: P1 version 1.
- Extraction status: draft (`unverified_spec`).
- Scope/preconditions: `Facto-DSA-128` `sig_verify`, exact indexed public submitted KAT, archived source/KAT SHA and declared output/status semantics.
- Baseline: A valid indexed submitted record (index 0 in smoke).
- Intervention: Switch to a different valid record (index 1 in smoke) while retaining instance and API; paired mutator records index change.
- Expected relation: Both records are accepted by sig_verify.
- Observables: Actual API reachability, status, output/length, parameter set and output canary for KEM.
- Positive control: Two distinct valid records pass through the real target API.
- Negative control: Repeating one record is ineffective and becomes `inconclusive`.
- Fault control: Change the observed acceptance/secret after a real call; the predicate must reject it.
- Required capabilities: submitted_kat, indexed_public_vector.
- Predicate: Require exact provenance/scope, successful reachable calls and expected status/secret on each indexed record; failure is candidate-only.
- Paired mutator: `implement/mutator/kat_factodsa128.py`.
- Limitations: Same-lineage submitted vectors, no negative-input or full-function coverage, no finite security proof.

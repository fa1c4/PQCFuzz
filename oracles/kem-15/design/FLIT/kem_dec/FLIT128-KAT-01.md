# FLIT128-KAT-01: exact submitted-vector relation

- Claim: `FLIT128-K` in `oracles/spec/kem-15-FLIT.md`, source locator PDF p. 10 (algorithm context) and `Test_Vectors/KAT_KEM_FLIT128_REF.txt`.
- Property: K03 version 1. Pattern: P1 version 1.
- Extraction status: draft (`unverified_spec`).
- Scope/preconditions: `FLIT128` `kem_dec`, exact indexed public submitted KAT, archived source/KAT SHA and declared output/status semantics.
- Baseline: A valid indexed submitted record (index 0 in smoke).
- Intervention: Switch to a different valid record (index 1 in smoke) while retaining instance and API; paired mutator records index change.
- Expected relation: Both records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output/length, parameter set and output canary for KEM.
- Positive control: Two distinct valid records pass through the real target API.
- Negative control: Repeating one record is ineffective and becomes `inconclusive`.
- Fault control: Change the observed acceptance/secret after a real call; the predicate must reject it.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Predicate: Require exact provenance/scope, successful reachable calls and expected status/secret on each indexed record; failure is candidate-only.
- Paired mutator: `implement/mutator/kat_flit128.py`.
- Limitations: Same-lineage submitted vectors, no negative-input or full-function coverage, no finite security proof.

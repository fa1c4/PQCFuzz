# NTRE128-KAT-01: exact submitted-vector relation

- Claim: `NTRE128-K` in `oracles/spec/kem-27-NTRE Key Encapsulation Mechanism.md`, source locator PDF p. 18 (algorithm context) and `Implementations/Reference_Implementation/NTRE-128/output/KAT_KEM_NTRE-128.txt`.
- Property: K03 version 1. Pattern: P1 version 1.
- Extraction status: draft (`unverified_spec`).
- Scope/preconditions: `NTRE-128` `kem_dec`, exact indexed public submitted KAT, archived source/KAT SHA and declared output/status semantics.
- Baseline: A valid indexed submitted record (index 0 in smoke).
- Intervention: Switch to a different valid record (index 1 in smoke) while retaining instance and API; paired mutator records index change.
- Expected relation: Both records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output/length, parameter set and output canary for KEM.
- Positive control: Two distinct valid records pass through the real target API.
- Negative control: Repeating one record is ineffective and becomes `inconclusive`.
- Fault control: Change the observed acceptance/secret after a real call; the predicate must reject it.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Predicate: Require exact provenance/scope, successful reachable calls and expected status/secret on each indexed record; failure is candidate-only.
- Paired mutator: `implement/mutator/kat_ntre128.py`.
- Limitations: Same-lineage submitted vectors, no negative-input or full-function coverage, no finite security proof.

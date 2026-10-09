# DKEX128-ROLE-01: final-role matching-session relation

- Claim: `DKEX128-C` in `oracles/spec/kex-04-DKEX.md`, PDF pp. 27–28 matching-session correctness and `Test_Vectors/KAT_KEX_DKEX-128.txt`.
- Property: X05 version 1, aligned peer interoperability. Pattern: P2 version 1, complementary role derivation on one matching transcript.
- Extraction status: draft (`unverified_spec`); any failure remains candidate-only.
- Scope/preconditions: `DKEX-128`, exact indexed 3-pass submitted transcript, correct role keys/final messages/states and pinned source/KAT hashes.
- Baseline: Both roles derive on one valid public submitted transcript.
- Intervention: Switch to another indexed valid transcript while retaining instance and role/API mapping; paired mutator records the changed index.
- Expected relation: For each record, both derived secrets agree with each other and with that record's submitted session key.
- Observables: Two actual target calls, return statuses, output bytes/lengths, canaries and pass count.
- Positive control: Two distinct records invoke both role APIs and satisfy the relation.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Flip one observed responder-secret bit after real calls; predicate rejects it.
- Required capabilities: submitted_kat, indexed_public_vector, dual_role_derivation, output_canary.
- Predicate: Validate exact source/provenance/scope, successful calls and two expected role outputs; mismatch is candidate-only.
- Paired mutator: `implement/mutator/role_128.py`.
- Limitations: Submitted-vector lineage; no handshake-generation, authentication, replay or full-function coverage claim.

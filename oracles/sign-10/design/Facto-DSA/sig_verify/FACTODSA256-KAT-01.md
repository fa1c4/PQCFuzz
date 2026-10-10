# FACTODSA256-KAT-01: exact submitted-vector relation

- Claim: `FACTODSA256-K` in `oracles/spec/sign-10-Facto-DSA.md`; source locator PDF p. 7 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-256.txt` SHA-256 `7863c23b59af62b695a0e574209404c75720ab4da41781d5ecb404bb4128a836`.
- Property: S03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Facto-DSA-256` `sig_verify`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records are accepted by sig_verify.
- Observables: Actual API reachability, status, output length, and return code.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector.
- Paired mutator: `implement/mutator/kat_factodsa256.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

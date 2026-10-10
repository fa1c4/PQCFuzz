# FACTODSA512-KAT-01: exact locally regenerated vector relation

- Claim: `FACTODSA512-K` in `oracles/spec/sign-10-Facto-DSA.md`; source locator PDF p. 7 (algorithm context); locally regenerated with the pinned submitted KAT_SIG.c generator; `generator/output/KAT_SIG_Facto-DSA-512.txt` SHA-256 `192bca21b8e1f83c5a3e31b051eb662853c72709576737daf637e210d58ee5e3`.
- Property: S03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Facto-DSA-512` `sig_verify`, exact indexed public locally regenerated KAT-generator KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed locally regenerated record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid locally regenerated KAT-generator records are accepted by sig_verify.
- Observables: Actual API reachability, status, output length, and return code.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: generated_kat, indexed_public_vector.
- Paired mutator: `implement/mutator/kat_factodsa512.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

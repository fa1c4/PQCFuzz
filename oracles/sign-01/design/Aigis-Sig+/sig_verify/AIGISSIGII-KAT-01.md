# AIGISSIGII-KAT-01: exact submitted-vector relation

- Claim: `AIGISSIGII-K` in `oracles/spec/sign-01-Aigis-Sig+.md`; source locator PDF p. 11 (algorithm context); `Test_Vectors/KAT_SIG_Aigis-sig2.txt` SHA-256 `21e152e13afdac3c1e189f02ad0413159df4477662c2f946bf77d91ce3a5a472`.
- Property: S03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Aigis-Sig+-II` `sig_verify`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records are accepted by sig_verify.
- Observables: Actual API reachability, status, output length, and return code.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector.
- Paired mutator: `implement/mutator/kat_aigissigii.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

# AIGISSIGIII-KAT-01: exact submitted-vector relation

- Claim: `AIGISSIGIII-K` in `oracles/spec/sign-01-Aigis-Sig+.md`; source locator PDF p. 11 (algorithm context); `Test_Vectors/KAT_SIG_Aigis-sig3.txt` SHA-256 `c9b942c39a596c0d6457c6186262ae7f98ef047249918b12efdd6cc5f72f6f5c`.
- Property: S03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Aigis-Sig+-III` `sig_verify`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records are accepted by sig_verify.
- Observables: Actual API reachability, status, output length, and return code.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector.
- Paired mutator: `implement/mutator/kat_aigissigiii.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

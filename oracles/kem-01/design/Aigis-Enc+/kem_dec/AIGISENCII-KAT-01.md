# AIGISENCII-KAT-01: exact submitted-vector relation

- Claim: `AIGISENCII-K` in `oracles/spec/kem-01-Aigis-Enc+.md`; source locator PDF pp. 8–9 (algorithm context); `Test_Vectors/KAT_KEM_Aigis-enc2.txt` SHA-256 `f6d8bad8e531512c6feee2a488b00b7e3ccf3d5318462154b9afb7701b06b527`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Aigis-Enc+-II` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_aigisencii.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

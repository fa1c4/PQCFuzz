# AIGISENCIII-KAT-01: exact submitted-vector relation

- Claim: `AIGISENCIII-K` in `oracles/spec/kem-01-Aigis-Enc+.md`; source locator PDF pp. 8–9 (algorithm context); `Test_Vectors/KAT_KEM_Aigis-enc3.txt` SHA-256 `1c7be3d27d749b6cb4ae83983799f5f1ea4cc6ca0d386967f9448943ab1c393c`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Aigis-Enc+-III` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_aigisenciii.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

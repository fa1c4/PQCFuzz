# TRIKE7-KAT-01: exact submitted-vector relation

- Claim: `TRIKE7-K` in `oracles/spec/kem-36-TRIKE.md`; source locator PDF p. 7 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-7.txt` SHA-256 `75e757b60924e0fbd00833172f603f1f960ba2c7ccd843a1deffdf4d2aaf06e1`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `TRIKE-7` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_trike7.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

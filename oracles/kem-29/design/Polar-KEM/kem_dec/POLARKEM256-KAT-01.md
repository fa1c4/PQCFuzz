# POLARKEM256-KAT-01: exact submitted-vector relation

- Claim: `POLARKEM256-K` in `oracles/spec/kem-29-Polar-KEM.md`; source locator PDF p. 11 (algorithm context); `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-256.txt` SHA-256 `2b0b827c53fa82bf8cef7ceb29868c40f08882b37be8088a7b3d0c820b88195b`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `PolarKEM-256` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_polarkem256.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

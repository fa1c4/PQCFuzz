# FLIT512-KAT-01: exact submitted-vector relation

- Claim: `FLIT512-K` in `oracles/spec/kem-15-FLIT.md`; source locator PDF p. 15 (algorithm context); `Test_Vectors/KAT_KEM_FLIT512_REF.txt` SHA-256 `e4019117230dc2ef5983e8c2c252f08189e8004e3b7db595a66eec3aa8d9820c`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `FLIT512` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_flit512.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

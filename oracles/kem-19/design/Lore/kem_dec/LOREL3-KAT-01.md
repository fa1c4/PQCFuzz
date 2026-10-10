# LOREL3-KAT-01: exact submitted-vector relation

- Claim: `LOREL3-K` in `oracles/spec/kem-19-Lore.md`; source locator PDF p. 12 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L3.txt` SHA-256 `d79252a2fddf5930b617f5f476a18ad460ee9db8f31aa282306a62a4d5feb18d`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Lore-L3` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_lorel3.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

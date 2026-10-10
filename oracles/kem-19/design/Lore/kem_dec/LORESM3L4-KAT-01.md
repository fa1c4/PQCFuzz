# LORESM3L4-KAT-01: exact submitted-vector relation

- Claim: `LORESM3L4-K` in `oracles/spec/kem-19-Lore.md`; source locator PDF p. 12 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L4.txt` SHA-256 `924e2d5d0b8109a08c5ea99f4879cc345b649b61b7a212e60454794dd3850fd3`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Lore-SM3-L4` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_loresm3l4.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

# LORESM3L3-KAT-01: exact submitted-vector relation

- Claim: `LORESM3L3-K` in `oracles/spec/kem-19-Lore.md`; source locator PDF p. 12 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L3.txt` SHA-256 `aebe78f3a3c48c56bf925626cd133a43bacfa23cdcf28666f36efce1abe11d93`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Lore-SM3-L3` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_loresm3l3.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

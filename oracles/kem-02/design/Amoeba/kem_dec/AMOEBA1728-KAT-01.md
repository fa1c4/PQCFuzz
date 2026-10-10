# AMOEBA1728-KAT-01: exact submitted-vector relation

- Claim: `AMOEBA1728-K` in `oracles/spec/kem-02-Amoeba.md`; source locator PDF pp. 7–9 (algorithm context); `Test_Vectors/KAT_KEM_Amoeba384.txt` SHA-256 `bfa2f968cfe402fbc78ea5ce05d6d425cf4602c2b270bba7abfa2e11d93063ca`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Amoeba-1728` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_amoeba1728.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

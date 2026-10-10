# AMOEBA864-KAT-01: exact submitted-vector relation

- Claim: `AMOEBA864-K` in `oracles/spec/kem-02-Amoeba.md`; source locator PDF pp. 7–9 (algorithm context); `Test_Vectors/KAT_KEM_Amoeba192.txt` SHA-256 `10440a828ae85edbecd129d1a070eb8b2f820cddb37ade5abe4627eaf1183878`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Amoeba-864` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_amoeba864.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

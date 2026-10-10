# NTRE256-KAT-01: exact submitted-vector relation

- Claim: `NTRE256-K` in `oracles/spec/kem-27-NTRE Key Encapsulation Mechanism.md`; source locator PDF p. 18 (algorithm context); `Implementations/Reference_Implementation/NTRE-256/output/KAT_KEM_NTRE-256.txt` SHA-256 `b46885a10bc6931aad20390b23aba3a630991948242f379cc41e72710145157a`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `NTRE-256` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_ntre256.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

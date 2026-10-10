# NTRE512-KAT-01: exact submitted-vector relation

- Claim: `NTRE512-K` in `oracles/spec/kem-27-NTRE Key Encapsulation Mechanism.md`; source locator PDF p. 18 (algorithm context); `Implementations/Reference_Implementation/NTRE-512/output/KAT_KEM_NTRE-512.txt` SHA-256 `b3608ede368d63bf002e4819139f748c1e387e1354d98de93420d5db99e24402`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `NTRE-512` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_ntre512.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

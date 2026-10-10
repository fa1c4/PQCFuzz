# BAGPIGLET512-KAT-01: exact submitted-vector relation

- Claim: `BAGPIGLET512-K` in `oracles/spec/kem-04-BAG-Piglet.md`; source locator PDF p. 7 (algorithm context); `Test_Vectors/KAT_KEM_bag_piglet_512.txt` SHA-256 `9a4ec3639ac1002b28a879ec31eaf8ac21e945661a7276aa1db184bfe1c9a335`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `bag_piglet512` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_bagpiglet512.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

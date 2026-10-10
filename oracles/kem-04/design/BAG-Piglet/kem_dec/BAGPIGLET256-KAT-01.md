# BAGPIGLET256-KAT-01: exact submitted-vector relation

- Claim: `BAGPIGLET256-K` in `oracles/spec/kem-04-BAG-Piglet.md`; source locator PDF p. 7 (algorithm context); `Test_Vectors/KAT_KEM_bag_piglet_256.txt` SHA-256 `5a0ee6161e598617226ab976048ce992516eb804a25c3590f2a15ef731cc4952`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `bag_piglet256` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_bagpiglet256.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

# POLARLAC512STAR-KAT-01: exact submitted-vector relation

- Claim: `POLARLAC512STAR-K` in `oracles/spec/kem-30-PolarLAC.md`; source locator PDF pp. 14–16 (algorithm context); `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512-Star.txt` SHA-256 `dc15d771b2d5fcf7f03c2a59076edb3352e58749eb9ecd8073aab9f29c0a74b1`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `POLARLAC-512-Star` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_polarlac512star.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

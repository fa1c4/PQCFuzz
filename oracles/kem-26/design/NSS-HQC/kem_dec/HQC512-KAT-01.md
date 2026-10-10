# HQC512-KAT-01: exact submitted-vector relation

- Claim: `HQC512-K` in `oracles/spec/kem-26-NSS-HQC.md`; source locator PDF pp. 22–24 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-512.txt` SHA-256 `e3d01cb3f70f06c548ab50cdee8028cd53974789572de9604acdb7e5a4a9d3d1`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `HQC-512` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_hqc512.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

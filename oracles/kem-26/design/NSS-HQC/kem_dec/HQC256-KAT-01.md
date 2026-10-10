# HQC256-KAT-01: exact submitted-vector relation

- Claim: `HQC256-K` in `oracles/spec/kem-26-NSS-HQC.md`; source locator PDF pp. 22–24 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-256.txt` SHA-256 `8cdfacea8444ed8e1380b9ce3cdb4f1ee270acfd35bcd39bb50ac3c4e00c9454`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `HQC-256` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_hqc256.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

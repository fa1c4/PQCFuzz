# HARE384-KAT-01: exact submitted-vector relation

- Claim: `HARE384-K` in `oracles/spec/kem-16-HARE.md`; source locator PDF p. 9 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-384-kr.txt` SHA-256 `9cd639973258bd9269093ffed7ccb1641ca51d74e01bd94094c26c671bb3c230`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `HARE-384` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_hare384.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

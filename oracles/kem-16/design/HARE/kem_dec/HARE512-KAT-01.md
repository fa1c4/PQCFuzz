# HARE512-KAT-01: exact submitted-vector relation

- Claim: `HARE512-K` in `oracles/spec/kem-16-HARE.md`; source locator PDF p. 9 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-512-kr.txt` SHA-256 `a5ec74c424e0f0408c31811ec847b1f71f4582ebe0b45fd696ffb3964ed1ddc6`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `HARE-512` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_hare512.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

# HARE256-KAT-01: exact submitted-vector relation

- Claim: `HARE256-K` in `oracles/spec/kem-16-HARE.md`; source locator PDF p. 9 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-256-kr.txt` SHA-256 `543e2ac2ec9a9d6267e11125fd0683f53920a0a71a3ab54df1ff198f29716221`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `HARE-256` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_hare256.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

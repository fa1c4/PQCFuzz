# OAEPNTRU2592-KAT-01: exact submitted-vector relation

- Claim: `OAEPNTRU2592-K` in `oracles/spec/kem-28-OAEP-NTRU.md`; source locator PDF p. 6 (algorithm context); `Test_Vectors/KAT_KEM_OAEP-NTRU-2592.txt` SHA-256 `4b8026ebc6f901358feafb811211be535b4a862a8e5b062d0a9cda865b0bc034`.
- Property: K03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `OAEP-NTRU-2592` `kem_dec`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records decapsulate to their own archived shared secrets.
- Observables: Actual API reachability, status, output length and guard for KEM.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector, output_canary.
- Paired mutator: `implement/mutator/kat_oaepntru2592.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

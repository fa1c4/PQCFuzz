# OPSSIG512-KAT-01: exact submitted-vector relation

- Claim: `OPSSIG512-K` in `oracles/spec/sign-17-OPS Digital Signature Algorithm.md`; source locator PDF p. 7 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-512/KAT_SIG_OPSsig-512-reference.txt` SHA-256 `2a7f1e29f2b8c2f43cc1bad56220ec936a3de4051e04686e0dbd19826d569263`.
- Property: S03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `OPSsig-512` `sig_verify`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records are accepted by sig_verify.
- Observables: Actual API reachability, status, output length, and return code.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector.
- Paired mutator: `implement/mutator/kat_opssig512.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

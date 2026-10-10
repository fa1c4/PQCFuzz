# OPSSIG256-KAT-01: exact submitted-vector relation

- Claim: `OPSSIG256-K` in `oracles/spec/sign-17-OPS Digital Signature Algorithm.md`; source locator PDF p. 7 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-256/KAT_SIG_OPSsig-256-reference.txt` SHA-256 `61881f46ecea283f08cf7e3ca51da570b856e80064b719209743e4c8a6b25f1c`.
- Property: S03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `OPSsig-256` `sig_verify`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records are accepted by sig_verify.
- Observables: Actual API reachability, status, output length, and return code.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector.
- Paired mutator: `implement/mutator/kat_opssig256.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

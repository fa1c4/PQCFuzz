# SHUTTLE256-KAT-01: exact submitted-vector relation

- Claim: `SHUTTLE256-K` in `oracles/spec/sign-23-Shuttle.md`; source locator PDF p. 10 (algorithm context); `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-256.txt` SHA-256 `02b98170db3ec301a019249545bbee9bb2d23a9717cd1bec0bf26724dcc20984`.
- Property: S03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `SHUTTLE-256` `sig_verify`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records are accepted by sig_verify.
- Observables: Actual API reachability, status, output length, and return code.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector.
- Paired mutator: `implement/mutator/kat_shuttle256.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

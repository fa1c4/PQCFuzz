# TSUOV256-KAT-01: exact submitted-vector relation

- Claim: `TSUOV256-K` in `oracles/spec/sign-31-TSUOV.md`; source locator PDF p. 24 (algorithm context); `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_256.txt` SHA-256 `21651f608d47524782f6728d34de20d80823a2e45bee67a4f327d6481bd54dec`.
- Property: S03 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `TSUOV_256` `sig_verify`, exact indexed public submitted KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed submitted record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: Both valid submitted records are accepted by sig_verify.
- Observables: Actual API reachability, status, output length, and return code.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: submitted_kat, indexed_public_vector.
- Paired mutator: `implement/mutator/kat_tsuov256.py`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.

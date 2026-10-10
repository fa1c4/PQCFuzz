# DRAGON768-KAT-01: source-pinned submitted KAT consistency

- Claim: `DRAGON768-K` in `oracles/spec/hash-07-Dragon.md`; source locator PDF pp. 9–10; `Dragon/Implementations and Test_vector/Dragon-ARM/Implementations/Reference_Implementation/Dragon-768/CryptHash_AlgorithmInstance.h` SHA-256 `a523f44d56252e27d2276057feb96cc3a7f12b3e6ca63f27aa70228eece5fe0f`; `Dragon/Implementations and Test_vector/Dragon-ARM/Test_Vector/KAT_2_12_Dragon-768.txt` SHA-256 `3661777eb35d496e0ed203c5f6a4a508e1a50a0c53add967b69b7b1e4d5352f8`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Dragon-768` reference `CryptHash`, 768-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/dragon768_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

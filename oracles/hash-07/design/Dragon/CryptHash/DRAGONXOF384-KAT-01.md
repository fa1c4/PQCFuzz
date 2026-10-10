# DRAGONXOF384-KAT-01: source-pinned submitted KAT consistency

- Claim: `DRAGONXOF384-K` in `oracles/spec/hash-07-Dragon.md`; source locator PDF pp. 9–10; `Dragon/Implementations and Test_vector/Dragon-ARM/Implementations/Reference_Implementation/Dragon-XOF-384/CryptHash_AlgorithmInstance.h` SHA-256 `c07b2186daf6fc8d2bef8c4011b99561669a9ea9d5318f42adf69a9f523d0fbe`; `Dragon/Implementations and Test_vector/Dragon-ARM/Test_Vector/KAT_2_12_Dragon-XOF-384.txt` SHA-256 `e6c582b5368610210bdfc77d31e30a602a0be915a9226c03ab359270f1e0ec0e`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Dragon-XOF-384` reference `CryptHash`, 1152-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/dragonxof384_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

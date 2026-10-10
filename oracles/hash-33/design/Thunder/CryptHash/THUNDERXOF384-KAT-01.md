# THUNDERXOF384-KAT-01: source-pinned submitted KAT consistency

- Claim: `THUNDERXOF384-K` in `oracles/spec/hash-33-Thunder.md`; source locator PDF pp. 7–8; `Thunder/Implementations and Test_vector/Thunder-ARM/Implementations/Reference_Implementation/Thunder-XOF-384/CryptHash_AlgorithmInstance.h` SHA-256 `2eb6a22d73cb05e27237b53701d53fb66d8d4f0f13599e952cd281d9a6bff301`; `Thunder/Implementations and Test_vector/Thunder-ARM/Test_Vector/KAT_2_12_Thunder-XOF-384.txt` SHA-256 `07c3a5ad56c2c1e52259d1f78c68d867910c77b435c00bb0be3473ff89b9dc85`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Thunder-XOF-384` reference `CryptHash`, 1152-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/thunderxof384_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

# NEULASER768-KAT-01: source-pinned submitted KAT consistency

- Claim: `NEULASER768-K` in `oracles/spec/hash-21-Neulaser.md`; source locator PDF p. 5; `Neulaser/Implementations and Test_Vectors/API_CryptHash/Implementations/Reference_Implementation/Neulaser-768/CryptHash_AlgorithmInstance.h` SHA-256 `e3c9b136eff6e07b3ca83d6bc451e77cefa327509419ab116c4c0f824c9ba13e`; `Neulaser/Implementations and Test_Vectors/API_CryptHash/Test_Vector/KAT_2_12_Neulaser-768.txt` SHA-256 `46b89e05bfc95dc5ce8bacbb8e8b366aea921d46970614e9af0dc891b0eec4f6`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Neulaser-768` reference `CryptHash`, 768-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/neulaser768_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

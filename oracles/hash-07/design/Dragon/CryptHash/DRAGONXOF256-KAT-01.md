# DRAGONXOF256-KAT-01: source-pinned submitted KAT consistency

- Claim: `DRAGONXOF256-K` in `oracles/spec/hash-07-Dragon.md`; source locator PDF pp. 9–10; `Dragon/Implementations and Test_vector/Dragon-ARM/Implementations/Reference_Implementation/Dragon-XOF-256/CryptHash_AlgorithmInstance.h` SHA-256 `af8edc23237e25758349c3e6330c83f3176c2644c3f06961e294cb2c9cf26fc4`; `Dragon/Implementations and Test_vector/Dragon-ARM/Test_Vector/KAT_2_12_Dragon-XOF-256.txt` SHA-256 `a70bbac199ca8a8eb394e4d864b7d79795abd42f37abb90f5bb522cb4c226da8`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Dragon-XOF-256` reference `CryptHash`, 1280-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/dragonxof256_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

# NEULASER1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `NEULASER1024-K` in `oracles/spec/hash-21-Neulaser.md`; source locator PDF p. 5; `Neulaser/Implementations and Test_Vectors/API_CryptHash/Implementations/Reference_Implementation/Neulaser-1024/CryptHash_AlgorithmInstance.h` SHA-256 `7650b1fe33b1e6dcf58ee84afc02e7b1cae2ad8393e5d83f6b9e805b17d19e95`; `Neulaser/Implementations and Test_Vectors/API_CryptHash/Test_Vector/KAT_2_12_Neulaser-1024.txt` SHA-256 `0059202e68c267fc76ec6ffff4c607ef2b02a2d757fb0934960d01acab75ab89`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Neulaser-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/neulaser1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

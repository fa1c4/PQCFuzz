# JUZIHASH1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `JUZIHASH1024-K` in `oracles/spec/hash-13-JuziHash.md`; source locator PDF pp. 6, 11; `Juzi/Implementations/Implementation/Reference_Implementation/JuziHash-1024/CryptHash_AlgorithmInstance.h` SHA-256 `7a2b5af6b24c700263f3f0ad811bb3bf2a11b159e10fc3b607b23e5f1046bafa`; `Juzi/Test_Vectors/KAT_2_12_JuziHash-1024.txt` SHA-256 `b2984c25da27d0601e5d705ce5ff75cfc3822a7dbc295b343cc593dada0a8e03`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `JuziHash-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/juzihash1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

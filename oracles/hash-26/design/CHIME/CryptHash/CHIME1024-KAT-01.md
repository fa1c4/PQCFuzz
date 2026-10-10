# CHIME1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `CHIME1024-K` in `oracles/spec/hash-26-CHIME.md`; source locator PDF p. 4; `CHIME/Implementations/Reference_Implementation/CHIME-1024/CryptHash_AlgorithmInstance.h` SHA-256 `120bc1b7e6cc991f2359fbbb263e9e6b76a6e7e3af1da23c936660b52c5c2dbd`; `CHIME/Test_Vectors/Test_Vector/KAT_2_12_CHIME-1024.txt` SHA-256 `f3eee2c88625d1ee95762e757966dd51e8d3353bdcd86a3420d4fe55420b6720`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `CHIME-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/chime1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

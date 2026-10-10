# TAICHI768-KAT-01: source-pinned submitted KAT consistency

- Claim: `TAICHI768-K` in `oracles/spec/hash-25-TaiChi.md`; source locator PDF pp. 5, 13; `TaiChi/Implementations/Reference_Implementation/TaiChi-768/CryptHash_AlgorithmInstance.h` SHA-256 `7db6d4a8afd23e0e67c47ffc3c7e0fc672d4f34c79781e67143b94dd3b78230a`; `TaiChi/Test_Vectors/KAT_2_12_TaiChi-768.txt` SHA-256 `3e30053a633167b50e49dc1e5ce38f0a80d7c3d70a66917547eabb2bb7a63093`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `TaiChi-768` reference `CryptHash`, 768-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/taichi768_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

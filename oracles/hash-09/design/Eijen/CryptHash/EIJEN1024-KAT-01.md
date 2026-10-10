# EIJEN1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `EIJEN1024-K` in `oracles/spec/hash-09-Eijen.md`; source locator PDF pp. 5, 10; `Eijen/Implementations/Reference_Implementation/Eijen-1024/CryptHash_AlgorithmInstance.h` SHA-256 `346f5af34e8057aac3c236294e408a11e5fa75176e16a80131d5140b8da5bdb9`; `Eijen/Test_Vectors/KAT_2_12_Eijen-1024.txt` SHA-256 `cb71785e899ba51fcf7e955f9cfec453827f871af0b3415cce648726e334f61e`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Eijen-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/eijen1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

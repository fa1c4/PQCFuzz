# THUNDERXOF256-KAT-01: source-pinned submitted KAT consistency

- Claim: `THUNDERXOF256-K` in `oracles/spec/hash-33-Thunder.md`; source locator PDF pp. 7–8; `Thunder/Implementations and Test_vector/Thunder-ARM/Implementations/Reference_Implementation/Thunder-XOF-256/CryptHash_AlgorithmInstance.h` SHA-256 `c1b93ca286c43902f92849bbf6e31446884c074be443944832f8b85788c234bd`; `Thunder/Implementations and Test_vector/Thunder-ARM/Test_Vector/KAT_2_12_Thunder-XOF-256.txt` SHA-256 `bf800da64fb07f77b508784bcbe6a0ea6513688ab7930d12f2925a12ade7e512`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Thunder-XOF-256` reference `CryptHash`, 1280-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/thunderxof256_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

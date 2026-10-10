# AXIS1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `AXIS1024-K` in `oracles/spec/hash-02-AXIS.md`; source locator PDF pp. 4, 10; `AXIS/Implementations/Reference_Implementation/AXIS-1024/CryptHash_AlgorithmInstance.h` SHA-256 `eefb77d6ccfe39777da23b05696e0c0d5ad437e2c2d07bb3b8489bf9bce05621`; `AXIS/Test_Vectors/KAT_2_12_AXIS-1024.txt` SHA-256 `281c71da5a2c4d851a79c45c90fe28a9096d0bb4a7e8f94419f871dba4d52204`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `AXIS-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/axis1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

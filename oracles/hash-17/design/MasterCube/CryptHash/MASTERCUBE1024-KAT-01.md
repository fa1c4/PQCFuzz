# MASTERCUBE1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `MASTERCUBE1024-K` in `oracles/spec/hash-17-MasterCube.md`; source locator PDF pp. 4, 10; `MasterCube/Implementations/Reference_Implementation/MasterCube-1024/CryptHash_AlgorithmInstance.h` SHA-256 `4c76ed50c0b5fb4b1175487b8fdee4e704861f1bf4da5057f083f2ecfb568f18`; `MasterCube/Test_Vectors/KAT_2_12_MasterCube-1024.txt` SHA-256 `20c32d208cbdc05776af95fdf22c805a105fffa6b2ada30b34d7a38271f99d13`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `MasterCube-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/mastercube1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

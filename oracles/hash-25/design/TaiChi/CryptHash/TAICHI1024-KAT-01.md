# TAICHI1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `TAICHI1024-K` in `oracles/spec/hash-25-TaiChi.md`; source locator PDF pp. 5, 13; `TaiChi/Implementations/Reference_Implementation/TaiChi-1024/CryptHash_AlgorithmInstance.h` SHA-256 `9502823b8532d8142ad5bdf58d6e66ba5298d9bb891002212e88c7af3e9c37f6`; `TaiChi/Test_Vectors/KAT_2_12_TaiChi-1024.txt` SHA-256 `b1cab06a69ffe259500199d9ceed3b1cae89e56d726481189f9a2e9f6678828f`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `TaiChi-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/taichi1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

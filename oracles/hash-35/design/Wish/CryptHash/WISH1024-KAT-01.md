# WISH1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `WISH1024-K` in `oracles/spec/hash-35-Wish.md`; source locator PDF pp. 5–8; `Wish/Implementations/Reference_Implementation/Wish1024_reference/CryptHash_AlgorithmInstance.h` SHA-256 `21229b8c17554f71fd1b044d601ef605baf278122f4a8fde5873a1ab57721528`; `Wish/Test_Vectors/Test_Vector/Wish1024/KAT_2_12_Wish1024.txt` SHA-256 `33ea939b4b699cc1e49b54cfed2173d1db3c454f230704dcb817dff278b7326c`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Wish1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/wish1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

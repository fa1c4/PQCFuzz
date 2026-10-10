# THUNDER1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `THUNDER1024-K` in `oracles/spec/hash-33-Thunder.md`; source locator PDF pp. 7–8; `Thunder/Implementations and Test_vector/Thunder-ARM/Implementations/Reference_Implementation/Thunder-1024/CryptHash_AlgorithmInstance.h` SHA-256 `6492838db1d4e1520325c1a642712f9479d0015c31ccfae2684a63a4b79facad`; `Thunder/Implementations and Test_vector/Thunder-ARM/Test_Vector/KAT_2_12_Thunder-1024.txt` SHA-256 `c7a6875584c99d98e9bbc591a6844945020ce2304b325215da4925b53b2fb6cf`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Thunder-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/thunder1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

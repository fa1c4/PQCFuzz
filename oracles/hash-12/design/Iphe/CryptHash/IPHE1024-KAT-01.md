# IPHE1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `IPHE1024-K` in `oracles/spec/hash-12-Iphe.md`; source locator PDF p. 4; `Iphe/Implementations/Reference_Implementation/Iphe-1024/CryptHash_AlgorithmInstance.h` SHA-256 `948d42ebff121dc79a1bdc83d5d12ef1f53f99b83ea7b44537ec5ecba48d5c10`; `Iphe/Test_Vectors/KAT_2_12_Iphe-1024.txt` SHA-256 `a451150e557a015ff5c183912141ae94b0239f9205e9c1fa3b996870c546b7d5`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Iphe-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/iphe1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

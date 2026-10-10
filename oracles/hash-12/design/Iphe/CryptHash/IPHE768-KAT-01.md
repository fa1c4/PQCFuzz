# IPHE768-KAT-01: source-pinned submitted KAT consistency

- Claim: `IPHE768-K` in `oracles/spec/hash-12-Iphe.md`; source locator PDF p. 4; `Iphe/Implementations/Reference_Implementation/Iphe-768/CryptHash_AlgorithmInstance.h` SHA-256 `9daacbb3aca1e0773e0ad2cfad100429105d36b2e3d42f591d75c0e81a0ac067`; `Iphe/Test_Vectors/KAT_2_12_Iphe-768.txt` SHA-256 `722e09ec85dba2125998f926a42d3d9fc5d2f4750bc06c5720332863e1e04f23`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Iphe-768` reference `CryptHash`, 768-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/iphe768_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

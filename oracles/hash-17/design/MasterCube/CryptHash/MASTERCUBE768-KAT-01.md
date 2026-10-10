# MASTERCUBE768-KAT-01: source-pinned submitted KAT consistency

- Claim: `MASTERCUBE768-K` in `oracles/spec/hash-17-MasterCube.md`; source locator PDF pp. 4, 10; `MasterCube/Implementations/Reference_Implementation/MasterCube-768/CryptHash_AlgorithmInstance.h` SHA-256 `a8bcecc518bf6252c46fd3572cd0d01e06a8bbc56400bbd38bce46734dcb8cef`; `MasterCube/Test_Vectors/KAT_2_12_MasterCube-768.txt` SHA-256 `80e1704ce024cdafe368f539306341bffa345524343a8a19a96c097126824471`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `MasterCube-768` reference `CryptHash`, 768-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/mastercube768_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

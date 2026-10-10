# AXIS768-KAT-01: source-pinned submitted KAT consistency

- Claim: `AXIS768-K` in `oracles/spec/hash-02-AXIS.md`; source locator PDF pp. 4, 10; `AXIS/Implementations/Reference_Implementation/AXIS-768/CryptHash_AlgorithmInstance.h` SHA-256 `b2c5f3ec59048a0ddfc32857d0f462d8f88ae9056670ad3e4bdd973a76a04f52`; `AXIS/Test_Vectors/KAT_2_12_AXIS-768.txt` SHA-256 `4298d5cae8e9946392cd1b96099156115c6ad3f3a2458720a0bf9f9d1007cac3`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `AXIS-768` reference `CryptHash`, 768-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/axis768_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

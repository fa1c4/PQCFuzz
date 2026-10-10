# DRAGONXOF512-KAT-01: source-pinned submitted KAT consistency

- Claim: `DRAGONXOF512-K` in `oracles/spec/hash-07-Dragon.md`; source locator PDF pp. 9–10; `Dragon/Implementations and Test_vector/Dragon-ARM/Implementations/Reference_Implementation/Dragon-XOF-512/CryptHash_AlgorithmInstance.h` SHA-256 `c4157bf496f16fc3433638bab0b56b75d6b8f423399c5b20c3bb8d0921ab3b12`; `Dragon/Implementations and Test_vector/Dragon-ARM/Test_Vector/KAT_2_12_Dragon-XOF-512.txt` SHA-256 `b2056e396f79f9c92d623708dfb579b68b68af6def2c0021206b3aaecc0d4a98`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Dragon-XOF-512` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/dragonxof512_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

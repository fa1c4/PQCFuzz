# DRAGON1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `DRAGON1024-K` in `oracles/spec/hash-07-Dragon.md`; source locator PDF pp. 9–10; `Dragon/Implementations and Test_vector/Dragon-ARM/Implementations/Reference_Implementation/Dragon-1024/CryptHash_AlgorithmInstance.h` SHA-256 `7c736caa59bf8ea30da200877a65d91b89ce7c4c0ec67eadd4f6a137d5b57ad7`; `Dragon/Implementations and Test_vector/Dragon-ARM/Test_Vector/KAT_2_12_Dragon-1024.txt` SHA-256 `c58ddbfda4740304f72247dfb7ef92f57cb73dc6fad1c291f37218cc65e00748`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Dragon-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/dragon1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

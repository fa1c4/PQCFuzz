# QSH768-KAT-01: source-pinned submitted KAT consistency

- Claim: `QSH768-K` in `oracles/spec/hash-24-QSH.md`; source locator PDF pp. 4–5, 15; `QSH/Implementations/03_Implementations/1_Reference_Implementation/QSH-768/CryptHash_AlgorithmInstance.h` SHA-256 `67a8aae8c91ed673514d40d5b03d57c1d2cb6648f26d88b0b38cd2cf6741b63d`; `QSH/Test_Vectors/04_TestVectors/KAT_2_12_QSH-768.txt` SHA-256 `e1c609cc4d63cf5e94eb372a1ab00ddf11461f34d12bc3260b5f86e701e9f835`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `QSH-768` reference `CryptHash`, 768-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/qsh768_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

# EIJEN768-KAT-01: source-pinned submitted KAT consistency

- Claim: `EIJEN768-K` in `oracles/spec/hash-09-Eijen.md`; source locator PDF pp. 5, 10; `Eijen/Implementations/Reference_Implementation/Eijen-768/CryptHash_AlgorithmInstance.h` SHA-256 `3b1a45ffde4ecfb8e2f286d2c6c3d974ffbb283df98f8648ce18d567feebe36f`; `Eijen/Test_Vectors/KAT_2_12_Eijen-768.txt` SHA-256 `aa754d0cab3640e8bbcb346ca758e530d73a9bff47da484e6dec47f63dc2e990`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Eijen-768` reference `CryptHash`, 768-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/eijen768_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

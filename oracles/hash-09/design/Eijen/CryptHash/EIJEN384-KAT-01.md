# EIJEN384-KAT-01: source-pinned submitted KAT consistency

- Claim: `EIJEN384-K` in `oracles/spec/hash-09-Eijen.md`; source locator PDF pp. 5, 10; `Eijen/Implementations/Reference_Implementation/Eijen-384/CryptHash_AlgorithmInstance.h` SHA-256 `8d66605bfad0003d10fd46f9954ebf5f7d8260c9093dc21e1c8a3c08b13d853b`; `Eijen/Test_Vectors/KAT_2_12_Eijen-384.txt` SHA-256 `30afffe48c8ba4e1defd7b0a169820cde1a014f52283da24bd788e2c1fcaeaee`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Eijen-384` reference `CryptHash`, 384-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/eijen384_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

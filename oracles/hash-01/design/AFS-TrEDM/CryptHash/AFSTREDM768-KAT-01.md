# AFSTREDM768-KAT-01: source-pinned submitted KAT consistency

- Claim: `AFSTREDM768-K` in `oracles/spec/hash-01-AFS-TrEDM.md`; source locator PDF pp. 8–9, 18; `AFS-TrEDM/Implementations/Reference_Implementation/AFS-TrEDM-768/CryptHash_AlgorithmInstance.h` SHA-256 `f696fde04fe207968800e31758fa39763e3ab5cb4cc77072b4921bc559916d6a`; `AFS-TrEDM/Test_Vectors/KAT_2_12_AFS-TrEDM-768.txt` SHA-256 `b267eb72b1ce2a7e2f162f7fddcdafaade51b052f661ec1e1bc5779cd4851b3b`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `AFS-TrEDM-768` reference `CryptHash`, 768-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/afstredm768_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

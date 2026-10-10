# AFSTREDM1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `AFSTREDM1024-K` in `oracles/spec/hash-01-AFS-TrEDM.md`; source locator PDF pp. 8–9, 18; `AFS-TrEDM/Implementations/Reference_Implementation/AFS-TrEDM-1024/CryptHash_AlgorithmInstance.h` SHA-256 `b7a0ee100abeb882ec13ff8748f65ec98da88231c6b6ba61f02e0320a3eaea92`; `AFS-TrEDM/Test_Vectors/KAT_2_12_AFS-TrEDM-1024.txt` SHA-256 `60c18a919b6fece8d1e3df350347c7de41be2fad3ec8a0398177b5c7fed05a39`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `AFS-TrEDM-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/afstredm1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

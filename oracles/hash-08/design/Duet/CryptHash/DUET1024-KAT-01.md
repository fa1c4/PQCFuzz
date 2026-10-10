# DUET1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `DUET1024-K` in `oracles/spec/hash-08-Duet.md`; source locator PDF pp. 13–14, 18; `Duet/Implementations/Reference_Implementation/Duet-1024/CryptHash_Duet-1024.h` SHA-256 `a89a8ca4e2c7c2d2ea22ed6a869f63f9db47b632732992a23b08f972d0ae5534`; `Duet/Test_Vectors/KAT_2_12_Duet-1024.txt` SHA-256 `6e3366423a2026b0be18ec762a0f8703676c4cb450e8cb621534becaeec29a4b`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Duet-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/duet1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

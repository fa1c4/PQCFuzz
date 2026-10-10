# DUET768-KAT-01: source-pinned submitted KAT consistency

- Claim: `DUET768-K` in `oracles/spec/hash-08-Duet.md`; source locator PDF pp. 13–14, 18; `Duet/Implementations/Reference_Implementation/Duet-768/CryptHash_Duet-768.h` SHA-256 `812d676cfb48aedd1a6599d70d50663fc1cf8effd9a8d7e9836d049944b66d3d`; `Duet/Test_Vectors/KAT_2_12_Duet-768.txt` SHA-256 `506abf4ae7a571da6fc0aeb372e556a4e5a0c7f97352c400ce20367a3729c50f`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Duet-768` reference `CryptHash`, 768-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/duet768_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

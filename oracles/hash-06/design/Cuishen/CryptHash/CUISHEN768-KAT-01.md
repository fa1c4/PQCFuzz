# CUISHEN768-KAT-01: source-pinned submitted KAT consistency

- Claim: `CUISHEN768-K` in `oracles/spec/hash-06-Cuishen.md`; source locator PDF pp. 7–9; `Cuishen/Implementations/Reference_Implementation/Cuishen-768/CryptHash_Cuishen-768.h` SHA-256 `e236cebc8824394fc0488d1652c106cf0fec5b90ec0e289c2d45fe4bc59a33a0`; `Cuishen/Test_Vectors/KAT_2_12_Cuishen-768.txt` SHA-256 `18dcee6282ccd8171fc68aa848a04993ae21ff742efd2e70eaf01a4555c2c935`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Cuishen-768` reference `CryptHash`, 768-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/cuishen768_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

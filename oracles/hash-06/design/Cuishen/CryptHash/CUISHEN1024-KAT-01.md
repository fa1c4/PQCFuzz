# CUISHEN1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `CUISHEN1024-K` in `oracles/spec/hash-06-Cuishen.md`; source locator PDF pp. 7–9; `Cuishen/Implementations/Reference_Implementation/Cuishen-1024/CryptHash_Cuishen-1024.h` SHA-256 `47969954ffee6230e5bc8203d68470e45776c5f7198d49f53a23acd3e0500887`; `Cuishen/Test_Vectors/KAT_2_12_Cuishen-1024.txt` SHA-256 `fee17c0fbe2c5638f008ec36ede2858a1ee8009d95279fc2880b7da2e397a9c1`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Cuishen-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/cuishen1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

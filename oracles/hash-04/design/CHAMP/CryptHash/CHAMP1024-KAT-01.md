# CHAMP1024-KAT-01: source-pinned submitted KAT consistency

- Claim: `CHAMP1024-K` in `oracles/spec/hash-04-CHAMP.md`; source locator PDF p. 4; `CHAMP/Implementations and Test_Vectors/API_CryptHash/Implementations/Reference_Implementation/CHAMP-1024/CryptHash_AlgorithmInstance.h` SHA-256 `0b3181b842b82713fea38e2ac42c72e22da65178e3e544de80c1ac7dfa08e94d`; `CHAMP/Implementations and Test_Vectors/API_CryptHash/Test_Vectors/KAT_2_12_CHAMP-1024.txt` SHA-256 `7609a32270418bac434daade83837177fbf01984099f9262b18a15a361690d5f`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `CHAMP-1024` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/champ1024_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

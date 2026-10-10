# EIJEN256-KAT-01: source-pinned submitted KAT consistency

- Claim: `EIJEN256-K` in `oracles/spec/hash-09-Eijen.md`; source locator PDF pp. 5, 10; `Eijen/Implementations/Reference_Implementation/Eijen-256/CryptHash_AlgorithmInstance.h` SHA-256 `f12869355a847875c7bddd4d64323946e598343624317d0010779991e5fed1bd`; `Eijen/Test_Vectors/KAT_2_12_Eijen-256.txt` SHA-256 `ae96fba851ae851a91718eeedcac88f6fc5305ee1d6ea74ccdc5ecd54baedb18`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Eijen-256` reference `CryptHash`, 256-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/eijen256_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

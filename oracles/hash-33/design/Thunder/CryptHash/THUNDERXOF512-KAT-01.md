# THUNDERXOF512-KAT-01: source-pinned submitted KAT consistency

- Claim: `THUNDERXOF512-K` in `oracles/spec/hash-33-Thunder.md`; source locator PDF pp. 7–8; `Thunder/Implementations and Test_vector/Thunder-ARM/Implementations/Reference_Implementation/Thunder-XOF-512/CryptHash_AlgorithmInstance.h` SHA-256 `bf3a197f010de106a7e324d23b71dcf41400b03830ba66ca405ee722e03028f3`; `Thunder/Implementations and Test_vector/Thunder-ARM/Test_Vector/KAT_2_12_Thunder-XOF-512.txt` SHA-256 `9a86aa91faf0a622b456a0968f821c68661d59fe39a83289f23ea963b7f3ca20`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Thunder-XOF-512` reference `CryptHash`, 1024-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/thunderxof512_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

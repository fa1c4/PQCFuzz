# THUNDER768-KAT-01: source-pinned submitted KAT consistency

- Claim: `THUNDER768-K` in `oracles/spec/hash-33-Thunder.md`; source locator PDF pp. 7–8; `Thunder/Implementations and Test_vector/Thunder-ARM/Implementations/Reference_Implementation/Thunder-768/CryptHash_AlgorithmInstance.h` SHA-256 `766e1c51851d289d0b0f595fb7002d68c7770a942bb68f95f9b7da7b7588f62f`; `Thunder/Implementations and Test_vector/Thunder-ARM/Test_Vector/KAT_2_12_Thunder-768.txt` SHA-256 `815e70e81ce3820a5429e6e73e6e82ce6eefe6040170994f48acb9c5a80ddc9d`.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `Thunder-768` reference `CryptHash`, 768-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `implement/mutator/thunder768_kat.py`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.

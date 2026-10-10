# FLIT512-KEMENC-P2-01: kem_enc public API relation

- Claim: `FLIT512-KEMENC-C` in `oracles/spec/kem-15-FLIT.md`; locator PDF p. 15; `Implementations/Reference_Implementation/FLIT512/KEM_AlgorithmInstance.h` SHA-256 `2d5a553d5204933dc45b974323f738242158f2d927e215c0b5f20f06dbe89044`; `Test_Vectors/KAT_KEM_FLIT512_REF.txt` SHA-256 `e4019117230dc2ef5983e8c2c252f08189e8004e3b7db595a66eec3aa8d9820c`.
- Property: K03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `FLIT512` `kem_enc` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `kem_enc` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/flit512-kemenc-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

# FLIT128-KEMKEYGEN-P2-01: kem_keygen public API relation

- Claim: `FLIT128-KEMKEYGEN-C` in `oracles/spec/kem-15-FLIT.md`; locator PDF p. 15; `Implementations/Reference_Implementation/FLIT128/KEM_AlgorithmInstance.h` SHA-256 `0c5c432f8692632a49d039e6018952607eddd04852bf4062e29d9117eaf014a4`; `Test_Vectors/KAT_KEM_FLIT128_REF.txt` SHA-256 `a772deebcc67af946d60d9ebab8014318879617de619692bd59650196b578e69`.
- Property: K03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `FLIT128` `kem_keygen` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `kem_keygen` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/flit128-kemkeygen-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

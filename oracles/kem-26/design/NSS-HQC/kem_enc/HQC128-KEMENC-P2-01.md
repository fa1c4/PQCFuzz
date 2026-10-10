# HQC128-KEMENC-P2-01: kem_enc public API relation

- Claim: `HQC128-KEMENC-C` in `oracles/spec/kem-26-NSS-HQC.md`; locator PDF pp. 22–24; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-128/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-128.txt` SHA-256 `66a0fe8816a982506b0d799c43fcdd18d0434fc54b12fc1e2cc50c0603af8bfc`.
- Property: K03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `HQC-128` `kem_enc` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `kem_enc` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/hqc128-kemenc-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

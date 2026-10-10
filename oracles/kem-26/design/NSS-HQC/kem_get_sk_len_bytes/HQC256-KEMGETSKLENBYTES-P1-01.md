# HQC256-KEMGETSKLENBYTES-P1-01: kem_get_sk_len_bytes public API relation

- Claim: `HQC256-KEMGETSKLENBYTES-C` in `oracles/spec/kem-26-NSS-HQC.md`; locator `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-256/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-256.txt` SHA-256 `8cdfacea8444ed8e1380b9ce3cdb4f1ee270acfd35bcd39bb50ac3c4e00c9454`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `HQC-256` `kem_get_sk_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `kem_get_sk_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/hqc256-kemgetsklenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

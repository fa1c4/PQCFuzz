# LORESM3L1-KEMGETSSLENBYTES-P1-01: kem_get_ss_len_bytes public API relation

- Claim: `LORESM3L1-KEMGETSSLENBYTES-C` in `oracles/spec/kem-19-Lore.md`; locator `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L1.txt` SHA-256 `74bdbeda5c9e37a7d1347cf51fd31424be457d2fee9a68b3e303b6fcc6afd95e`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `Lore-SM3-L1` `kem_get_ss_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `kem_get_ss_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/loresm3l1-kemgetsslenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

# POLARKEM256-KEMGETSSLENBYTES-P1-01: kem_get_ss_len_bytes public API relation

- Claim: `POLARKEM256-KEMGETSSLENBYTES-C` in `oracles/spec/kem-29-Polar-KEM.md`; locator `Submission_Package/Implementations/Reference_Implementation/PolarKEM-256/KEM_AlgorithmInstance.h` SHA-256 `83a9469ee6fb2a2b3c5fe8a7feb5c592ae6f56fe0560e87e26d98eb64585abb9`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-256.txt` SHA-256 `2b0b827c53fa82bf8cef7ceb29868c40f08882b37be8088a7b3d0c820b88195b`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `PolarKEM-256` `kem_get_ss_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `kem_get_ss_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/polarkem256-kemgetsslenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

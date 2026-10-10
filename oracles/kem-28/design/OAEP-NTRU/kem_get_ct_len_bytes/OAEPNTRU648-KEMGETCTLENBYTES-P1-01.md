# OAEPNTRU648-KEMGETCTLENBYTES-P1-01: kem_get_ct_len_bytes public API relation

- Claim: `OAEPNTRU648-KEMGETCTLENBYTES-C` in `oracles/spec/kem-28-OAEP-NTRU.md`; locator `Implementations/Reference_Implementation/OAEP-NTRU-648/KEM_AlgorithmInstance.h` SHA-256 `8580ca34bff25787dea1e130000962e5c13040ebbb2f7485b180eedd388c0bbf`; `Test_Vectors/KAT_KEM_OAEP-NTRU-648.txt` SHA-256 `b4733e7c232600120eafc607e2aa04402111d8e9cc9279965ed5cf429321740d`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `OAEP-NTRU-648` `kem_get_ct_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `kem_get_ct_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/oaepntru648-kemgetctlenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

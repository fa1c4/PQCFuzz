# TRIKE5-KEMGETSKLENBYTES-P1-01: kem_get_sk_len_bytes public API relation

- Claim: `TRIKE5-KEMGETSKLENBYTES-C` in `oracles/spec/kem-36-TRIKE.md`; locator `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-5/src/KEM_AlgorithmInstance.h` SHA-256 `e90b987c1e45b636001e5f77cd656ed672bf763eb53c1e3a718676a693b2144f`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-5.txt` SHA-256 `0322e5244f6f9b6c381561e6519fbf7f30b3658d66693d5832ff596894032362`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `TRIKE-5` `kem_get_sk_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `kem_get_sk_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/trike5-kemgetsklenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

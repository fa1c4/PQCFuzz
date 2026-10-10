# POLARLAC256-KEMGETSKLENBYTES-P1-01: kem_get_sk_len_bytes public API relation

- Claim: `POLARLAC256-KEMGETSKLENBYTES-C` in `oracles/spec/kem-30-PolarLAC.md`; locator `Implementations/Reference_Implementation/x86/POLARLAC-256/KEM_AlgorithmInstance.h` SHA-256 `6beadac185c39f1a4663a6cabd2efc5b54cb940239e8ce03b1ee4141ad08c69b`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-256.txt` SHA-256 `0607ad1d8b26c1be60c72b8ad858b73a5a92d8b4cce2a5167a8eceb157848454`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `POLARLAC-256` `kem_get_sk_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `kem_get_sk_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/polarlac256-kemgetsklenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

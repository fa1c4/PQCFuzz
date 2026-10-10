# SHUTTLE512-SIGGETPKLENBYTES-P1-01: sig_get_pk_len_bytes public API relation

- Claim: `SHUTTLE512-SIGGETPKLENBYTES-C` in `oracles/spec/sign-23-Shuttle.md`; locator `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-512/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-512.txt` SHA-256 `58db9d94375d91b9a941134b5b06a32d430f7866636c081a81725fdfac66a3bb`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `SHUTTLE-512` `sig_get_pk_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `sig_get_pk_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/shuttle512-siggetpklenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

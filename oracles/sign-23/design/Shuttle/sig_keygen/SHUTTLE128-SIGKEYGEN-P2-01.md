# SHUTTLE128-SIGKEYGEN-P2-01: sig_keygen public API relation

- Claim: `SHUTTLE128-SIGKEYGEN-C` in `oracles/spec/sign-23-Shuttle.md`; locator PDF p. 10; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-128/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-128.txt` SHA-256 `2c3a69e9a24315af747bae07309a7c4ad02fd29808461f9198aad29a6e0a60b3`.
- Property: S03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `SHUTTLE-128` `sig_keygen` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `sig_keygen` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/shuttle128-sigkeygen-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

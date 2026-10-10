# AIGISSIGII-SIGGETSKLENBYTES-P1-01: sig_get_sk_len_bytes public API relation

- Claim: `AIGISSIGII-SIGGETSKLENBYTES-C` in `oracles/spec/sign-01-Aigis-Sig+.md`; locator `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-II/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig2.txt` SHA-256 `21e152e13afdac3c1e189f02ad0413159df4477662c2f946bf77d91ce3a5a472`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `Aigis-Sig+-II` `sig_get_sk_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `sig_get_sk_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/aigissigii-siggetsklenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

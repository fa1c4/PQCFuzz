# AIGISENCIII-KEMGETCTLENBYTES-P1-01: kem_get_ct_len_bytes public API relation

- Claim: `AIGISENCIII-KEMGETCTLENBYTES-C` in `oracles/spec/kem-01-Aigis-Enc+.md`; locator `Implementations/Reference_Implementation/Aigis-Enc+-III/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc3.txt` SHA-256 `1c7be3d27d749b6cb4ae83983799f5f1ea4cc6ca0d386967f9448943ab1c393c`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `Aigis-Enc+-III` `kem_get_ct_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `kem_get_ct_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/aigisenciii-kemgetctlenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

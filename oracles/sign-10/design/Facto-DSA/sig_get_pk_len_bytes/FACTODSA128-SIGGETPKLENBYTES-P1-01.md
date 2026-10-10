# FACTODSA128-SIGGETPKLENBYTES-P1-01: sig_get_pk_len_bytes public API relation

- Claim: `FACTODSA128-SIGGETPKLENBYTES-C` in `oracles/spec/sign-10-Facto-DSA.md`; locator `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-128/SIG_AlgorithmInstance.h` SHA-256 `d1ff0df1e12ee725f8c31b0def204745f66f5486c7389e28dd516c8568366431`; `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-128.txt` SHA-256 `d80c26116d6f0940ad57993af12a4932983bddf052afa07606840db8a73f95a5`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `Facto-DSA-128` `sig_get_pk_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `sig_get_pk_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/factodsa128-siggetpklenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

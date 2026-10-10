# TSUOV128-SIGGETPKLENBYTES-P1-01: sig_get_pk_len_bytes public API relation

- Claim: `TSUOV128-SIGGETPKLENBYTES-C` in `oracles/spec/sign-31-TSUOV.md`; locator `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_128/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_128.txt` SHA-256 `f880573499a298ace2e834a9ea21be65e8aca4e9cd2543d48b273140618cd34c`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `TSUOV_128` `sig_get_pk_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `sig_get_pk_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/tsuov128-siggetpklenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

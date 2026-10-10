# TSUOV512-SIGKEYGEN-P2-01: sig_keygen public API relation

- Claim: `TSUOV512-SIGKEYGEN-C` in `oracles/spec/sign-31-TSUOV.md`; locator PDF p. 24; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_512/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_512.txt` SHA-256 `bac1cf750e1900bc72d283ab7c0ecb6991303464b258546a9adfb1f9f7fd9f6e`.
- Property: S03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `TSUOV_512` `sig_keygen` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `sig_keygen` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/tsuov512-sigkeygen-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

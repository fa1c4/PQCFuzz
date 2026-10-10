# AIGISSIGI-SIGSIGN-P2-01: sig_sign public API relation

- Claim: `AIGISSIGI-SIGSIGN-C` in `oracles/spec/sign-01-Aigis-Sig+.md`; locator PDF p. 11; `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-I/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig1.txt` SHA-256 `5e29fe8057c7193b86567f9ee8ff20998bccb165648931e0b5a9154487b867ef`.
- Property: S03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `Aigis-Sig+-I` `sig_sign` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `sig_sign` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/aigissigi-sigsign-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

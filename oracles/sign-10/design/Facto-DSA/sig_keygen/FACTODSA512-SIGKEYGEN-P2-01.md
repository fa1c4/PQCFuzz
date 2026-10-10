# FACTODSA512-SIGKEYGEN-P2-01: sig_keygen public API relation

- Claim: `FACTODSA512-SIGKEYGEN-C` in `oracles/spec/sign-10-Facto-DSA.md`; locator PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-512/SIG_AlgorithmInstance.h` SHA-256 `847b7485077c7e11ce95fa442be7bf311d5f2f7a6957c238116fbcde2a31b1bb`; `generator/output/KAT_SIG_Facto-DSA-512.txt` SHA-256 `192bca21b8e1f83c5a3e31b051eb662853c72709576737daf637e210d58ee5e3`.
- Property: S03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `Facto-DSA-512` `sig_keygen` public function, pinned primary reference source and ten locally regenerated KAT-generator records; valid key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid locally regenerated KAT-generator key pair or a freshly generated key pair, the complementary public operations complete an honest roundtrip.
- Observable: `sig_keygen` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: generated_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact locally regenerated length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/factodsa512-sigkeygen-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

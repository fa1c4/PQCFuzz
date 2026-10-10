# FACTODSA128-SIGKEYGEN-P2-01: sig_keygen public API relation

- Claim: `FACTODSA128-SIGKEYGEN-C` in `oracles/spec/sign-10-Facto-DSA.md`; locator PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-128/SIG_AlgorithmInstance.h` SHA-256 `d1ff0df1e12ee725f8c31b0def204745f66f5486c7389e28dd516c8568366431`; `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-128.txt` SHA-256 `d80c26116d6f0940ad57993af12a4932983bddf052afa07606840db8a73f95a5`.
- Property: S03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `Facto-DSA-128` `sig_keygen` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `sig_keygen` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/factodsa128-sigkeygen-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

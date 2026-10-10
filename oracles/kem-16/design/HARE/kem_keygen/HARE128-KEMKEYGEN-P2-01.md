# HARE128-KEMKEYGEN-P2-01: kem_keygen public API relation

- Claim: `HARE128-KEMKEYGEN-C` in `oracles/spec/kem-16-HARE.md`; locator PDF p. 9; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-128/kr/KEM_AlgorithmInstance.h` SHA-256 `27f84e514b3d81a4747b141d53a14f36c228306a8372c7b8c7f760ba2b6e2eea`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-128-kr.txt` SHA-256 `fbb71eee548f838976461c754e4b4d6e3dcb8e22d480ad81f9df00baada38f7f`.
- Property: K03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `HARE-128` `kem_keygen` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `kem_keygen` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/hare128-kemkeygen-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

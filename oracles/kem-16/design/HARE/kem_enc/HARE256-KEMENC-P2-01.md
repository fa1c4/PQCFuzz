# HARE256-KEMENC-P2-01: kem_enc public API relation

- Claim: `HARE256-KEMENC-C` in `oracles/spec/kem-16-HARE.md`; locator PDF p. 9; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-256/kr/KEM_AlgorithmInstance.h` SHA-256 `298e1624266f2b726455ed8bb961e71a10f8553817b036b0864c3ec07287c060`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-256-kr.txt` SHA-256 `543e2ac2ec9a9d6267e11125fd0683f53920a0a71a3ab54df1ff198f29716221`.
- Property: K03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `HARE-256` `kem_enc` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `kem_enc` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/hare256-kemenc-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

# OAEPNTRU2592-KEMENC-P2-01: kem_enc public API relation

- Claim: `OAEPNTRU2592-KEMENC-C` in `oracles/spec/kem-28-OAEP-NTRU.md`; locator PDF p. 6; `Implementations/Reference_Implementation/OAEP-NTRU-2592/KEM_AlgorithmInstance.h` SHA-256 `295bf457a63fe0392b13374002cc71edbf83e832e88ed88083927487948c2b71`; `Test_Vectors/KAT_KEM_OAEP-NTRU-2592.txt` SHA-256 `4b8026ebc6f901358feafb811211be535b4a862a8e5b062d0a9cda865b0bc034`.
- Property: K03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `OAEP-NTRU-2592` `kem_enc` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `kem_enc` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/oaepntru2592-kemenc-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

# LOREL2-KEMENC-P2-01: kem_enc public API relation

- Claim: `LOREL2-KEMENC-C` in `oracles/spec/kem-19-Lore.md`; locator PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L2.txt` SHA-256 `3735ec4f854bd1230b63a0502b03b845fb3c8af04f3fba872455fb92ed961b8a`.
- Property: K03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `Lore-L2` `kem_enc` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `kem_enc` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/lorel2-kemenc-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

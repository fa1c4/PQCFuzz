# NTRE128-KEMENC-P2-01: kem_enc public API relation

- Claim: `NTRE128-KEMENC-C` in `oracles/spec/kem-27-NTRE Key Encapsulation Mechanism.md`; locator PDF p. 18; `Implementations/Reference_Implementation/NTRE-128/KEM_AlgorithmInstance.h` SHA-256 `093b78a8d0dbc29a73506622227aa2eee1847f1c8a705f498dc53e4a75a769cc`; `Implementations/Reference_Implementation/NTRE-128/output/KAT_KEM_NTRE-128.txt` SHA-256 `65cab746a920cf829732bdb6e2c9f2a9caf198d3fa676a48c85f03f897a87af7`.
- Property: K03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `NTRE-128` `kem_enc` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `kem_enc` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/ntre128-kemenc-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

# AMOEBA864-KEMENC-P2-01: kem_enc public API relation

- Claim: `AMOEBA864-KEMENC-C` in `oracles/spec/kem-02-Amoeba.md`; locator PDF pp. 7–9; `Implementations/Reference_Implementation/Amoeba-864/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba192.txt` SHA-256 `10440a828ae85edbecd129d1a070eb8b2f820cddb37ade5abe4627eaf1183878`.
- Property: K03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `Amoeba-864` `kem_enc` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `kem_enc` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/amoeba864-kemenc-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

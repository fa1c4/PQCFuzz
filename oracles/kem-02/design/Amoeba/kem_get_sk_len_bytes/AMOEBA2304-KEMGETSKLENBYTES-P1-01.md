# AMOEBA2304-KEMGETSKLENBYTES-P1-01: kem_get_sk_len_bytes public API relation

- Claim: `AMOEBA2304-KEMGETSKLENBYTES-C` in `oracles/spec/kem-02-Amoeba.md`; locator `Implementations/Reference_Implementation/Amoeba-2304/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba512.txt` SHA-256 `08d4f43a29be52118fc3a5f5b0c495f66c25be031e7f837b8749c4521039dfc6`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `Amoeba-2304` `kem_get_sk_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `kem_get_sk_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/amoeba2304-kemgetsklenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

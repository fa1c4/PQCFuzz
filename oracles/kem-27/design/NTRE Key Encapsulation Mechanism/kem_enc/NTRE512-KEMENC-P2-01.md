# NTRE512-KEMENC-P2-01: kem_enc public API relation

- Claim: `NTRE512-KEMENC-C` in `oracles/spec/kem-27-NTRE Key Encapsulation Mechanism.md`; locator PDF p. 18; `Implementations/Reference_Implementation/NTRE-512/KEM_AlgorithmInstance.h` SHA-256 `6d418768fa7ae0af64f3eb1dd00406a24b6c879e6dbacf3dcf06565258ce701d`; `Implementations/Reference_Implementation/NTRE-512/output/KAT_KEM_NTRE-512.txt` SHA-256 `b3608ede368d63bf002e4819139f748c1e387e1354d98de93420d5db99e24402`.
- Property: K03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `NTRE-512` `kem_enc` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `kem_enc` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/ntre512-kemenc-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

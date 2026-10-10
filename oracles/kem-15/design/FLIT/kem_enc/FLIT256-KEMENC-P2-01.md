# FLIT256-KEMENC-P2-01: kem_enc public API relation

- Claim: `FLIT256-KEMENC-C` in `oracles/spec/kem-15-FLIT.md`; locator PDF p. 15; `Implementations/Reference_Implementation/FLIT256/KEM_AlgorithmInstance.h` SHA-256 `8a4a7e0fd2cd19925bb423baf6c2a527c071f59b141bcc03ff1c0e7727d72edf`; `Test_Vectors/KAT_KEM_FLIT256_REF.txt` SHA-256 `0788e13e3a0c0ff0c8ada4defab0ea4213bf7980bcb6099dba1a2e35b05ea618`.
- Property: K03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `FLIT256` `kem_enc` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `kem_enc` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/flit256-kemenc-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

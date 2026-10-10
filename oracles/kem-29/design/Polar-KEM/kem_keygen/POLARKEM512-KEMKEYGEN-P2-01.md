# POLARKEM512-KEMKEYGEN-P2-01: kem_keygen public API relation

- Claim: `POLARKEM512-KEMKEYGEN-C` in `oracles/spec/kem-29-Polar-KEM.md`; locator PDF p. 11; `Submission_Package/Implementations/Reference_Implementation/PolarKEM-512/KEM_AlgorithmInstance.h` SHA-256 `5359792389effa0ef1dde564235b44e814c57cdc45dd755d5e4177a085711a91`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-512.txt` SHA-256 `4f0aaf3430199e17af2e758b37219f2615bfc7ea810bffa2b8fe5078d1175f47`.
- Property: K03 version 1; pattern: P2 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `PolarKEM-512` `kem_keygen` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Observable: `kem_keygen` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, honest_roundtrip, rng_control, output_canary.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/polarkem512-kemkeygen-p2-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

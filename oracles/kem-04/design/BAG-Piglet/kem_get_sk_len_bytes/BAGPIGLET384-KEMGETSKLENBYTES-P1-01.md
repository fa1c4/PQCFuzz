# BAGPIGLET384-KEMGETSKLENBYTES-P1-01: kem_get_sk_len_bytes public API relation

- Claim: `BAGPIGLET384-KEMGETSKLENBYTES-C` in `oracles/spec/kem-04-BAG-Piglet.md`; locator `Implementations/Reference_Implementation/bag_piglet384/src/kat/KEM_AlgorithmInstance.h` SHA-256 `60593ab900184b42a28674a41a57feac0cadf32df26b6fa464c304481c8017a9`; `Test_Vectors/KAT_KEM_bag_piglet_384.txt` SHA-256 `26293e3c85763b06d5bd8cc896fb150fb3032099ebce2bb6d96997793933420b`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `bag_piglet384` `kem_get_sk_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `kem_get_sk_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/bagpiglet384-kemgetsklenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

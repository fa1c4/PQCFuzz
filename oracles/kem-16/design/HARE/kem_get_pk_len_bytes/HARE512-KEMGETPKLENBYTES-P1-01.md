# HARE512-KEMGETPKLENBYTES-P1-01: kem_get_pk_len_bytes public API relation

- Claim: `HARE512-KEMGETPKLENBYTES-C` in `oracles/spec/kem-16-HARE.md`; locator `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-512/kr/KEM_AlgorithmInstance.h` SHA-256 `7dc0ec26a36a531982d31fcb2077cbc67564856f3f06de07eaa6dc61642cac3b`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-512-kr.txt` SHA-256 `a5ec74c424e0f0408c31811ec847b1f71f4582ebe0b45fd696ffb3964ed1ddc6`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `HARE-512` `kem_get_pk_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `kem_get_pk_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/hare512-kemgetpklenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

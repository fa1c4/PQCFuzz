# OPSSIG256-SIGGETSNLENBYTES-P1-01: sig_get_sn_len_bytes public API relation

- Claim: `OPSSIG256-SIGGETSNLENBYTES-C` in `oracles/spec/sign-17-OPS Digital Signature Algorithm.md`; locator `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-256/SIG_AlgorithmInstance.h` SHA-256 `03b221a09a67995cef7449d321519f26227c024de58caa64690f16075eadeb5a`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-256/KAT_SIG_OPSsig-256-reference.txt` SHA-256 `61881f46ecea283f08cf7e3ca51da570b856e80064b719209743e4c8a6b25f1c`.
- Property: X05 version 1; pattern: P1 version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `OPSsig-256` `sig_get_sn_len_bytes` public function, pinned primary reference source and ten KAT records; valid submitted key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Observable: `sig_get_sn_len_bytes` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: submitted_kat, indexed_public_vector, submitted_lengths.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `implement/mutator/opssig256-siggetsnlenbytes-p1-01.py`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.

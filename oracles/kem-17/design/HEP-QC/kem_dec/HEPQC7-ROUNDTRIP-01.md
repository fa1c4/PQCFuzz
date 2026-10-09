# HEPQC7-ROUNDTRIP-01: HEP-QC honest KEM round trip

- Claim: `HEPQC7-R` in `oracles/spec/kem-17-HEP-QC.md`; PDF pp. 16–18 §3.7 Algorithms 4–6.
- Property: K03 version 1, KEM correctness. Pattern: P2 version 1, round-trip relation.
- Extraction status: draft (`unverified_spec`), candidate-only.
- Scope/preconditions: `hep-qc-7` run-local submitted build, two indexed public KAT seeds; `prng_init` controls the actual `prng_get_bytes` used by `kem_keygen` and `kem_enc`.
- Baseline: Honest keygen→enc→dec under the first public seed.
- Intervention: Reset the PRNG with a different indexed public seed, then repeat all three calls.
- Expected relation: For each seed, encapsulated and decapsulated shared-secret bytes agree, with success status, exact lengths and untouched output guards.
- Observables: Actual `kem_keygen`, `kem_enc`, `kem_dec` results and output bytes. No secret keys are emitted into traces.
- Positive control: Distinct public seeds, both honest triples reach all APIs and agree.
- Negative control: No seed-index change is ineffective and `inconclusive`.
- Fault control: Flip one observed decapsulated-secret bit after real calls; predicate must detect mismatch.
- Required capabilities: indexed_public_vector, seeded_prng, honest_roundtrip, output_canary.
- Predicate: Check source provenance, API statuses, lengths, guards and two independent shared-secret equalities.
- Paired mutator: `implement/mutator/roundtrip_7.py`.
- Limitations: Public deterministic seeds and finite trials do not prove reliability or confidentiality; archived KAT bytes are not the expected outputs for this oracle.

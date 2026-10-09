# PAVELOR512-DIFF-01: Pavelor-512 source-pinned relation

- Claim: `PAVELOR512-D` in `oracles/spec/hash-22-Pavelor.md`; PDF pp. 5–8 §1.2 for the algorithm and `Pavelor/Implementations and Test_Vectors/API_CryptHash/Test_Vector/KAT_2_12_Pavelor-512.txt` for KAT observations.
- Property: X05 version 1. Pattern: P3 version 1.
- Extraction status: draft; results are `unverified_spec` candidates.
- Scope/preconditions: Exact `Pavelor-512` `512`-bit `CryptHash`, canonical bitstring storage, successful target calls, pinned source and exact KAT provenance when used.
- Baseline: Valid public input on the submitted reference path.
- Intervention: switch only the submitted backend; paired mutator records changed fields and effectiveness.
- Expected relation: reference and optimized digests match for the same bitstring, and a bound KAT digest when present.
- Observables: Target reachability, status, output bytes and length, 16-byte output canary, exact vector path/hash/index when applicable.
- Positive control: Real submitted 512-bit row for P3, distinct 512/513-bit rows for P1.
- Negative control: Identical input/backends or repeated KAT row is ineffective and `inconclusive`.
- Fault control: Flip one observed digest bit after a real call in smoke; predicate must reject it.
- Required capabilities: bit_input, submitted_kat, dual_backend, output_canary as relevant.
- Predicate: Validate scope/provenance/calls and compare the observed bytes against the declared relation; failure is candidate-only.
- Paired mutator: `implement/mutator/variant_diff_512.py`.
- Limitation: Shared implementation/vector lineage; no finite proof of collision or preimage security.

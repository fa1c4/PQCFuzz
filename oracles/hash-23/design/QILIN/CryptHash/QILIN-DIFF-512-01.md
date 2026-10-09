# QILIN-DIFF-512-01: submitted-backend digest agreement

- Claim: S1 in `oracles/spec/hash-23-QILIN.md`, Qilin v2 printed pp. 3–4 (§1.1–1.3, Algorithm 1). S2 supplies a submitted-vector smoke control.
- Property: X05 version 1, interoperability and exact algorithm identity.
- Pattern: P3 version 1, cross-backend differential.
- Extraction status: draft; any candidate carries `unverified_spec`.
- Scope: QILIN-512, `CryptHash`, 512-bit digest, the archived reference and optimized C backends built from the same official ZIP on a little-endian host.
- Preconditions: Both APIs use identical valid bitstrings, exact message bit length, and `digest_len_bits=512`; both return status zero and 64 output bytes. The two backends are related, not independent implementations.
- Baseline: `backend=reference`, an MSB-first public message and its bit length.
- Intervention: Change only `backend` to `optimized`; the paired `implement/mutator/backend_switch.py` records the change and checks that the bitstring is unchanged.
- Expected relation: Both normalized 64-byte digests are equal. For selected submitted KAT control inputs, both must also equal the archived `Dst` value.
- Observable: Target-call reachability, return status, digest bytes and output length for each backend. A process crash or timeout is a harness observation, not a semantic mismatch.
- Positive control: Both C backends hash a submitted rate-boundary vector and match its `Dst` value.
- Negative control: Identical reference-backend inputs set `effective=false` and are classified `inconclusive`.
- Fault control: `fault_observation` flips one bit of the optimized observation after the real API call. The unchanged predicate must then fail during smoke; the hook is not used in campaigns.
- Required capabilities: `dual_backend`, `bit_input`. The adapter declares no RNG, protocol, or decapsulation capability.
- Predicate: If both real calls are reached and succeed, the backend switch is effective, and lengths are 64 bytes, compare digests; if a submitted expectation is attached, compare each output to that digest too. Only a false relation after passing controls is a `counterexample_candidate`.
- Limitations: The common source lineage can hide shared defects; this relation does not test collision/preimage resistance or unsupported digest lengths. A semantic candidate needs specification review and independent triage before any stronger claim.

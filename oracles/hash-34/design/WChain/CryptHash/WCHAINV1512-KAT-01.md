# WCHAINV1512-KAT-01: submitted known-answer conformance

- Claim: S2 in `oracles/spec/hash-34-WChain.md`; source locator: `WChain/Implementations and Test_Vectors/Test_Vectors/KAT_2_12_WChain-V1-512.txt` in the official source ZIP, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` records generated through the submitted `KAT_CryptHash.c` API.
- Property: X05 version 1, exact algorithm identity against submitted vectors.
- Pattern: P1 version 1, known-answer/reference conformance.
- Extraction status: draft; a mismatch remains `unverified_spec` candidate evidence.
- Scope: WChain-V1-512, submitted `CryptHash` API, 512-bit KAT digest, exact archived source and the registered build profile.
- Preconditions: Two distinct rows from the pinned submitted KAT, matching message bytes, exact bit lengths, fixed output length and requested backend. Both actual calls return success and the expected number of output bytes.
- Baseline: One selected exact submitted KAT row on the requested backend.
- Intervention: Change the public message bytes/bit length to another exact KAT row, keeping backend and output profile unchanged. The paired mutator verifies row and input changes.
- Expected relation: Each output equals its own archived `Dst` value; backend is alternated across campaign iterations. No equality between distinct-message digests is assumed.
- Observable: Target-call reachability, status, output length and digest bytes; case evidence includes both original KAT row indices, source path and source-file SHA-256.
- Positive control: Two distinct submitted rows at the 1152-bit rate boundary and its successor both reproduce their expected digest through real target calls.
- Negative control: The same row twice yields `effective=false` and is classified `inconclusive`.
- Fault control: Flip one bit of the second observed digest after its real target call; the P1 predicate must detect it during smoke only.
- Required capabilities: `bit_input`, `submitted_kat`.
- Predicate: If exact row-to-input/provenance binding, successful actual calls and expected output lengths hold, compare each output separately with its submitted expectation. A false relation is only a `counterexample_candidate`.
- Limitations: Submitted vectors may be produced by the same code lineage and are not independent normative truth. A match covers only selected rows and profiles; a mismatch requires source/specification review. Finite KAT testing proves no computational security property.

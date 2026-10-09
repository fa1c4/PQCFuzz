# LITCHI-XOF-BOUND-01: requested XOF output region

- Claim: S1 in `oracles/spec/hash-15-Litchi.md`, PDF pp. 7–8 §2.2 and p. 11 §2.5, plus the submitted `CryptHash_AlgorithmInstance.h` parameter contract. S2 provides the 1024-bit KAT control.
- Property: X05 version 1, exact algorithm identity across the submitted core and wrapper APIs.
- Pattern: P3 version 1, cross-API differential with normalized requested output and a canary after it.
- Extraction status: draft; any candidate carries `unverified_spec`.
- Scope: Litchi-XOF, public bitstrings, 512/768/1024-bit requests, submitted `litchi_xof` and `CryptHash` on a little-endian host.
- Preconditions: Identical valid message and requested output bits; both functions are reached; output buffers have 144 allocated bytes with `0xa5` canaries after the requested region. This over-allocation observes writes without intentionally corrupting memory.
- Baseline: `backend=core`, invoking `litchi_xof(out, out_bits, message, message_bits)`.
- Intervention: Change only `backend` to `wrapper`, invoking `CryptHash(out_bits, message, message_bits, out)`.
- Expected relation: Both requested output prefixes match and neither API alters any byte after `out_bits/8`. A selected 1024-bit KAT must additionally match its submitted `Dst` in both paths.
- Observable: Actual call reachability, status, requested prefix, first changed canary offset and whether the 16-byte guard after the maximum 1024-bit output changes.
- Positive control: Both paths request 1024 bits for the submitted 576-bit KAT, match its `Dst` and preserve all canaries.
- Negative control: An identical core/core input has `effective=false` and is `inconclusive`.
- Fault control: Mark a canary byte after the maximum 1024-bit output as changed after a real successful call; the predicate must detect the planted write-bound fault in smoke only.
- Required capabilities: `core_wrapper_comparison`, `output_canary`, `bit_input`.
- Predicate: With two actual successful calls and effective backend switch, compare prefixes and require both `guard_modified=false`; where a 1024-bit submitted vector is attached, compare both prefixes to `Dst`. A failed relation after smoke is a `counterexample_candidate` only.
- Limitations: The write-bound interpretation of the C API needs human review; canary modification is not a sanitizer finding, exploit demonstration, or proof of XOF security. The core and wrapper share code, and a divergence does not identify a normative fault until the API contract is reviewed.

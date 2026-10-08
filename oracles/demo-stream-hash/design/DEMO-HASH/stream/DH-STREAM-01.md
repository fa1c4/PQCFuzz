# DH-STREAM-01: streaming digest consistency

- Claim: S1 in the local demo specification, Section 1. The same byte message has the same digest for one or multiple chunks.
- Property: H07 version 1. Pattern: P4 version 1.
- Preconditions: Valid hex encoded chunks, same concatenated message, SHA-256 output length 32.
- Baseline: One chunk. Mutated input: Same bytes split into two chunks.
- Intervention: Change only chunk partition; paired mutator `implement/mutator/chunk_split.py`.
- Observable: Adapter status, reachability, output hex and output length for each call.
- Positive control: `hello world` in one versus two chunks, relation holds.
- Negative control: Identical structured inputs, ineffective, inconclusive.
- Fault control: Oracle flips one byte of the mutated observation and must detect relation failure.
- Required capabilities: `streaming`.
- Predicate: Both calls reached target and returned ok, intervention effective and equal 32-byte digests. A mismatch is a candidate only after smoke controls pass.
- Limits: Local demonstration contract only; digest equality does not establish collision resistance or PQC security.
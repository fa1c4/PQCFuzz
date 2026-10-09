# CHASH512-DIFF-01: C-Hash-512 submitted-backend agreement

- Claim: S1 in `oracles/spec/hash-03-C-Hash.md`, PDF pp. 5–6 and 14, §1.1 and §1.4 (C-Hash-512 CTR-Perm and the mandatory short-message path). S2 supplies submitted KAT controls.
- Property: X05 version 1, interoperability and exact algorithm identity.
- Pattern: P3 version 1, cross-backend differential.
- Extraction status: draft; any candidate is `unverified_spec`.
- Scope: C-Hash-512 `CryptHash`, 512-bit digest, submitted reference/optimized backends built from the same archived source on this host.
- Preconditions: Identical valid bitstrings and exact bit lengths, `digest_len_bits=512`, two zero return codes and two 64-byte digests. Backends share submission lineage.
- Baseline: `backend=reference`, valid public message and bit length.
- Intervention: Change only `backend` to `optimized`; the paired mutator verifies message and bit-length identity.
- Expected relation: Equal normalized 64-byte digests. Selected submitted KAT controls must also match archived `Dst` in both paths.
- Observable: Actual API reachability, return status, output bytes and output length. Crashes and timeouts are harness observations.
- Positive control: A submitted KAT at the 736-bit rate boundary passes both real backends.
- Negative control: An identical reference/reference input sets `effective=false` and yields `inconclusive`.
- Fault control: Flip exactly one bit in the optimized observation after the real call; the oracle must detect the difference during smoke only.
- Required capabilities: `dual_backend`, `bit_input`.
- Predicate: With successful actual calls, effective backend change, matching valid structured inputs and 64-byte outputs, compare both digests; where a submitted KAT expectation is attached, compare both to it as well. A false relation after controls is only a `counterexample_candidate`.
- Limitations: Common lineage and submitted vectors can hide common defects. This does not test computational security or other parameter sets. A candidate requires independent triage.

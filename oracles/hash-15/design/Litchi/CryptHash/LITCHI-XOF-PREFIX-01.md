# LITCHI-XOF-PREFIX-01: requested-length prefix relation

- Claim: `S3` in the draft extraction; Litchi PDF pp. 7–8 §2.2 squeezing rule and p. 11 §2.5 XOF definition.
- Property: X05 version 1, exact XOF API algorithm identity.
- Pattern: P4 version 1, controlled output-request metamorphic relation.
- Extraction status: draft (`unverified_spec`); a failure remains candidate-only.
- Scope: submitted Litchi-XOF core or wrapper, fixed `c=1024,fid=1`, valid public bitstrings and requests of 512, 768 or 1024 bits.
- Preconditions: The same canonical message bytes, exact bit length and backend; only the requested output length changes, and both calls succeed.
- Baseline: A valid 512- or 768-bit output request.
- Intervention: Increase `out_bits` to one of the listed longer requests on the same path; `implement/mutator/xof_prefix.py` records the changed field and effectiveness.
- Expected relation: The shorter output equals the prefix of the longer output. An attached 1024-bit submitted KAT must also match exactly.
- Observable: Actual target reachability, success status, requested output lengths and bytes. Write-bound canaries are evaluated separately by `LITCHI-XOF-BOUND-01`.
- Positive control: A submitted 576-bit message on the core at 512/1024-bit output; longer output equals its pinned KAT and the short output equals its prefix.
- Negative control: Identical 512-bit requests set `effective=false` and yield `inconclusive`.
- Fault control: Flip one bit in the longer observed output after a real call; the predicate must reject it in smoke only.
- Required capabilities: `bit_input`, `variable_output`, `submitted_kat`.
- Predicate: With valid paired requests and successful calls, compare the short digest to the long prefix; where pinned KAT evidence is attached, also compare the long digest to that row. A mismatch is only a `counterexample_candidate`.
- Limitations: This is a functional prefix relation, not a proof of XOF security. The wrapper may write beyond a shorter requested output region; that separate draft API-contract candidate is not hidden by a prefix pass.

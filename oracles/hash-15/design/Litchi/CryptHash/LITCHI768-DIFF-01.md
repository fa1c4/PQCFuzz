# LITCHI768-DIFF-01: Litchi-768 P3 source-pinned relation

- Claim: `LITCHI768-D` in the draft extraction; source locator: PDF pp. 7–8 §2.2 and p. 11 §2.5.
- Property: X05 version 1, exact algorithm identity and interoperability.
- Pattern: P3 version 1, cross-path differential.
- Extraction status: draft (`unverified_spec`); failures remain candidate-only.
- Scope: `Litchi-768` `768`-bit `CryptHash` profile and the two submitted paths `core`/`wrapper`.
- Preconditions: Canonical MSB-first bitstring storage, exact requested output length, successful target calls and pinned source identity. KAT expectations require exact source path, SHA-256 and row index.
- Baseline: A valid public message with `768`-bit output on `core` or a selected KAT path.
- Intervention: switch `core` to `wrapper` with message and output length fixed; the paired structured mutator records changed fields and effectiveness.
- Expected relation: identical 768-bit outputs from `core` and `wrapper` for one bitstring, also equal to a pinned KAT digest when present.
- Observable: Actual target reachability, status, output length, digest bytes and output canary.
- Positive control: Selected submitted 512-bit message row (P3), or the 512/513-bit distinct rows (P1), passes through real submitted code.
- Negative control: Identical structured inputs, or the same KAT row twice, set `effective=false` and yield `inconclusive`.
- Fault control: Flip one bit of an observed digest after a real call; the predicate must reject it in smoke only.
- Required capabilities: `bit_input`, `submitted_kat` for P1 and `dual_backend` or `core_wrapper_comparison` for P3.
- Predicate: Check exact instance and provenance, both successful calls and output lengths; compare the observed digest(s) to the expected relation. A mismatch becomes `counterexample_candidate` only.
- Paired mutator: `implement/mutator/variant_diff_768.py`.
- Limitations: Submitted paths and KATs are not independent specification witnesses. A finite campaign cannot prove collision, preimage or other computational security claims.

# VDOO256-BIND-01: VDOO exact signed-message binding

- Claim: `VDOO256-V` in `oracles/spec/sign-33-VDOO.md`; PDF p. 10 Algorithm 5 and p. 19 §5.7.
- Property: S01 version 1, EUF-CMA witness boundary. Pattern: P5 version 1, acceptance set/freshness.
- Extraction status: draft (`unverified_spec`), candidate-only.
- Scope/preconditions: `VDOO-256` `sig_verify`, exact public KAT key/signature/signed-message history, nonempty message and one effective bit flip.
- Baseline: Verify the archived signature on its recorded message.
- Intervention: Change only the first message bit; keep key, signature and instance fixed. Paired mutator records effectiveness and signed-record index.
- Expected relation: Original accepted, changed-message signature rejected.
- Observables: Two actual API calls, return status, normalized acceptance and archived vector identity.
- Positive control: Valid original and changed message reach the verifier and show accept/reject.
- Negative control: No bit flip is ineffective and `inconclusive`.
- Fault control: Replace observed reject with accept after the real call; predicate must detect it.
- Required capabilities: indexed_public_vector, message_mutation, acceptance_status.
- Predicate: Require exact provenance, valid baseline, reached calls and an effective mutation, then compare accepted/rejected status; failure is a candidate witness only.
- Paired mutator: `implement/mutator/bind_256.py`.
- Limitations: One public test signature and one-bit change do not establish unforgeability or uniqueness of accepted encodings.

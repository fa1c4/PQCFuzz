# Eijen-512 submitted backend agreement

- Claim: S1 in `oracles/spec/hash-09-Eijen.md`; source locator `PDF pp. 5, 10` and submitted backend files in `data/build_sources.json`.
- Property: X05 version 1, same-instance algorithm identity.
- Pattern: P3 version 1, cross-backend differential.
- Extraction status: draft; results are `unverified_spec` candidates.
- Scope: `Eijen-512`, 512-bit `CryptHash`, pinned reference and optimized implementations, canonical public bitstrings.
- Preconditions: Identical bitstring and output length on both backends, successful calls and 64-byte outputs.
- Baseline: Reference backend on one valid bitstring.
- Intervention: Switch only backend to the optimized submitted path; the paired mutator records that change.
- Expected relation: Digests agree for the same bitstring; when an exact KAT row is used, both also equal the bound submitted digest.
- Observable: Target reachability, status, output bytes/length and output-buffer canary; exact KAT provenance when applicable.
- Positive control: Both paths agree on the same 512-bit submitted KAT input through actual target calls.
- Negative control: No backend switch is ineffective and yields `inconclusive`.
- Fault control: Flip one observed digest bit after real calls during smoke; predicate must reject it.
- Required capabilities: `dual_backend`, `bit_input`, `output_canary`.
- Predicate: With matching structured input and observable calls, compare outputs and any bound KAT expectation. False relation is candidate-only.
- Paired mutator: `implement/mutator/diff.py`.
- Limitations: Shared implementation lineage, profile-specific behavior and absent independent reference limit inference; finite testing proves no security property.

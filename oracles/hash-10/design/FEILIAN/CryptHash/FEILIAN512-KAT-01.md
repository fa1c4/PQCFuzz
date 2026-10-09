# FEILIAN512 submitted KAT consistency

- Claim: S2 in `oracles/spec/hash-10-FEILIAN.md`; source locator `FEILIAN/Test_Vectors/KAT_2_12_FEILIAN512.txt`, SHA-256 `081f5e0640f66c15747dc53bf91cd6206fa8e1151f4d598c50edc2fd43db83ef`.
- Property: X05 version 1, exact algorithm identity against submitted vectors.
- Pattern: P1 version 1, known-answer/reference conformance.
- Extraction status: draft; results are `unverified_spec` candidates.
- Scope: `FEILIAN512`, submitted `CryptHash`, 512-bit KAT digest, exact archived source and registered profile.
- Preconditions: Two distinct exact pinned KAT rows, canonical message storage, exact bit lengths, same requested backend, successful calls and 64-byte outputs.
- Baseline: One pinned KAT row on a submitted backend.
- Intervention: Switch message bytes/bit length to a second pinned KAT row, retaining backend and profile. The paired mutator records changed fields and effectiveness.
- Expected relation: Each actual digest equals its own pinned `Dst` value; no equality of different-message digests is assumed.
- Observable: Target reachability, status, output bytes/length and output-buffer canary; exact vector indices/path/SHA in case evidence.
- Positive control: Distinct 512- and 513-bit KAT inputs yield their own recorded digests through actual target calls.
- Negative control: Repeating one row is ineffective and yields `inconclusive`.
- Fault control: Flip one observed digest bit after a real target call during smoke; the predicate must reject it.
- Required capabilities: `bit_input`, `submitted_kat`, `output_canary`.
- Predicate: With exact provenance/input binding and observable successful calls, compare each digest to its own expected row. False relation is candidate-only.
- Paired mutator: `implement/mutator/kat.py`.
- Limitations: Submitted vectors may share implementation lineage; finite testing proves no security property.

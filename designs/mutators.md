# Mutators design

Parent: [architecture.md](architecture.md). Implements DES-03, DES-04.

## Paired implementation

Every registered oracle points to exactly one `oracles/<target>/implement/mutator/<id>.py`. It exposes `generate(seed, iteration) -> case` and `smoke_cases() -> controls`. A case contains a structured `baseline` and `mutated` input, `changed_fields`, `intervention`, and `effective` with an explanation. Changes are made to named fields, not opaque random bytes unless the oracle explicitly tests serialization. Stable seed and iteration reproduce the same case.

## Validity and reachability

The mutator records baseline-domain validity and any expected invalid-input class. Effectiveness is checked against the intended field and the returned inputs, not merely asserted. Runtime invokes the adapter on both inputs and records whether the intended API was reached. An identical or otherwise ineffective mutation is `inconclusive`. A permitted rejection of invalid input is not a security violation absent the specific oracle relation.

## Corpus and controls

Corpus entries use the same structured schema as generated cases and carry provenance. Positive control supplies an evaluable valid case; negative control supplies an ineffective/non-evaluable case; fault control alters an observation through an auditable test hook without modifying production verdict rules. Campaign feedback retains candidates but does not mutate the active knowledge catalogs.

## Acceptance

A fixed seed reproduces the case. Mutation identity, changed fields, effectiveness and both structured inputs are present in each trace.
# Proposed amendment: multi-instance registration for a submitted hash target

Status: **design decision record for the 2026-10-09 SOP continuation; not design authority**. The user instructed continuation after this concrete amendment was presented. The amended `designs/architecture.md` and linked module documents are authoritative; this file preserves the original decision and acceptance criteria.

## Decision needed

The current root/config/oracles/runtime design and schema-v1 code pin one
`parameter_set` in `oracles/<target>/manifest.json`. A configuration entry
also requires unique API names, so the real submitted `CryptHash` cannot be
registered again for another output instance without either lying about its
name or changing the registration model. Seven S-tier packages currently
cover one instance each, while the submitted sources expose 21 digest
instances. The user requested all public functions and instances to be
tested through the SOP.

## Proposed contract

Keep one `oracles/<target>/manifest.json` per source identity. A schema-v2
manifest has `instances[]`, each identified by an exact
`(algorithm, parameter_set, api)` tuple, with its own spec claim links,
profile IDs, adapter capability declaration and oracle/mutator/design paths.
The config registry holds the same instance tuples, allowing a real API name
to repeat across different parameter sets; uniqueness is enforced on the full
tuple and build-profile ID. The CLI accepts `--parameter-set` and requires it
when more than one compatible instance remains. Every adapter call receives
the selected immutable tuple and rejects a different digest length or variant
before target reachability is claimed. Runtime snapshots the tuple in the
manifest, trace and report, and validates each instance's claim scope before
building or scheduling. A shared implementation file is legal only when every
instance still has a separate source-backed oracle design and exact KAT
provenance.

The existing schema-v1 target packages and already retained run artifacts
remain readable with their original meaning. No migration rewrites old
evidence. Source function/branch coverage, if requested, is a separately
instrumented metric with its own build identity; KAT counts never imply it.

## Affected modules and evidence

Affected: `designs/architecture.md` target identity and configuration
paragraphs, `designs/config.md`, `designs/oracles.md`, `designs/adapters.md`,
`designs/runtime.md`, their validators/schemas and target package records.
No proposed relaxation affects DES-01 through DES-10, draft-spec labels or
candidate-only reporting.

Acceptance: ambiguous or cross-instance selection fails closed; all 21
submitted instances are enumerated under the seven source identities; each
new instance has exact spec scope and active-pattern applicability review;
preflight, isolated build, healthy/ineffective/fault controls and campaign
work under an explicit selector; full submitted KAT checks are recorded; run
evidence verifies and retains the complete tuple. The original seven runs
still verify with schema-v1 semantics.

The subsequent user instruction to continue the SOP through all seven S-tier
targets was treated as authorization to apply this contract. No draft
specification was promoted to verified and no finding was promoted to
confirmed. Source function/branch coverage remains a separate measurement.

# Knowledge design

Parent: [architecture.md](architecture.md). Implements DES-01, DES-02, DES-08.

## Catalogs and governance

`knowledge/property/security_property.md` contains active properties; `knowledge/property/candidates.md` contains agent-proposed candidates. `knowledge/oracles/patterns.md` contains active patterns; `knowledge/oracles/futures.md` contains human-managed reserve patterns and occurrence counts. Only a human promotes either reserve class. Agents never change futures or its counts. Each entry has a permanent ID, semantic version, primitive scope, preconditions, limitations and provenance. IDs are never reused or silently aliased.

## Selection

Property selection establishes a target-spec claim in the exact algorithm/parameter/API scope. Pattern selection establishes a concrete relation and the required observables/capabilities. Only active IDs can appear in a registered manifest. A property is not an oracle implementation, and a pattern is not itself a normative claim. If no active property applies, record the gap in the target workspace; candidate properties are not scheduled. If no active pattern fits, record the unmet pattern need there for human review, without editing futures.

## Catalog validation

Runtime parses the active catalog headings/table IDs and rejects unknown, duplicate or future/candidate IDs. Manifest pins ID and version; a semantic catalog change increments version and invalidates smoke for new runs. Existing run manifests retain the old pair. A version mismatch is an actionable configuration error.

## Acceptance

An active property plus pattern is accepted only with scope and preconditions satisfied. Candidate/future IDs, duplicate IDs and mismatched versions are rejected with named diagnostics.
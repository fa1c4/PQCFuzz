# Specification extraction design

Parent: [architecture.md](architecture.md). Implements DES-01, DES-02, DES-04.

## Artifact and authority

One `oracles/spec/<target>-<algorithm>.md` represents one algorithm and exact source edition. Original specification and source snapshots stay in `third_party/<target>/`. The extract is a claim inventory, not an independent standard. Front matter contains `status: draft|verified`, `target`, `algorithm`, `source_path`, `source_sha256`, `document_path`, `document_sha256`, `source_version`, and `extract_version`. Verified extracts also carry `reviewer` and `review_date`. Only the human maintainer changes draft to verified. Both states are registerable; every run snapshots status and extract digest.

## Claim record

Each claim has a stable local claim ID, exact page/section locator, short paraphrase, normative/proposal/API/research classification, primitive/algorithm/parameter/API scope, preconditions, limitations, ambiguity and extraction inference. Quote only the minimum needed. Record disagreement between spec editions explicitly. Unknown scope or ambiguous requirement yields a diagnostic and may not become a semantic oracle predicate.

## Validation and evidence

Preflight verifies path containment, source and extract digests, required front matter, unique claim IDs and a locator for every scheduled claim. Draft results carry `unverified_spec`. A verified status strengthens provenance only; it does not prove implementation conformance. Editing claim semantics changes the extract digest, invalidates earlier smoke eligibility and leaves old run snapshots intact.

## Acceptance

A draft and verified extract both register. A missing locator, mismatched digest or malformed status fails closed. Run evidence links its exact claim and extract digest.
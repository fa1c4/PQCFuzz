# PQCFuzz architecture design

This document is the root of the PQCFuzz design tree. It specifies the intended architecture; it does not describe what the current code already implements.

## Authority and scope

This document defines cross-module requirements. Each linked design in the Modules section refines its module and must not weaken a root invariant. If accepted designs conflict, stop the affected work and present the conflict for a human design decision. `designs/actuality.md` records observed behavior only and is not design authority. Target specifications are authoritative for algorithm-specific normative claims; this design governs their extraction, testing and reporting. Code, configuration, schemas and tests implement these decisions.

The current onboarding scope ends at evidence-preserving counterexample capture and a candidate report. Automatic replay validation, causal triage and confirmed vulnerability classification are deferred. Existing replay/report code and the historical vertical test slice remain implementation facts, not requirements to promote new candidates. A later design amendment must define their integration and artifact migration before they are used for new target campaigns.

Design changes state the decision, affected modules, compatibility impact and observable acceptance evidence. The human maintainer accepts design changes and promotes knowledge entries. Implemented changes are recorded in `history/YYYY-MM-DD.md`; implementation plans belong in `plans/`.

## System flow

`specification + source → extracted claim with provenance → specification extract with recorded review status → target/config identity → property mapping → active oracle-pattern selection → target-specific oracle design → adapter/oracle/mutator implementation → controls and preview or registration smoke test → registered execution → trace and counterexample capture → candidate report`.

An existing `oracles/spec/` document, whether draft or verified, may be the workflow input instead of a PDF. Each transition preserves repository/source identity, algorithm, parameter set, API, build profile, specification version, property ID, pattern ID, oracle ID and evidence class. Missing or incompatible links produce an explicit diagnostic. No new target may silently change another target's semantics.

## Modules

- **Specification extraction** — [specification.md](specification.md) defines source provenance, extraction records, optional human verification and the evidence label carried by drafts.
- **Knowledge** — [knowledge.md](knowledge.md) defines active/candidate properties, active/future patterns, stable IDs and human promotion.
- **Configuration** — [config.md](config.md) defines validated target-algorithm entries, execution profiles, limits and retention policy.
- **Adapters** — [adapters.md](adapters.md) defines the target invocation boundary and declared API/observation capabilities.
- **Oracles** — [oracles.md](oracles.md) defines target-specific claims, relations, controls, dispatch and verdicts.
- **Mutators** — [mutators.md](mutators.md) defines structured interventions paired with each target-specific oracle.
- **Runtime** — [runtime.md](runtime.md) defines dynamic discovery, build, scheduling, smoke tests, campaign execution, trace capture and candidate reporting.

Only these seven linked module documents refine this root. Runtime owns all dynamic execution behavior; the other modules define static knowledge, declarations and target-specific artifacts. Target identity, pairing, schemas and deferred replay/triage remain cross-cutting root requirements rather than separate module documents. Add another module only through an explicit human-approved architecture amendment.

## Knowledge and specification contracts

`knowledge/property/security_property.md` contains active properties; `knowledge/property/candidates.md` contains candidate properties. Both require a stable, never-reused ID, applicable primitive scope, preconditions, limitations, version and source/provenance. An agent may draft a candidate but only a human may promote it to the active file. A candidate is not silently eligible for a registered oracle.

`knowledge/oracles/patterns.md` contains active oracle patterns with the same ID/scope/precondition/limitation/version fields. `knowledge/oracles/futures.md` is a human-maintained reserve of future patterns and occurrence counts. Agents neither edit nor promote entries in that file and scheduling never selects them. If no active pattern fits, the agent records the unmet need in the target workspace for human review; it does not improvise a registered pattern. The human uses these observations to update counts and evaluate future promotion.

A property states the security relation to test; a pattern describes a reusable way to construct inputs, intervention and observation. A target-specific oracle binds a source-backed claim with recorded extraction status, an active property and an active pattern to one implementation/API context. Semantic changes receive new versions so old runs retain their original meaning.

Each `oracles/spec/<target-name>-<algorithm>.md` records specification identity/version, page or section locators, scoped claims, extraction inferences and ambiguities. YAML front matter in that document stores `status: draft` or `status: verified`; only human review changes the status to `verified`, with reviewer and review date recorded there. Verification is optional for registration: both states may drive smoke tests and registered oracles. A run manifest snapshots the spec status and content digest. Draft-based results remain explicitly `unverified_spec` candidates and cannot be reported as confirmed normative violations solely from the extraction. A Markdown extraction in either state is a valid SOP starting point.

## Target identity and static layout

For Git source, `<target-name>` is `<repository-name>-<full-commit>`. For non-Git source, omit the commit and use `<repository-name>`. The source path and a content digest are still recorded; a directory-name collision with different source content is an error, not an implicit merge. An imported source snapshot is not claimed to have a Git commit.

Algorithms and APIs for one target occupy stable subpaths, using `<algorithm>/<api>` consistently in design and implementation references. Build profiles need stable IDs and are distinguished in configuration and run manifests, even when they share the same algorithm/API directory. Every executable identity includes target name, source digest or commit, algorithm, parameter set, API, build profile and oracle ID.

Agent-generated target-specific oracle artifacts live under `oracles/<target-name>/` and are the canonical package for a newly onboarded target. `design/<algorithm>/<api>/<oracle-id>.md` contains the oracle design. `implement/` contains the explicit adapter, oracle and structured mutator code; every registered oracle has a paired mutator under `implement/mutator/`. A machine-validated `manifest.json` binds those files to configuration, property, pattern and specification IDs. Source and original specification inputs remain under `third_party/<target-name>/`.

## Target-specific oracle and capability contract

An oracle design states its source claim, property ID, pattern ID, preconditions, valid baseline, structured input mode, intervention, paired mutator, expected relation, observable values, positive and negative controls, applicability boundary, limitations and exact verdict rule. It also names the adapter capabilities it requires. A mutator records which field changed and whether the intended intervention was effective; malformed inputs or legal rejection are classified according to the oracle's declared relation.

An adapter declares primitive, algorithm, parameter set, implementation/source identity, API and status semantics, plus capabilities such as random-source control, fault injection, intermediate-state observation and access to decapsulation failure paths. Job generation and scheduling validate these declarations. A property outside its declared scope is `not_applicable`; a relevant test lacking required adapter capability is `unsupported`. Neither is a pass.

A semantic counterexample requires a valid baseline, effective intervention, actual target reachability, observable relation and successful controls. Crashes, timeouts and malformed setup are retained as observations but cannot be promoted into a semantic counterexample by default.

## Configuration and onboarding boundary

`configs/targets.json` contains one entry per target and algorithm, with API and build-profile variants inside that entry. It declares source/specification paths, dependencies, execution environment, timeouts, CPU/memory/disk budgets, concurrency isolation, seed policy and data access/retention policy. Schema validation rejects unknown IDs, missing fields, incompatible capabilities and ambiguous profile selection.

`agent/pqc_sop.md` is the single onboarding SOP. From a specification and source tree, the agent produces a status-labeled spec extraction and the target-specific design, adapter, oracle, mutator and manifest under `oracles/<target-name>/`, plus the corresponding configuration entry. These generated target artifacts are the canonical new-target oracle package. The target specification remains authority for normative claims; this architecture and its linked modules govern the package contract. Legacy `src/oracles/specs/*.json` records remain compatibility inputs, not the package authority for newly onboarded targets.

## Runtime and evidence boundary

[runtime.md](runtime.md) owns dynamic discovery/registration, capability-checked job creation, isolated builds, preflight and smoke gates, fuzzing/test execution, trace capture, run storage and candidate-only reporting. The runtime consumes validated static declarations and registered target artifacts; no other module substitutes an unknown target, adapter, pattern, mutator or oracle with a default.

Runtime outputs belong under `workspace/<target-name>/runs/<run-id>/`. A run retains the complete source/spec/config/oracle identity, structured baseline and mutated inputs, effective-intervention and reachability evidence, observations, controls, environment, seed policy and artifact hashes. Draft-spec results carry `unverified_spec`. Automatic replay validation and triage are deferred; current runs record `replay_status: not_run` and never claim a confirmed vulnerability. The detailed stage, status, isolation, data-retention and script contracts belong to [runtime.md](runtime.md).

## Root invariants

**DES-01, evidence:** Every security claim has an identified source, scope and limitations; proposal status and extraction inference are explicit; finite tests do not prove computational security.

**DES-02, fail closed:** Unknown algorithm, oracle/pattern/property ID, adapter, schema version or incompatible configuration yields a diagnostic or harness/configuration error, never an apparent pass.

**DES-03, evaluability:** A semantic counterexample requires a valid baseline, effective intervention, target reachability, observable relation and positive/negative controls; non-evaluable paths are not passes or vulnerabilities.

**DES-04, evidence preservation:** A candidate retains structured input, mutation, harness, source identity, trace semantics and exact run environment; automated replay and validation are deferred.

**DES-05, reporting:** Reports separate candidate, inconclusive, not-applicable, unsupported and harness-error records; no aggregation promotes an unvalidated candidate to a confirmed finding.

**DES-06, extension:** Adapter capabilities and target identity are validated before job generation; signature, KEM, key-exchange and hash targets use appropriate input/observation models.

**DES-07, compatibility:** Design/schema/trace migrations specify old-artifact handling; historical replay-validated records remain interpretable without silently changing the new candidate-only status model.

**DES-08, knowledge governance:** Candidate properties require human promotion; future patterns and occurrence counts are human-maintained and cannot be scheduled as active patterns.

**DES-09, runtime isolation:** Builds, execution, temporary paths and caches are isolated per run, with declared budgets, environment and seed policy.

**DES-10, data governance:** Run evidence is hash-verifiable and immutable while retained; sensitive material follows declared access and retention rules.

## Acceptance evidence

The first onboarding slice should cover both draft and verified specification states, one active property/pattern, one target-specific oracle and paired mutator, a healthy control, a fault-injected counterexample, an ineffective mutation, a missing capability and an unknown ID. The observed outputs must demonstrate draft-based registration with an `unverified_spec` evidence label, correct status separation, target reachability, complete evidence capture and no automatic confirmed-vulnerability report. Existing replay tests remain historical compatibility checks until a future replay design is accepted.



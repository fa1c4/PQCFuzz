# Oracles design

Parent: [architecture.md](architecture.md). Implements DES-01, DES-02, DES-03, DES-05, DES-08.

## Package and design record

`oracles/<target>/manifest.json` pins schema version, source/spec digests, algorithm identity and exact instance identities. Schema v2 contains `instances[]` keyed by `(parameter_set, api)`; each instance pins its profiles, adapter path, capability declaration and oracle records. Each oracle record pins an active property ID/version, active pattern ID/version, exact spec claim ID, design path, executable oracle path, paired mutator path and required capabilities and applicable primitive list. A reused implementation path does not merge claim scope across instances. Schema-v1 manifests retain their original single-instance interpretation. The design at `design/<algorithm>/<api>/<oracle-id>.md` states source locator, preconditions, valid baseline, structured intervention, expected relation, observables, positive and negative controls, fault control, scope/limits, and exact verdict predicate. A generic pattern alone cannot register.

## Executable protocol and verdict

`implement/oracle.py` exposes `evaluate(case, baseline, mutated) -> relation` returning `applicable`, `observable`, `holds`, `expected`, `actual` and explanation. The runtime does not accept a semantic pass unless baseline validity, effective mutation, target reachability and controls are established. A failed relation with all gates satisfied is `counterexample_candidate` only. Unsupported capabilities, out-of-scope properties, non-evaluable data and harness faults use distinct classes. Oracle evaluation must be deterministic for the same normalized observations and version.

## Controls

The target package supplies smoke cases for healthy, ineffective and controlled-fault outcomes. The healthy case must pass against the real adapter; the ineffective case must not become a candidate; the controlled fault must be detected by the predicate. Control evidence is preserved in the run. If a control fails, registration smoke fails and campaigns do not start.

## Acceptance

Unknown IDs, missing paired mutator, unlinked claim and controls that fail to distinguish a planted fault block execution. Draft specs are allowed with `unverified_spec` evidence.

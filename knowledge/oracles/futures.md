# Future oracle patterns

Catalog version: 1. Imported at the maintainer's request on 2026-10-08 from E:/PQCFuzz/oracles/future_patterns.md, SHA-256 DB7EB78AD883C8BCA64C28CB359567A61607A8A50BDC78637AD2871D5E38E74C. Each entry cites section 3, F1–F11, of that source. This reserve is human-maintained: agents do not edit or schedule these entries. Source priority is research priority, not finding severity.

Occurrence counts are not measured by the source document. Each entry starts as `not_measured` rather than a misleading zero; the maintainer can update it from deduplicated target/workspace observations using a declared counting period and unit.

### F1 — Buffer aliasing and memory layout

- Version: 1; priority: high; closest active patterns: P6, P9.
- Scope: Public buffer APIs with documented overlap, alignment and pointer/length contracts.
- Preconditions: Allowed and forbidden layouts are specified; equivalent disjoint and layout-variant calls can be built.
- Relation: Allowed layouts preserve normalized output; forbidden layouts fail safely before unsafe access.
- Limitations: Unsupported caller misuse is not automatically a library defect.
- Occurrence count: not_measured.
- Source: section 3, F1.

### F2 — Concurrency and reentrancy

- Version: 1; priority: medium; closest patterns: F11, P9.
- Scope: APIs that claim thread safety or reentrancy.
- Preconditions: A permitted serial ordering and controlled schedules/independent contexts are defined.
- Relation: Concurrent observations match an allowed serial execution without cross-thread state contamination.
- Limitations: No thread-safety claim means a race-shaped observation alone is not a contract violation.
- Occurrence count: not_measured.
- Source: section 3, F2.

### F3 — Resource exhaustion and complexity bounds

- Version: 1; priority: high; closest active pattern: P9.
- Scope: Inputs or sequences that can amplify CPU, memory, allocations or stack use.
- Preconditions: Comparable input classes and a specification- or baseline-derived cost bound are declared.
- Relation: Normalized cost and repeated-call growth stay within the declared bound.
- Limitations: Absolute timing is platform sensitive; use matched baselines and declared ratios.
- Occurrence count: not_measured.
- Source: section 3, F3.

### F4 — Initialization and environmental failure

- Version: 1; priority: medium; closest active patterns: P7, P8.
- Scope: Provider initialization, dispatch, loader, I/O and dependent system services.
- Preconditions: Dependency failure can be injected and documented recovery/fallback behavior is known.
- Relation: Failed dependencies produce documented failure or explicitly allowed fallback without valid-looking stale output.
- Limitations: Fallback behavior is profile and API specific.
- Occurrence count: not_measured.
- Source: section 3, F4.

### F5 — Secret erasure and sensitive-state lifetime

- Version: 1; priority: medium; closest patterns: F11, P9.
- Scope: Secret-bearing contexts with stated erasure or lifetime policy.
- Preconditions: Sensitive values and lifecycle boundaries are identified; instrumented storage is observable.
- Relation: Required secret storage is cleared or made inaccessible after success, failure, reset or destruction.
- Limitations: Memory inspection cannot prove absence of every compiler/runtime copy.
- Occurrence count: not_measured.
- Source: section 3, F5.

### F6 — ABI, FFI and wrapper equivalence

- Version: 1; priority: high; closest active patterns: P3, P6.
- Scope: Native APIs and wrappers/providers/language bindings with overlapping input domains.
- Preconditions: Equivalent inputs, outputs, status and wrapper policy can be normalized.
- Relation: Wrapper observations preserve native semantics for representable inputs.
- Limitations: Documented stricter wrapper policy is not a defect by itself.
- Occurrence count: not_measured.
- Source: section 3, F6.

### F7 — Cross-configuration and cross-platform differential

- Version: 1; priority: high; closest active pattern: P3.
- Scope: Compiler, optimization, architecture, endianness, CPU dispatch and feature-flag variants.
- Preconditions: Builds use compatible profiles and a common structured corpus.
- Relation: Deterministic observations agree and randomized variants satisfy the same semantic relation.
- Limitations: Legitimate profile differences require normalization; divergence does not identify the wrong build.
- Occurrence count: not_measured.
- Source: section 3, F7.

### F8 — Persistent state and crash consistency

- Version: 1; priority: target dependent; closest future pattern: F11.
- Scope: Stateful or persistence-dependent signing/key operations.
- Preconditions: State transition and storage-failure points are observable; restart/recovery contract is defined.
- Relation: Committed state does not roll back and forbidden index, nonce or key state is not reused.
- Limitations: In-memory sequence tests alone do not establish crash consistency.
- Occurrence count: not_measured.
- Source: section 3, F8.

### F9 — Probabilistic reliability and rare failure

- Version: 1; priority: high for probabilistic schemes; closest active patterns: P2, P9.
- Scope: Schemes with permitted nonzero correctness-failure probability.
- Preconditions: Bound or compatible reference, independent trials and predeclared statistical test are available.
- Relation: Honest-operation failure rate is compatible with the declared bound.
- Limitations: Finite trials never prove negligible failure probability.
- Occurrence count: not_measured.
- Source: section 3, F9.

### F10 — Internal fault containment and invariants

- Version: 1; priority: target dependent; closest active patterns: P7, P9.
- Scope: Instrumentable intermediate state with a declared software-fault model.
- Preconditions: Fault point, independent invariant and expected fail-closed behavior are specified.
- Relation: Faulted execution either preserves correct output or fails without valid-looking incorrect output.
- Limitations: Software injection is not physical-fault evaluation.
- Occurrence count: not_measured.
- Source: section 3, F10.

### F11 — Stateful sequence and lifecycle

- Version: 1; priority: target dependent; related extensions: F2, F8.
- Scope: Incremental, stateful or persistent APIs, including stateful signatures.
- Preconditions: Legal and illegal call transitions, counters and reset/retry behavior are specified.
- Relation: Call sequences follow the state machine without forbidden reuse, rollback or output after invalid transitions.
- Limitations: Concurrency and crash recovery need the additional F2/F8 models; current one-shot adapters do not establish coverage.
- Occurrence count: not_measured.
- Source: section 3, F11.


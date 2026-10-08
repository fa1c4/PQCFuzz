# Configuration design

Parent: [architecture.md](architecture.md). Implements DES-02, DES-06, DES-07, DES-09, DES-10.

## Registry

`configs/targets.json` has `schema_version: 1` and a `targets` array. One entry names a target, algorithm, primitive, immutable source path/digest, spec extract path, and API variants. Every API has parameter set and build profiles. Each profile has a stable ID, build argv, declared dependencies, wall timeout, CPU/memory/disk budgets, iteration limit, concurrency limit, seed policy and retention/data policy. Source, spec and package paths resolve inside the repository and never escape through `..` or symlinks. Duplicate target/algorithm/API/profile tuples fail closed.

## Selection and limits

An executable selection names target, algorithm, API, profile and oracle ID. Omitted selectors are allowed only if exactly one choice remains. No default is chosen between ambiguous variants. Budget overrides may tighten limits only. A `null` CPU or memory limit explicitly declares that hard enforcement is unavailable for that run and must be reported; a finite limit must be enforced or preflight blocks. Timeouts, disk quota and run isolation are mandatory. Seed is recorded, never inferred from global RNG. Dependencies are checked by executable name before build.

## Data policy

Profiles declare `sensitive_inputs`, `retention_days` and access policy. Raw sensitive material must not appear in ordinary logs or report summaries. If the runtime cannot meet the declared access policy, execution blocks. Runs keep a manifest of policy and expiry; deletion is a separate audited operation and never alters a retained run.

## Acceptance

Malformed/unknown keys, ID collision, digest drift, missing dependency, non-enforceable finite budget and ambiguous selection produce diagnostics, never an apparent pass.
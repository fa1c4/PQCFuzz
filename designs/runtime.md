# Runtime design

Parent: [architecture.md](architecture.md). Implements DES-02 through DES-07, DES-09 and DES-10.

Runtime alone performs dynamic discovery, validation, build, smoke, campaign execution, evidence capture and candidate reporting. Static declarations come from the six other modules.

## Registration and stages

Read `configs/targets.json` and `oracles/<target>/manifest.json`; validate versions, IDs, paths, hashes, spec front matter, active knowledge versions, full `(algorithm, parameter set, API, profile)` identity and capabilities. Schema-v2 target packages enumerate instances; `--parameter-set` is required when the remaining selection is ambiguous. Schema-v1 demo packages and already retained run artifacts keep their previous interpretation. Selection is explicit or uniquely determined. Stage order is `preflight → build → smoke → run → candidate report`. A changed source/spec/config/package digest invalidates smoke eligibility. A run is never overwritten. Stage outcomes are `ready`, `blocked`, `needs_input` or `failed` with a diagnostic; evaluation classes are `pass`, `counterexample_candidate`, `inconclusive`, `not_applicable`, `unsupported` and `harness_error`.

## Isolation and invocation

Each run owns `workspace/<target>/runs/<run-id>/` with source/build copy, temporary directory, cache, input, trace, logs and report. Worker processes run there with run-local temp/cache variables, declared dependency versions and bounded wall time. Finite CPU/memory limits must be enforceable on the host or block. Disk overrun blocks/fails the run and is reported. Third-party source is read-only input; the runtime copies both source and registered package into the run and invokes that package copy. It snapshots the spec extract, config and active catalogs; build writes to the run copy. Process errors, timeout and sanitizer output are distinct from semantic relation failure.

## Smoke gate

Smoke executes a real healthy baseline and effective mutation, negative ineffective control and planted fault control through the same oracle predicate. It records reachability and all relations. A failed gate blocks campaign. Draft spec registration is legal and marked `unverified_spec`. Missing capability yields `unsupported`, out-of-scope property `not_applicable`, neither pass.

## Campaign and scripts

The new target entry is `scripts/pqcfuzz_target.py`. `scripts/pqcfuzz_eval_<target>.sh` is a thin wrapper. `scripts/pqcfuzz_all_eval.sh targets ...` derives registered targets from config/manifest rather than a hard-coded target list; the old suite syntax stays under its compatibility path. Parameters select target/algorithm/parameter-set/API/profile/oracle, iteration budget and seed. Unknown and ambiguous IDs are errors. Runtime calls the paired structured mutator, adapter and oracle per iteration.

## Evidence and reporting

Every run writes immutable `manifest.json`, per-case structured input files, `trace.json`, `report.json` and hashes. The manifest snapshots identity, source/spec/config/package digests, draft/verified status, evidence class, versions, environment, budget, seed, times, verdict counts and `replay_status: not_run`. Traces include baseline/mutated input, intervention/effectiveness, target reachability, controls, normalized observations, expected/actual relation and process diagnostics. Candidates are linked individually and never called confirmed. Reports separate all six result classes. Restrict sensitive evidence according to config; never put raw secrets in ordinary reports. Retention expiry is declared, not silently executed.

## Compatibility and acceptance

Legacy family scripts and historical replay/report artifacts stay interpretable; the new runtime does not silently import them. A vertical demo shows draft and verified specs, healthy/fault control, ineffective mutation, missing capability, unknown ID, isolated paths, complete hashes and candidate-only report. Native old tests remain separate compatibility gates.

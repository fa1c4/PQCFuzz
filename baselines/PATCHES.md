# Baseline patches

## libFuzzer

- Changed: `baselines/libFuzzer/{fuzz_common.h,fuzz_kem.c,fuzz_sig.c}`.
- Reason: replace abort-on-API-error handling with normalized outcomes and
  diagnostics, add a versioned KEM/SIG property envelope, and persist
  deduplicated replayable semantic findings without stopping libFuzzer.
- Behavior preserved: the `memory-safety` profile remains a conventional
  sanitizer-guided valid-lifecycle baseline; semantic findings do not become
  sanitizer crashes.
- Changed: `scripts/baselines/libFuzzer/run.sh`,
  `scripts/eval_baselines_fuzzing.sh`, and
  `scripts/compact_baseline_results.py`.
- Reason: require an explicit `memory-safety` or `semantic` profile, keep KEM
  and SIG summaries isolated, record per-target result accounting, and compact
  artifact counts relative to the correct target.
- Behavior preserved: sanitizer artifacts continue to use libFuzzer's normal
  crash-artifact mechanism.

## cryptofuzz

- Changed: `baselines/cryptofuzz/Makefile`
- Reason: redirect top-level object files, generated repository headers, helper binaries, the main fuzzer binary, and the local cpu_features CMake build to `workspace/cryptofuzz/targets-build`.
- Behavior preserved: upstream fuzzing logic unchanged.
- Changed: `baselines/cryptofuzz/{gen_repository.py,entry.cpp,driver.cpp,executor.cpp,executor.h,operation.cpp,include/cryptofuzz/module.h,include/cryptofuzz/operations.h}` and added `baselines/cryptofuzz/modules/liboqs/`.
- Reason: add first-class liboqs KEM/SIG self-check operations and a version-specific liboqs module for reproducing PQ baseline campaigns.
- Behavior preserved: existing non-liboqs cryptofuzz operations remain opt-in through the original operation/module controls.
- Shared-oracle policy: `baselines/cryptofuzz/modules/liboqs/{module.cpp,module.h,Makefile}` and
  `baselines/CLFuzz/modules/liboqs/{module.cpp,module.h,Makefile}` are intentionally independent
  physical copies, but must remain byte-for-byte identical.  They implement the shared liboqs
  oracle only; `executor.cpp`, mutator behavior, and runner scripts remain fuzzer-specific and may
  diverge.  `tests/baseline_compaction_test.py` enforces this synchronization contract.
- Changed: `scripts/baselines/cryptofuzz/run.sh`,
  `scripts/compact_baseline_results.py`, and `scripts/eval_baselines_fuzzing.sh`.
- Reason: isolate every campaign's libFuzzer working logs, record replayable semantic findings and
  operation diagnostics separately from crashes/hangs, retain their structured evidence during
  compaction, and report target-root-local retained counts and replay validation.
- Behavior preserved: a reproduced semantic finding completes the campaign with findings; it is not
  reclassified as a sanitizer crash.  A missing or non-reproduced replay prevents compaction from
  deleting the campaign evidence and is recorded as a failed compaction manifest.
- Changed: `baselines/cryptofuzz/Dockerfile` and `scripts/run_baseline.sh`
- Reason: keep `ubuntu:22.04` as the default Docker base image while allowing `--base-image` or `PQCDF_DOCKER_BASE_IMAGE` overrides when Docker Hub or a registry mirror returns inconsistent base-image metadata.
- Behavior preserved: default Docker build command still builds the same baseline image.

## CLFuzz

- Upstream provenance: the vendored CLFuzz tree has no retained upstream `.git`
  metadata, so an upstream SHA cannot be recovered honestly from this checkout.
  Its reproducible in-repository source revision is
  `d2cba61e1013df2e373d01a43739801494fffa5f` (`CLFuzz Reproduce`), based on
  vendor import `763e08d7eb3ec2ff324d77c0683fef3545b69430`.  Any future
  upstream refresh must replace this explicit unavailable-upstream record with
  the upstream URL and immutable SHA.
- Changed: `baselines/CLFuzz/Makefile`
- Reason: redirect top-level object files, generated repository headers, the main fuzzer binary, and the local cpu_features CMake build to `workspace/CLFuzz/targets-build`.
- Behavior preserved: upstream fuzzing logic unchanged.
- Changed: `baselines/CLFuzz/{driver.cpp,liboqs_replay_input.h}` and
  `baselines/CLFuzz/modules/liboqs/{module.cpp,module.h,Makefile}`.
- Reason: add the local liboqs KEM/SIG oracle versioned as
  `pqcdf-clfuzz-liboqs-oracle-v2`.  It records structured outcomes rather than
  converting API returns into fuzzer crashes; compares effective mutations;
  emits atomic, deduplicated, bounded replay inputs; and covers the KEM
  round-trip/ciphertext/secret-key/public-key/keygen-RNG/encaps-RNG and SIG
  round-trip/signature/message/public-key/secret-key/keygen-RNG/sign-RNG
  properties.
- Shared-oracle policy: these module files remain byte-for-byte identical to
  `baselines/cryptofuzz/modules/liboqs/`.  They use neutral
  `PQCDF_LIBOQS_*` sidecar variables (with legacy cryptofuzz aliases) so a
  runner supplies its baseline identity without changing oracle logic.  The
  common sidecar schema records `baseline`, module version, algorithm,
  primitive, property, setup/baseline/mutated statuses, normalized relation,
  diagnostics, skips and passed-property coverage, mutation
  effectiveness/offset/length/operation/delta and before/after digests.  The
  CLFuzz driver keeps the original libFuzzer bytes in thread-local scope while
  dispatching a liboqs operation.  A semantic candidate is retained only if
  the module atomically captures that exact input under
  `findings/replay-inputs/<sha256>.bin`; a missing or mismatched fixture is a
  non-counted diagnostic.
- Public-key normalization: accepted signature public-key mutations are
  replayed with three fresh liboqs objects, prove raw-byte changes, and use an
  independent same-byte probe to distinguish `ignored_public_key_bytes` from
  `verification_key_malleability`.  Generic liboqs has no public-key
  parse/serialize interface, so canonicalization is explicitly recorded as
  `unsupported` rather than inferred.  Failed replay is retained as an
  `unreproduced` diagnostic and is excluded from semantic finding totals.
- Changed: `baselines/CLFuzz/executor.cpp`.
- Reason: a false legacy self-test result is now non-terminal because the
  local liboqs module has already recorded its classified outcome.  ASan,
  UBSan, signals, and unexpected exceptions still terminate normally through
  the fuzzer runtime.
- Changed: `scripts/baselines/CLFuzz/run.sh`,
  `scripts/eval_baselines_fuzzing.sh`, and
  `scripts/compact_baseline_results.py`.
- Reason: create isolated `liboqs-<version>/<profile>` campaign roots for
  corpus, logs, findings, diagnostics, coverage outcomes, metadata, crashes,
  and artifacts (with a per-profile lock); report semantic findings separately
  from sanitizer artifacts; mark a healthy run with evidence as
  `completed-with-findings`; record CPU/worker/property coverage and stop
  reason; and validate/replay-retain structured CLFuzz evidence during
  compaction.  Compaction requires a matching raw fixture SHA-256 and three
  unanimous exact-input replay results before it counts a CLFuzz semantic
  finding.  A crash artifact or sanitizer report remains terminal even if an
  intermediate wrapper exits zero.
- Changed: `baselines/patches/liboqs-0.14.0-empty-context.patch` and
  `scripts/baselines/CLFuzz/build.sh`.
- Reason: liboqs 0.14.0 ML-DSA AVX2 calls `memcpy` with a null context pointer
  and zero length through the generic signing API, which UBSan reports despite
  a successful operation. The version-scoped patch skips those zero-length
  copies. liboqs 0.4.0's normal CLFuzz campaign uses ASan only because its
  archived Saber/SIKE/Picnic/qTesla implementations emit known recoverable
  UBSan findings; set `PQCDF_CLFUZZ_STRICT_UBSAN=1` to run the strict UBSan
  discovery lane. The selected sanitizer profile is persisted in the run
  summary.
- Behavior preserved: ASan artifacts, signals, and unfiltered sanitizer
  reports still fail the campaign. A recoverable log-only report is labelled
  `sanitizer-report`, rather than inaccurately as a target crash.
- Replay procedure: `CLFuzz run --mode replay` requires a raw input plus a
  pinned algorithm and property.  It stages the input under the campaign
  findings directory and can use `legacy-or-one-v1` mutation semantics to
  reproduce the historical 0.14.0 `OV-Is-pkc-skc` public-key exemplar without
  changing normal CLFuzz mutation behavior.  Replay is deliberately one job
  and one worker; use `--profile NAME` to keep distinct investigations apart.
  The archived raw exemplar and its SHA-256/mutation manifest are tracked as
  `tests/seeds/clfuzz_ov_is_pkc_skc_0.14.0.{input.b64,replay.json}`; its
  regression verifies exact staging and the pinned legacy replay contract.

## cryptoTesting

- Changed: `baselines/cryptoTesting/Makefile`
- Reason: make liboqs checkout/configure/build recipes fail-fast so a failed `git checkout` cannot continue into CMake/Ninja on the wrong revision.
- Behavior preserved: upstream fuzzing logic unchanged.
- Changed: `scripts/baselines/cryptoTesting/run.sh`, `reproduce.sh`, both
  liboqs drivers, their report scripts, and
  `scripts/compact_baseline_results.py`.
- Reason: mount a durable raw AFL root before fuzzing starts; route each
  algorithm/property's live `fuzzinputs` and `fuzzoutputs` there; emit an
  checksummed raw manifest plus per-task schedule/state records; and compact
  from that mounted root instead of from the disposable liboqs checkout.
  Functional cryptoTesting and its vanilla AFL workflow are explicit,
  separately named modes (`cryptoTesting-functional` and
  `cryptoTesting-vanilla`).
- Behavior preserved: the functional driver still invokes `fuzz_liboqs.py`
  and `report.py`; vanilla invokes `fuzz_liboqs_baseline.py` and
  `report_baseline.py`.  The local wrapper only changes output ownership,
  accounting, and invocation selection.
- Changed: functional liboqs property Makefiles.
- Reason: a `GenInput` deadline now creates a structured
  `setup-timeout/GenInput.json` diagnostic with the command, timeout,
  algorithm index, elapsed allocation, and exit code.  It is not written as
  an AFL target hang.
- Behavior preserved: the original independent `GenInput` deadline remains
  configurable as `--geninput-timeout` / `CRYPTO_TESTING_GENINPUT_TIMEOUT`.
  A target hang enters validated comparison accounting only after its raw
  reproducer's replay status is `reproduced`.
- Replay procedure: every raw manifest item includes a one-artifact
  `crypto_testing_replay.py` command.  It rebuilds the matching cloned target
  and records a normalized `target-hang`, `crash`, `operation-error`, or
  `unreproduced` result (or a property-specific `accepted-mutation` /
  `mismatch` clean-exit classification) beneath
  `raw/.../metadata/replays/`.  Re-run the manifest helper (or the compactor)
  after recording replay evidence; only a replayed `target-hang` contributes
  to the validated hang count.
- Changed: `scripts/eval_baselines_fuzzing.sh`.
- Reason: cryptoTesting evaluation fixes its worker budget at one unless the
  experiment is deliberately configured otherwise, runs the configured time
  limit inside the durable workflow, and requires a summary for every baseline
  rather than exempting cryptoTesting. A controlled budget stop is recorded as
  `completed-at-budget`; a pre-run failure skips compaction instead of creating
  a second missing-raw-output failure. The final evaluation summary labels the
  functional mode explicitly and includes per-version shared
  algorithm/property coverage intersections alongside each campaign's full
  scheduled matrix.

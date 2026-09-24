# PQCFuzz

PQCFuzz is a framework for post-quantum crypto differential fuzzing. The active
FIPS 203/204/205 implementation lives under:

```text
/src
```

The current active scope is ML-KEM, ML-DSA, and SLH-DSA external-API
differential fuzzing for:

- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024
- ML-DSA-44
- ML-DSA-65
- ML-DSA-87
- SLH-DSA-SHA2-128s
- SLH-DSA-SHAKE-128s
- SLH-DSA-SHA2-128f
- SLH-DSA-SHAKE-128f
- SLH-DSA-SHA2-192s
- SLH-DSA-SHAKE-192s
- SLH-DSA-SHA2-192f
- SLH-DSA-SHAKE-192f
- SLH-DSA-SHA2-256s
- SLH-DSA-SHAKE-256s
- SLH-DSA-SHA2-256f
- SLH-DSA-SHAKE-256f

A second active scope adds the Aigis (PQMagic) and CROSS families; see the
Aigis and CROSS workflow sections below. CROSS test claims cite the CROSS
round-2 submission specification, not FIPS 203/204/205.

The active path uses externally supplied implementation-pair metadata. It does
not infer whether projects share provenance or are independently maintained.

## Quickstart

Validate the default explicit pair file:

```bash
python3 src/pairing/validate_pair_alg.py \
  --pair-alg src/config/pair_alg.default.json
```

Generate ML-KEM jobs:

```bash
python3 src/jobs/generate_jobs.py \
  --pair-alg src/config/pair_alg.default.json \
  --algorithm-family ML-KEM
```

Generate ML-DSA jobs:

```bash
python3 src/jobs/generate_jobs.py \
  --pair-alg src/config/pair_alg.default.json \
  --algorithm-family ML-DSA
```

Generate SLH-DSA jobs:

```bash
python3 src/jobs/generate_jobs.py \
  --pair-alg src/config/pair_alg.default.json \
  --algorithm-family SLH-DSA
```

Replay one structured seed:

```bash
python3 src/replay/replay_one.py \
  --job workspace/jobs/job_mlkem768_liboqs_vs_pqclean.json \
  --input tests/seeds/mlkem_roundtrip_seed.bin
```

## Evaluation Runs

One tmux campaign per supported liboqs version (`0.14.0`, `0.8.0`, `0.4.0`):

```bash
# default metamorphic (mutation/relational) fuzzing
scripts/pqcfuzz_eval.sh --versions 0.14.0,0.8.0,0.4.0 --fuzzing-time 24h

# FIPS case-ID oracle suite (canonicality, exact length, z-norm, implicit rejection, RNG failure)
scripts/pqcfuzz_eval.sh --versions 0.14.0,0.8.0,0.4.0 --fuzzing-time 24h --oracle-suite fips

# both suites concurrently: two campaigns per version, same 24h budget each
scripts/pqcfuzz_eval.sh --versions 0.14.0,0.8.0,0.4.0 --fuzzing-time 24h --full-test
```

`--full-test` takes precedence over `--oracle-suite`. Full-test session names
are `<prefix>-liboqs-<version>-metamorphic` and `<prefix>-liboqs-<version>-fips`;
results land under `workspace/pqcfuzz_eval/campaigns/liboqs-<version>-<suite>/`
with the merged `workspace/pqcfuzz_eval/summary.json`. Pressing Ctrl+C in the
orchestrator stops every tmux campaign session that invocation started (also
on SIGTERM/SIGHUP) before exiting. Campaigns whose only findings are
`HARDENING_GAP`s (for example the void-RNG `*_rng_failure` diagnostics) report
`completed`/`preflight-completed`; those findings remain in the artifacts.
Restarting with an output root that still has live indexed sessions is refused
(stop them with the printed `tmux kill-session` command first).

## Layout

```text
/src
/baselines
/eval
/projects
/workspace
```

The active implementation is flattened directly under `src/`; the older
mapper/pairing/fuzzer scaffold has been removed.

## Baseline Fuzzers

PQCFuzz vendors several external baseline fuzzers under `baselines/`.

They are tracked as ordinary source directories, not as Git submodules. The
nested upstream `.git` directories are removed.

Use the dispatcher to build and run them:

```bash
scripts/run_baseline.sh cryptofuzz build
scripts/run_baseline.sh cryptofuzz run

scripts/run_baseline.sh CLFuzz build
scripts/run_baseline.sh CLFuzz run
scripts/run_baseline.sh CLFuzz build --version 0.14.0
scripts/run_baseline.sh CLFuzz run --version 0.14.0 --mode smoke --profile smoke

scripts/run_baseline.sh libFuzzer docker-build
scripts/run_baseline.sh libFuzzer build --version 0.14.0
scripts/run_baseline.sh libFuzzer run --version 0.14.0 --target all --profile semantic --mode smoke

scripts/run_baseline.sh cryptoTesting build
scripts/run_baseline.sh cryptoTesting run
```

Build and run artifacts are isolated under:

```text
workspace/<baseline>/targets-build/
workspace/<baseline>/targets-run/
```

CLFuzz run outputs are further separated by `liboqs-<version>/<profile>/`; the
profile defaults to the selected mode.

## Aigis (PQMagic) Workflow

PQCFuzz also fuzzes the PQMagic `Aigis-Enc` (modes 1-4) and `Aigis-Sig`
(modes 1-3) implementations in `third_party/PQMagic`, following the oracle
design in `plans/deepseek_pqc_test_oracle_design.md`.
Differential pairs are same-source SM3-vs-SHAKE hash profiles (object formats
are hash-independent, so the SHAKE archive is symbol-renamed by
`scripts/rename_pqmagic_symbols.py` before both variants are linked into one
binary; cross-exchange oracles are intentionally not scheduled because the
shared secret and signature challenge bind the hash function).

```bash
# Build PQMagic (SM3 + SHAKE) and all fips/metamorphic fuzzers + replays:
ORACLE_SUITE=fips scripts/pqcfuzz_aigis_eval.sh build   # then preflight | run | all
ORACLE_SUITE=metamorphic ORACLE_SET=all TARGET_RUNTIME=pqmagic \
  scripts/pqcfuzz_aigis_eval.sh all

# Validate the explicit pair file and generate jobs:
python3 src/pairing/validate_pair_alg.py --pair-alg src/config/pair_alg.aigis.json
python3 src/jobs/generate_jobs.py --pair-alg src/config/pair_alg.aigis.json \
  --algorithm-family AIGIS-SIG
```

Aigis-Sig fips oracles implement the doc's blocking tests: exact signature
length (`aigissig_exact_length`), unused challenge sign bits
(`aigissig_unused_sign_bits`), ctx_len=256 failure-state consistency
(`aigissig_ctx256_failure_state`), determinism (`aigissig_determinism_profile`);
Aigis-Enc adds implicit-rejection and non-canonical secret-key coefficient
oracles. Findings are labeled as implementation observations / hardening gaps,
never as FIPS nonconformance.

## CROSS Workflow

PQCFuzz fuzzes the pinned CROSS reference implementation vendored from the
NIST additional-signatures round-2 submission (`projects/CROSS/reference`,
archive SHA-256 recorded in `src/config/source_locks/cross.json`). The 18
parameter sets (`CROSS-RSDP|RSDPG-{1,3,5}-{FAST,BALANCED,SMALL}`) get their own
layout, structured mutation recipe, executor, and oracle spec
(`src/oracles/specs/cross.json`), with capability-gated subtests and replay.

```bash
# Validate the explicit pair file and materialize CROSS jobs:
python3 src/pairing/validate_pair_alg.py --pair-alg src/config/pair_alg.cross.json
python3 src/jobs/generate_jobs.py --pair-alg src/config/pair_alg.cross.json \
  --algorithm-family CROSS --oracle-suite fips --jobs-dir workspace/cross/jobs

# Build the sanitizer fuzzers/replays, preflight every oracle, run a smoke
# campaign, and write workspace/cross/report/summary.{json,md}:
scripts/pqcfuzz_cross_eval.sh build
scripts/pqcfuzz_cross_eval.sh preflight
scripts/pqcfuzz_cross_eval.sh smoke
scripts/pqcfuzz_cross_eval.sh report

# Longer campaign (per-job seconds):
MAX_TOTAL_TIME=3600 scripts/pqcfuzz_cross_eval.sh run
```

The independent Python model lane (`tests/models/cross_model.py`,
`tests/cross_model_test.py`) covers bit packing, Fp/Fz membership, the
fixed-weight challenge sampler, seed-tree/Merkle rebuild semantics, and the
mutant catalogue, and differentially checks the codec and sampler against the
pinned reference build. `tests/cross_oracles_test.py` covers routing, envelope
IDs, structured recipes with 32-bit offsets (reaching byte 74589 of
`CROSS-RSDP-5-FAST`), honest oracles on the real adapter, and findings from a
deliberately broken adapter.

Limitations: the submission archive has no official KAT response files (fixtures
are reference-derived); only the single pinned reference build is vendored, so
`cross_cross_verify` is disabled rather than faked; and the P2 timing/fault lanes
are opt-in. Reports never claim IND-CCA/EUF/sUF or quantum security.

## Notes

- `projects/` is reserved for upstream source trees only.
- `workspace/` is reserved for runtime outputs only.
- Checked-in active PQCFuzz code lives under `src/`.
- Generated jobs, configs, traces, findings, and PoCs never live in
  source-of-truth directories.

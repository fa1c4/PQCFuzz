# PQCFuzz

## Registered target package path

New targets use the seven-module design tree and the Agent SOP. The checked-in `demo-stream-hash` package is a **local infrastructure fixture**, not a PQC claim. It demonstrates extraction provenance, active H07/P4 mapping, structured mutation, adapter reachability, smoke controls and candidate-only evidence.

```bash
python scripts/pqcfuzz_target.py list
python scripts/pqcfuzz_target.py preflight --target demo-stream-hash --algorithm DEMO-HASH --api stream --profile healthy
python scripts/pqcfuzz_target.py run --target demo-stream-hash --algorithm DEMO-HASH --api stream --profile injected
bash scripts/pqcfuzz_all_eval.sh targets run --target demo-stream-hash --profile healthy
bash scripts/pqcfuzz_all_eval.sh targets run
python scripts/pqcfuzz_target.py verify --run "workspace/demo-stream-hash/runs/<run-id>"
```

The last command discovers every configured API/profile. New runs write to `workspace/<target>/runs/<run-id>/`, including a source/package/spec/config snapshot, trace, report and file hashes. A new target is authored in `oracles/<target>/` and registered in `configs/targets.json`; the legacy fixed suite commands of `pqcfuzz_all_eval.sh` still work.


## NGCC 候选材料下载

`projects/download_ngcc_targets.sh` 使用固定的 [119 项清单](projects/ngcc_targets.json)，默认下载全部候选的官方提交 ZIP、完整解压树及提交规范 PDF 到 `third_party/<candidate-id>/`。这些是第一轮候选提案材料，不是已颁布的国标。每个目录的 `download.json` 记录官方 ZIP 哈希、PDF 来源与哈希、源码树哈希及可能存在的嵌套归档。

```bash
bash projects/download_ngcc_targets.sh --dry-run
bash projects/download_ngcc_targets.sh --target kem-29
bash projects/download_ngcc_targets.sh --verify-only --target kem-29
bash projects/download_ngcc_targets.sh --jobs 2
```

脚本需要 Python 3.10+、访问 NICCS 与 GitHub raw 的 HTTPS 网络；`sign-09` 的内嵌 RAR 源码还需要 `bsdtar`。本次已下载并复验 119/119 项：原始 ZIP 合计 5,994,444,545 字节，解压源码合计 10,773,117,921 字节。`sign-09` 的两份 RAR 源码展开在 `source/_nested/`；`sign-29` 的固定镜像 PDF 与官方 ZIP 不一致，故选用官方 ZIP 内的算法规范 PDF，收据保留差异信息。文件不会自动覆盖；若现有目录的收据或哈希不匹配，脚本会失败并列出候选 ID。


## Design authority

The human-facing design tree starts at [designs/architecture.md](designs/architecture.md)
and is refined by [module designs](designs/). [designs/actuality.md](designs/actuality.md)
records observed implementation behavior only. Codex reads the repository guidance
in [AGENTS.md](AGENTS.md); target onboarding follows
[agent/pqc_sop.md](agent/pqc_sop.md). Implementation plans live in
[plans/](plans/) and changes are recorded in [history/](history/).

PQCFuzz is a framework for post-quantum crypto differential fuzzing. The active
FIPS 203/204/205 implementation lives under:

```text
/src
```

The current active scope is ML-KEM, ML-DSA, and SLH-DSA external-API testing
for:

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

ML-KEM and ML-DSA run in the liboqs differential lane
(`scripts/pqcfuzz_eval.sh`) and in the KAT lane
(`scripts/pqcfuzz_kat_eval.sh`). The 12 SLH-DSA parameter sets run in the KAT
lane (`fips205_kat_keygen`); their liboqs differential targets are deliberately
not built because the pinned liboqs releases ship round-3 SPHINCS+ simple, not
FIPS 205 SLH-DSA. `generate_jobs.py` therefore materializes zero SLH-DSA
differential jobs and the liboqs summary records SLH-DSA under
`skipped_families` with `skipped_family_reasons`.

A second active scope adds the Aigis (PQMagic), CROSS, NTRU, Falcon, SIKE/SIDH
and SNOVA families; see their workflow sections below. CROSS and SNOVA test
claims cite the corresponding round-2 submission specifications, not FIPS
203/204/205.

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

SLH-DSA differential jobs are intentionally not materialized (the pinned
liboqs releases ship round-3 SPHINCS+ simple, not FIPS 205 SLH-DSA). Run the
SLH-DSA KAT lane instead:

```bash
scripts/pqcfuzz_kat_eval.sh build
scripts/pqcfuzz_kat_eval.sh run ML-KEM-512 ML-KEM-768 ML-KEM-1024 \
  SLH-DSA-SHA2-128s SLH-DSA-SHAKE-128s
```

Replay one structured seed:

```bash
python3 src/replay/replay_one.py \
  --job workspace/jobs/job_mlkem768_liboqs_vs_pqclean.json \
  --input tests/seeds/mlkem_roundtrip_seed.bin
```

## All-Lane Evaluation

`scripts/pqcfuzz_all_eval.sh` drives every algorithm lane behind one command
interface: the liboqs ML-KEM/ML-DSA/SLH-DSA campaigns, the PQMagic Aigis
campaign, and the CROSS, Falcon, NTRU, SIKE/SIDH and SNOVA family lanes.

```bash
# Everything: liboqs + Aigis + CROSS/Falcon/NTRU/SIKE/SIDH/SNOVA.
MAX_TOTAL_TIME=3600 scripts/pqcfuzz_all_eval.sh all

# Select lanes (liboqs, aigis, cross, falcon, ntru, sike_sidh, snova):
SUITES=cross,falcon,ntru,sike_sidh,snova scripts/pqcfuzz_all_eval.sh all
SUITES=liboqs VERSIONS=0.14.0,0.8.0,0.4.0 scripts/pqcfuzz_all_eval.sh preflight
SUITES=aigis ORACLE_SUITE=fips scripts/pqcfuzz_all_eval.sh all

# One lane at a time, or one job:
SUITES=ntru scripts/pqcfuzz_all_eval.sh smoke
SUITES=cross JOB_FILTER=cross_rsdp_5_fast scripts/pqcfuzz_all_eval.sh run
```

Commands are `build | preflight | smoke | run | report | all`; `run` uses
`MAX_TOTAL_TIME` seconds per job and `smoke` uses `SMOKE_FUZZ_SECONDS`. All
selected lanes run **concurrently** by default (liboqs already starts one tmux
campaign per version); each lane has its own workspace root and per-lane log at
`workspace/all/logs/<step>-<lane>.log`. For the liboqs lane, `build` runs
`pqcfuzz_eval.sh --preflight-only` (build + seeded corpus), and the following
`preflight` step reuses that completed result unless
`LIBOQS_REUSE_PREFLIGHT=0`. Cap concurrent lanes with `ALL_JOBS=N`,
or serialize with `ALL_PARALLEL=0`. Set `PQCFUZZ_INCLUDE_P2=1` to schedule the
opt-in P2 oracles. `report` runs each lane's report and writes the aggregate
`workspace/all/report/summary.json` (Aigis also writes
`workspace/all/report/aigis_summary.md`). A step with failures stops the driver
before the next step unless `ALL_CONTINUE_ON_ERROR=1` is set.

## KAT Lane

`scripts/pqcfuzz_kat_eval.sh` builds one `kat_oracle` runner against the pinned
PQClean reference adapters and validates official NIST ACVP/FIPS KAT responses,
writing coverage and findings through the standard pipeline under
`workspace/results/kat/`.

```bash
scripts/pqcfuzz_kat_eval.sh build
scripts/pqcfuzz_kat_eval.sh run ML-KEM-512 ML-KEM-768 ML-KEM-1024
scripts/pqcfuzz_kat_eval.sh run SLH-DSA-SHA2-128s SLH-DSA-SHAKE-128s   # fips205_kat_keygen
scripts/pqcfuzz_kat_eval.sh all
```

It covers the ML-KEM (`fips203_kat_*`) and SLH-DSA (`fips205_kat_keygen`)
families; ML-DSA lives in the liboqs differential lane.

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

The optimized (AVX2) build from the same pinned round-2 submission is vendored
at `projects/CROSS/avx2` (source-lock hashes recorded). Each of the 18
parameter sets has a `*_cross_reference_vs_avx2` pair: the optimized overlay
(`CROSS.c`, `merkle.c`, `seedtree.c`, 4-way Keccak) is compiled with `-mavx2`
and the 13 entry points shared with the reference build are renamed `opt_*`
with `objcopy --redefine-syms`, so both implementations link into one binary
and `cross_cross_verify` exercises two builds. Provenance is labelled
`same-source-reference-vs-avx2`.

Limitations: the submission archive has no official KAT response files (fixtures
are reference-derived); the P2 timing/fault lanes are opt-in. Reports never
claim IND-CCA/EUF/sUF or quantum security.

## SNOVA Workflow

PQCFuzz fuzzes the pinned SNOVA round-2 reference implementation vendored at
`projects/SNOVA/reference` (commit `13182903…`, archive SHA-256 in
`src/config/source_locks/snova.json`; the upstream HEAD is round 3 and is
deliberately not followed). The 11 parameter sets × {AES, SHAKE} public-key
expansion backends get AlgorithmIds 96-117, oracle IDs 140-159, a dedicated
layout/mutator/executor and an independent Python model. SSK (48-byte seed) and
ESK (expanded) private-key storage formats are both registered from one adapter
object, so an SSK-vs-ESK pair exercises the storage-format equivalence oracles
without exchanging private-key buffers.

```bash
# Validate the explicit pair file and materialize SNOVA jobs:
python3 src/pairing/validate_pair_alg.py --pair-alg src/config/pair_alg.snova.json
python3 src/jobs/generate_jobs.py --pair-alg src/config/pair_alg.snova.json \
  --algorithm-family SNOVA --oracle-suite fips --jobs-dir workspace/snova/jobs

# Build the sanitizer fuzzers/replays, preflight every oracle, run a smoke
# campaign, and write workspace/snova/report/summary.{json,md}:
scripts/pqcfuzz_snova_eval.sh build
scripts/pqcfuzz_snova_eval.sh preflight
scripts/pqcfuzz_snova_eval.sh smoke
scripts/pqcfuzz_snova_eval.sh report

# Longer campaign (per-job seconds):
MAX_TOTAL_TIME=3600 scripts/pqcfuzz_snova_eval.sh run
```

The pinned source regenerates the official `PQCLAB-SNOVA/SNOVA_KAT` round-2
count=0 responses byte-for-byte; `tests/fixtures/snova/kat_reference.json`
records the seed/message/public key/signed message (expanded secret keys are
bound by SHA-256) and is regenerable with
`python3 scripts/generate_snova_fixtures.py --kat-root <SNOVA_KAT checkout>`.
The independent model (`tests/models/snova_model.py`) covers GF16
`x^4+x+1` arithmetic, the nibble codecs, AES-128-CTR and indexed-SHAKE128
expansion (including the fixed `SHAKE256("SNOVA_ABQ")` block for l≤3), the
round-2 T/F/P relations, the full l²+l public map and a GF16 Gaussian solver,
and is differentially checked against the real adapter for the (24,5,4) and
fixed-ABQ profiles. P2 fault/timing lanes are opt-in; reports never claim
IND-CCA, EUF-CMA, sUF or quantum security.

The `snova_public_expansion` model lane locks the AES counter convention to
the pinned `aes_c.c` and treats SNOVA_SHAKE as indexed `SHAKE128(seed ||
LE64(i))`, not a continuous XOF. Accepted nonzero input padding nibbles are
reported as byte-alias observations, never as EUF forgeries.

Each parameter set/backend also has a `*_reference_vs_avx2` pair. The vendored
plasma/AVX2 overlay is recompiled with `-mavx2 -DOPTIMISATION=1`; its kernel
symbols are renamed `opt_*` (`objcopy --redefine-syms`) so both builds link
into one binary and `snova_cross_verify` exercises both. Provenance is labelled
`same-source-reference-vs-avx2`. The upstream `OPTIMISATION=2` (VTL) path was
reproduced by this harness to perform an unaligned 32-byte `__m256i` access in
`snova_plasma_avx2.h` during SSK signing (a memory-safety finding recorded in
`src/config/source_locks/snova.json`), so the standing lane uses
`OPTIMISATION=1`; the VTL crash is not silently masked as a target pass.

## SIKE/SIDH Workflow

PQCFuzz fuzzes the pinned microsoft/PQCrypto-SIDH generic build vendored at
`projects/SIKE_SIDH` (commit and archive SHA-256 recorded in
`src/config/source_locks/{sike,sidh}.json`). The four uncompressed SIKE KEM
parameter sets (`SIKE-p434/p503/p610/p751`, AlgorithmIds 40-43) and the four
SIDH key-exchange sets (`SIDH-p434/p503/p610/p751`, AlgorithmIds 48-51, a
distinct `kex` primitive with role-typed keygen/derive) share the source tree
but have separate adapters, executors and oracle specs
(`src/oracles/specs/{sike,sidh}.json`, oracle IDs 80-99).

**SIKE and SIDH are known broken since the 2022 attacks.** This lane covers
historical conformance, parser/memory-safety, failure behaviour and regression
research only; no report claims IND-CCA, key-agreement security or quantum
security. The SIKE re-encryption gate and fallback formula are checked against
an independent harness SHAKE256 plus the pinned isogeny reference, and the
official KAT responses are verified record-by-record.

Each parameter set also has a `*_reference_vs_optimized` pair. The AMD64
optimized build (`AMD64/fp_x64.c` + `fp_x64_asm.S`, MULX/ADX) is linked
alongside the generic build in one binary: every defined optimized symbol is
renamed with an `opt_` prefix (`objcopy --redefine-syms`) and the optimized
adapters call the renamed entry points through a generated API header. This
makes `sike_cross_exchange` and `sidh_cross_agreement` exercise two arithmetic
backends of the same pinned source; provenance is labelled
`same-source-reference-vs-optimized` and never reported as an independent
reimplementation.

```bash
# Validate the explicit pair file and materialize both families' jobs:
python3 src/pairing/validate_pair_alg.py --pair-alg src/config/pair_alg.sike_sidh.json
python3 src/jobs/generate_jobs.py --pair-alg src/config/pair_alg.sike_sidh.json \
  --algorithm-family SIKE --oracle-suite fips --jobs-dir workspace/sike_sidh/jobs
python3 src/jobs/generate_jobs.py --pair-alg src/config/pair_alg.sike_sidh.json \
  --algorithm-family SIDH --oracle-suite fips --jobs-dir workspace/sike_sidh/sidh_jobs

# Build the sanitizer fuzzers/replays, preflight every oracle, run a smoke
# campaign, and write workspace/sike_sidh/report/summary.{json,md}:
scripts/pqcfuzz_sike_sidh_eval.sh build
scripts/pqcfuzz_sike_sidh_eval.sh preflight
scripts/pqcfuzz_sike_sidh_eval.sh smoke
scripts/pqcfuzz_sike_sidh_eval.sh report

# Longer campaign (per-job seconds); FAMILY=SIKE|SIDH|all selects a lane:
MAX_TOTAL_TIME=3600 scripts/pqcfuzz_sike_sidh_eval.sh run
```

The independent Python models (`tests/models/sike_model.py`,
`tests/models/sidh_model.py`) cover the field codecs, SHAKE256 framing, gate
selection, Fp2 arithmetic, the j-invariant identity `j(A=6)=287496 mod p` and
the pinned reference transcripts. `tests/sike_oracles_test.py`,
`tests/sidh_oracles_test.py` and `tests/sike_model_test.py` cover routing,
envelope IDs, structured recipes, honest oracles on the real adapters, the
official SIKE KAT fixture, and detection by deliberately broken fake adapters
(ignored gate, always-fallback, dropped c1, mismatched SIDH agreement).
`scripts/generate_sike_sidh_fixtures.py` regenerates the fixtures and their
hashes. Compressed SIKE and the fault/timing lanes are opt-in P2 and are not
built by default.

## Falcon Workflow

PQCFuzz fuzzes the pinned official Falcon implementation archive
(`Falcon-impl-20211101`, archive SHA-256 in
`src/config/source_locks/falcon.json`) against the v1.2 (01/10/2020)
specification. The six encoding profiles
(`FALCON-{512,1024}-{COMPRESSED,PADDED,CT}`) get AlgorithmIds 56-61 and oracle
IDs 100-118 with a format-aware layout/mutator, an executor, a signed-message
adapter, and an independent Python model using integer negacyclic convolutions
(no target NTT/FFT).

```bash
# Validate the explicit pair file and materialize Falcon jobs:
python3 src/pairing/validate_pair_alg.py --pair-alg src/config/pair_alg.falcon.json
python3 src/jobs/generate_jobs.py --pair-alg src/config/pair_alg.falcon.json \
  --algorithm-family FALCON --oracle-suite fips --jobs-dir workspace/falcon/jobs

# Build the sanitizer fuzzers/replays, preflight every oracle, run a smoke
# campaign, and write workspace/falcon/report/summary.{json,md}:
scripts/pqcfuzz_falcon_eval.sh build
scripts/pqcfuzz_falcon_eval.sh preflight
scripts/pqcfuzz_falcon_eval.sh smoke
scripts/pqcfuzz_falcon_eval.sh report
```

The pinned round-3 KAT response files are vendored under `projects/FALCON/kat`;
the model lane reproduces their count=0 records. Compressed profiles pre-check
the declared `0x39/0x3A` header and verify with `sig_type=0`, so both the exact
compressed and the full zero-padded forms are accepted while partial padding
and non-zero padding remain negative controls.

The four compressed/padded profiles also have
`*_falcon_reference_vs_pqclean` pairs. PQClean's clean falcon-512/1024 and
falcon-padded-512/1024 wrappers are linked into the same binary (their symbols
are namespaced, so no renaming is needed) and `falcon_cross_verify` exercises
both builds. PQClean wraps the same Falcon core as the author reference, so
the provenance is labelled `same-source-shared-core-pqclean` and never
reported as an independent reimplementation. P2 fault/timing rows (117/118)
are opt-in via `PQCFUZZ_INCLUDE_P2=1`; reports never claim IND-CCA, EUF/sUF or
quantum security.

## NTRU Workflow

PQCFuzz fuzzes the pinned NTRU round-3 `Reference_Implementation`
(NTRU-HPS-2048-509/677, NTRU-HPS-4096-821, NTRU-HRSS-701; AlgorithmIds 32-35)
vendored at `projects/NTRU/reference` with the source archive SHA-256 recorded
in `src/config/source_locks/ntru.json`. Oracle IDs 64-79 cover the SHA3-256
implicit-rejection contract, the strict ciphertext-padding policy, PRF-key
separation, the S3/Rq0 codecs and the DPKE membership model.

```bash
# Validate the explicit pair file and materialize NTRU jobs:
python3 src/pairing/validate_pair_alg.py --pair-alg src/config/pair_alg.ntru.json
python3 src/jobs/generate_jobs.py --pair-alg src/config/pair_alg.ntru.json \
  --algorithm-family NTRU --oracle-suite fips --jobs-dir workspace/ntru/jobs

# Build the sanitizer fuzzers/replays, preflight every oracle, run a smoke
# campaign, and write workspace/ntru/report/summary.{json,md}:
scripts/pqcfuzz_ntru_eval.sh build
scripts/pqcfuzz_ntru_eval.sh preflight
scripts/pqcfuzz_ntru_eval.sh smoke
scripts/pqcfuzz_ntru_eval.sh report
```

The official count=0 KAT records (`PQCkemKAT_*.rsp`) are vendored under
`projects/NTRU/kat` and reproduced by the model lane; the independent Python
model implements its own integer polynomial arithmetic, HPS/HRSS lifts, codecs
and SHA3-256, and is differentially checked against the pinned build through
`tests/ntru_hook_cli.cc`. NTRU-HPS-4096-821 has no unused ciphertext bits, so
its padding oracles are explicitly `NOT_APPLICABLE` rather than fabricated.
P2 fault/timing rows (78/79) are opt-in via `PQCFUZZ_INCLUDE_P2=1`; reports
never claim IND-CCA or quantum security.

The optimized build of the same pinned round-3 submission is vendored under
`projects/NTRU/optimized` (source-lock file hashes recorded). Each parameter
set has a `*_ntru_reference_vs_optimized` pair whose left/right adapters are
compiled from the two trees with disjoint `CRYPTO_NAMESPACE` prefixes and
linked into one binary, so `ntru_cross_exchange` exercises a true
reference-vs-optimized lineage. The provenance is labelled
`same-source-reference-vs-optimized`, never reported as independent
reimplementations.

## Notes

- `projects/` is reserved for upstream source trees only.
- `workspace/` is reserved for runtime outputs only.
- Checked-in active PQCFuzz code lives under `src/`.
- Generated jobs, configs, traces, findings, and PoCs never live in
  source-of-truth directories.

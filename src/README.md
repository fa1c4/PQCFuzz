# PQCFuzz Active Source Tree

`src/` is the active PQCFuzz implementation for FIPS 203 ML-KEM, FIPS 204
ML-DSA, and FIPS 205 SLH-DSA external-API differential fuzzing, plus the
PQMagic Aigis-Enc (modes 1-4) and Aigis-Sig (modes 1-3) algorithms fuzzed
from `third_party/PQMagic` (see the Aigis section below).

This path is intentionally driven by an explicit pair file:

```bash
python3 src/pairing/validate_pair_alg.py \
  --pair-alg src/config/pair_alg.default.json

python3 src/jobs/generate_jobs.py \
  --pair-alg src/config/pair_alg.default.json \
  --algorithm-family ML-KEM

python3 src/jobs/generate_jobs.py \
  --pair-alg src/config/pair_alg.default.json \
  --algorithm-family ML-DSA

python3 src/jobs/generate_jobs.py \
  --pair-alg src/config/pair_alg.default.json \
  --algorithm-family SLH-DSA
```

## Oracle records and verdicts

`src/oracles/specs/*.json` is the source of truth for every oracle record
(claim, evidence class, source reference, scope, limitations, controls, and
execution metadata). `scripts/generate_oracle_specs.py` materializes the
checked-in `generated_*_specs.inc` tables; run it without arguments after
editing a spec, or with `--check` in CI.

Findings carry the design-document verdict vocabulary
(`CONFORMANT`, `NONCONFORMANT`, `HARDENING_GAP`, `NO_COUNTEREXAMPLE`,
`INCONCLUSIVE`, `NOT_APPLICABLE`, `HARNESS_ERROR`) plus the primary
`evidence_class` (`NORMATIVE`, `REFERENCE_DERIVED`, `IMPLEMENTATION_OBSERVED`,
`ENGINEERING_RECOMMENDATION`, `INFERENCE`), the tested claim, its source
reference, and explicit limitations. Aigis hardening observations are reported
as `HARDENING_GAP` with a conditional verdict, never as FIPS nonconformance.
Trace/finding artifacts use semantics version 5; versions 2-4 remain readable
as legacy evidence.

Additional case-ID oracle families: `*_implicit_rejection_relations`
(stability, z-separation, valid-z independence, public status shape),
`mlkem_raw_length_boundary` (`NOT_APPLICABLE` at the fixed-pointer boundary),
`*_verify_exact_lengths` and `*_ctx_boundaries` (signature length and context
limits at the target boundary), `mlkem_ek_canonicality` (12-bit coefficient
boundaries), and `mldsa_hint_canonicality` (FIPS 204 Algorithm 21 canonicality
mutations). Aigis oracles need the PQMagic snapshot under `third_party/PQMagic`
(`.gitignore`d); `scripts/pqcfuzz_aigis_eval.sh` builds it.

Every trace records `controls` (baseline repeat equality plus positive/negative
controls), and failures use the design doc's failure-state sentinel contract
(0xA5 prefill, output-length poison value, partial-output detection). Dedicated
fault binaries are built by `scripts/pqcfuzz_build_fault_binaries.sh` with
`-Wl,--wrap=malloc,calloc,realloc`; allocation failures are selected with
`PQCFUZZ_ALLOC_FAIL_AT`/`PQCFUZZ_ALLOC_FAIL_COUNT`, and `RngTape` supports
reported-failure, short-read, interrupted, repeated-block, and all-zero modes.

PQClean reference adapters (`pqclean_reference` project, ids
`pqclean_ref_mlkem*`/`pqclean_ref_mldsa*`/`pqclean_ref_slhdsa_*`) are built from
the pinned PQClean commit by `scripts/build_pqclean_reference.sh`; they expose
ML-KEM `keygen_derand`/`encaps_derand`, ML-DSA context sign/verify, and
SLH-DSA seed key generation plus sign/verify for KAT and deterministic-hook
oracles.

KAT oracles (`fips203_kat_keygen`, `fips203_kat_encaps`,
`fips203_kat_decaps`, `fips205_kat_keygen`) compare byte-for-byte against the
pinned NIST ACVP vectors fetched by `scripts/fetch_kat_vectors.sh` and
materialized into `src/oracles/kat/generated_kat_vectors.inc` by
`scripts/parse_kat_vectors.py` (a capped subset; the manifest records source
commit and per-file SHA-256). The executor lives in
`src/oracles/kat_executor.{h,cc}`.

Additional FIPS 204 oracles: `mldsa_z_norm_boundary` (packed response
coefficient boundary mutations), `mldsa_rnd_determinism` (fixed zero tape
reproducibility plus fresh-tape variation), and explicit `NOT_APPLICABLE`
records for `*_pure_prehash_separation` / `*_ph_oid_separation` until a
prehash-capable adapter is supplied. Reported-RNG-failure handling is checked
by `mlkem_rng_failure`, `mldsa_rng_failure`, and `slhdsa_rng_failure` using
the fault-injection tape modes; void RNG APIs that cannot report failure yield
`ENGINEERING_RECOMMENDATION`/`HARDENING_GAP` findings. Allocation-failure
output contracts are checked by `alloc_failure_contract` through
`scripts/pqcfuzz_build_fault_binaries.sh` (`alloc_probe`, built with
`-Wl,--wrap=malloc,calloc,realloc`); each allocation site runs in a forked
worker so fail-stop `exit()`/`abort()` behavior is recorded as an observation.
Quality checks and failure minimization are available via
`scripts/check_oracle_rubric.py` (design doc Section 43),
`scripts/minimize_input.py` (Section 37 ddmin), and
`scripts/pqcfuzz_api_surface.py` (Sections 30.10/49 diagnostic export and
zeroization inventory).

The generator only consumes pair records supplied by `--pair-alg`; it does not
infer implementation provenance or compatibility. Generated jobs and runtime
configs are written under `workspace/jobs/` and `workspace/tmp/`.

Replay accepts PQCFuzz envelope inputs and writes structured traces/artifacts:

```bash
python3 src/replay/replay_one.py \
  --job workspace/jobs/<mlkem_job>.json \
  --input tests/seeds/mlkem_roundtrip_seed.bin

python3 src/replay/replay_one.py \
  --job workspace/jobs/<mldsa_job>.json \
  --input tests/seeds/mldsa_sign_verify_seed.bin

python3 src/replay/replay_one.py \
  --job workspace/jobs/<slhdsa_job>.json \
  --input tests/seeds/slhdsa_sign_verify_seed.bin
```

Baselines remain outside this active implementation and are not modified by the
PQCFuzz FIPS 203 path.

## Aigis (PQMagic) support

Aigis-Enc / Aigis-Sig are fuzzed against the PQMagic implementation through the
same envelope/oracle pipeline:

- **Pair file:** `src/config/pair_alg.aigis.json` (7 pairs: `pqmagic` SM3 build
  vs SHAKE build per mode; cross-exchange oracles are intentionally not
  scheduled because the shared secret and signature challenge bind the hash
  function).
- **Adapters:** `src/adapters/pqmagic/kem_adapter.cc`, `sig_adapter.cc`
  (project id `pqmagic`; implementation ids `pqmagic_aigis_enc_<m>_std_<hash>`
  and `pqmagic_aigis_sig<m>_std_<hash>`). The shared RNG override for strong
  `randombytes` symbols is `src/adapters/randombytes_override.cc`.
- **Layouts/mutators:** `src/mutators/aigis_enc_layout.*`,
  `aigis_enc_mutator.*` (ciphertext.u/v regions, 13-bit secret coefficient),
  `src/mutators/aigis_sig_layout.*`, `aigis_sig_mutator.*` (z/h/c signature
  regions, unused-sign-bit operation).
- **Oracle specs:** `src/oracles/specs/aigis_enc.json`, `aigis_sig.json`
  (envelope oracles 31-45). The Aigis-Sig fips suite implements the blocking
  tests from `plans/deepseek_pqc_test_oracle_design.md`:
  exact signature length, unused challenge sign bits, ctx_len=256
  failure-state consistency, determinism, plus implicit rejection and
  non-canonical secret-key coefficient oracles for Aigis-Enc. Aigis findings
  are labeled implementation observations / hardening gaps, never FIPS
  nonconformance.
- **Build/run:** `scripts/pqcfuzz_aigis_eval.sh` builds both PQMagic hash
  variants (`-DPQMAGIC_DISABLE_DEFAULT_OPTS=ON` for sanitizer builds), renames
  the SHAKE archive symbols with `scripts/rename_pqmagic_symbols.py`, and
  drives per-job fuzzer/replay builds, preflight (with an oracle-coverage
  gate), and parallel campaigns (`run-parallel`, `JOB_FILTER`, `WORKERS`).
- **Known triage note:** the generic metamorphic `kem_decaps_sk` oracle has a
  `~1/q`-per-position false-positive floor: when the NTT-domain ciphertext
  coefficient at the mutated secret position is `0 (mod q)`, flipping that
  secret bit provably cannot change the shared secret (normal lattice-KEM
  behavior, not a defect). `kem_decaps_sk` is not part of the security-tier
  oracle set.
- **Reproducibility:** metamorphic KEM keygen/encapsulation and signature
  keygen draw from seed-derived deterministic tapes, so recorded findings
  replay bit-identically. Hedged *signing* randomness is only controlled by
  the `*_badrng` oracles; deterministic signers (Aigis-Sig) replay fully.

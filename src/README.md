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
  tests from `third_party/aigis_nist_doc/deepseek_pqc_test_oracle_design.md`:
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

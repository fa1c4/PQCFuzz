# Baselines

This directory contains vendored baseline fuzzers used by PQC-DF.

These baselines are not Git submodules. Their upstream `.git` directories have been removed, and the source trees are tracked directly by the PQC-DF repository.

Baseline `.gitignore` files are intentionally kept so that upstream build/cache conventions remain visible.

Git platform metadata such as `.github/`, `.gitmodules`, and `.gitattributes` is removed from vendored baselines.

## Baselines

- `cryptofuzz`
- `CLFuzz`
- `cryptoTesting`

## Running baselines

Use the root dispatcher:

```bash
scripts/run_baseline.sh cryptofuzz build
scripts/run_baseline.sh cryptofuzz run

scripts/run_baseline.sh CLFuzz build
scripts/run_baseline.sh CLFuzz run

scripts/run_baseline.sh cryptoTesting build
scripts/run_baseline.sh cryptoTesting run
```

Build artifacts are written to:

```text
workspace/<baseline>/targets-build/
```

Run artifacts are written to:

```text
workspace/<baseline>/targets-run/
```

Baseline source directories should remain clean and should not contain PQC-DF runtime artifacts.

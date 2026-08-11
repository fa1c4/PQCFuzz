#!/usr/bin/env python3
"""Compare the vendored cryptoTesting baseline with the upstream repository.

Classifies every local difference against one of the categories defined in
Section 5 of the reproduction plan:

    PQCDF_OUTPUT_ISOLATION          # changes output ownership/paths only
    PQCDF_DURABLE_ARTIFACTS         # keeps raw AFL/replay evidence durable
    PQCDF_REPLAY_OR_MANIFEST        # adds replay/manifest metadata
    PQCDF_BUILD_OR_CLONE_ROBUSTNESS # retry/cache/docker build robustness
    PAPER_SEMANTICS_CHANGE          # changes GenInput/Call/Maul/Match semantics
    PAPER_COUNTING_CHANGE           # changes report counting semantics
    UNKNOWN_OR_RISKY

Usage:

    python3 scripts/cryptoTesting_compare_upstream.py \\
        --local baselines/cryptoTesting \\
        --upstream workspace/cryptoTesting-reproduction-alpha/upstream_compare/cryptoTesting-upstream \\
        --output-dir workspace/cryptoTesting-reproduction-alpha/upstream_compare
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path


COMPARE_FILES = [
    "Makefile", "Dockerfile", "build.sh", "run.sh", "reproduce.sh",
    "fuzz_liboqs.py", "fuzz_liboqs_baseline.py",
    "report.py", "report_baseline.py",
    "supercop_report.py", "supercop_report_baseline.py",
]
COMPARE_TREES = [
    "tech/paper_fuzzing/liboqs",
    "tech/paper_fuzzing/utilities",
    "tech/paper_fuzzing/vanilla",
    "paper_reports",
]

# True semantics files implement GenInput/Call/Maul/Match/PRNG/serialization.
SEMANTICS_FILES = {
    "tech/paper_fuzzing/liboqs/Maul.c",
    "tech/paper_fuzzing/liboqs/Maul.py",
    "tech/paper_fuzzing/liboqs/Match.c",
    "tech/paper_fuzzing/liboqs/Match.h",
}
SEMANTICS_SOURCE_SUFFIXES = (".c", ".h", ".py")
SEMANTICS_TREES = {
    "tech/paper_fuzzing/liboqs",
    "tech/paper_fuzzing/utilities",
}
NON_SEMANTICS_BASENAMES = {"Makefile", "MakefileCommonTargets.mk"}


def file_hash(path: Path) -> str:
    if not path.is_file():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def diff_stat(a: Path, b: Path) -> tuple[str, int]:
    """Return ('identical'|'modified'|'only-local'|'only-upstream', line_count)."""
    if not a.is_file() and not b.is_file():
        return ("missing", 0)
    if a.is_file() and not b.is_file():
        return ("only-local", sum(1 for _ in a.read_text(errors="replace").splitlines()))
    if b.is_file() and not a.is_file():
        return ("only-upstream", sum(1 for _ in b.read_text(errors="replace").splitlines()))
    if file_hash(a) == file_hash(b):
        return ("identical", 0)
    try:
        out = subprocess.run(["diff", str(a), str(b)], capture_output=True, text=True)
        return ("modified", len(out.stdout.splitlines()))
    except FileNotFoundError:
        return ("modified", -1)


def classify(rel: str, status: str) -> str:
    if status == "identical":
        return "IDENTICAL"
    # Bytecode artifacts are not source; ignore them as build cache noise.
    if "__pycache__" in rel or rel.endswith((".pyc", ".pyo")):
        return "PQCDF_BUILD_OR_CLONE_ROBUSTNESS"
    base = rel.rsplit("/", 1)[-1]
    # Build configuration inside the semantics trees is not test semantics.
    if base in NON_SEMANTICS_BASENAMES:
        return "PQCDF_BUILD_OR_CLONE_ROBUSTNESS"
    if rel in SEMANTICS_FILES:
        return "PAPER_SEMANTICS_CHANGE"
    if any(rel.startswith(t + "/") for t in SEMANTICS_TREES):
        # Only actual source files (Call.c, GenInput.c, Maul.py, serialize, ...)
        # that implement GenInput/Call/Maul/Match/PRNG are semantics-relevant.
        if rel.endswith(SEMANTICS_SOURCE_SUFFIXES):
            if base in ("run_all.py",):
                # run_all.py only changes output paths/env vars and failure
                # reporting, not GenInput/Call/Maul/Match behaviour.
                return "PQCDF_OUTPUT_ISOLATION"
            return "PAPER_SEMANTICS_CHANGE"
        return "PQCDF_BUILD_OR_CLONE_ROBUSTNESS"
    if rel == "fuzz_liboqs.py":
        return "PQCDF_DURABLE_ARTIFACTS"  # output isolation + manifest + blacklist-empty
    if rel in ("crypto_testing_manifest.py", "crypto_testing_replay.py"):
        return "PQCDF_REPLAY_OR_MANIFEST"
    if rel == "report.py":
        return "PQCDF_OUTPUT_ISOLATION"   # --output-root/--report-dir + LaTeX escaping
    if rel in ("fuzz_liboqs_baseline.py", "report_baseline.py"):
        return "PQCDF_OUTPUT_ISOLATION"   # baseline campaign infrastructure
    if rel in ("Makefile", "Dockerfile", "build.sh", "clone_with_retry.sh"):
        return "PQCDF_BUILD_OR_CLONE_ROBUSTNESS"
    if rel in ("reproduce.sh", "run.sh"):
        return "PQCDF_OUTPUT_ISOLATION"
    if rel.startswith("paper_reports/"):
        return "PQCDF_DURABLE_ARTIFACTS"
    if rel.startswith("tech/paper_fuzzing/vanilla/"):
        return "PQCDF_OUTPUT_ISOLATION"
    return "UNKNOWN_OR_RISKY"


def collect_files(root: Path, rels: list[str]) -> list[str]:
    found = set()
    for rel in rels:
        p = root / rel
        if p.is_file():
            found.add(rel)
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file():
                    found.add(str(f.relative_to(root)))
    return sorted(found)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Compare vendored vs upstream cryptoTesting.")
    ap.add_argument("--local", required=True, help="Vendored baseline directory.")
    ap.add_argument("--upstream", required=True, help="Upstream clone directory.")
    ap.add_argument("--output-dir", required=True, help="Output directory for evidence.")
    args = ap.parse_args(argv)

    local = Path(args.local)
    upstream = Path(args.upstream)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    rels = set(COMPARE_FILES)
    for t in COMPARE_TREES:
        rels.update(collect_files(local, [t]))
        rels.update(collect_files(upstream, [t]))
    # Add vendored-only files (crypto_testing_manifest.py, crypto_testing_replay.py, clone_with_retry.sh)
    for extra in ("crypto_testing_manifest.py", "crypto_testing_replay.py", "clone_with_retry.sh"):
        if (local / extra).is_file():
            rels.add(extra)

    rows = []
    for rel in sorted(rels):
        status, lines = diff_stat(upstream / rel, local / rel)
        cat = classify(rel, status)
        rows.append((rel, status, lines, cat))

    # TSV manifests.
    with (out / "upstream_file_manifest.tsv").open("w") as f:
        f.write("path\tsha256\n")
        for rel in sorted(rels):
            f.write(f"{rel}\t{file_hash(upstream / rel)}\n")
    with (out / "local_file_manifest.tsv").open("w") as f:
        f.write("path\tsha256\n")
        for rel in sorted(rels):
            f.write(f"{rel}\t{file_hash(local / rel)}\n")

    # Diff summary.
    with (out / "diff_summary.md").open("w") as f:
        f.write("# Vendored vs upstream diff summary\n\n")
        f.write("| path | status | diff_lines | classification |\n")
        f.write("|---|---|---:|---|\n")
        for rel, status, lines, cat in rows:
            f.write(f"| {rel} | {status} | {lines} | {cat} |\n")

    # PQCDF local changes.
    with (out / "pqcdf_local_changes.md").open("w") as f:
        f.write("# PQCFuzz local changes classification\n\n")
        by_cat: dict[str, list[str]] = {}
        for rel, status, lines, cat in rows:
            by_cat.setdefault(cat, []).append(rel)
        for cat in sorted(by_cat):
            f.write(f"## {cat}\n\n")
            for rel in by_cat[cat]:
                f.write(f"- `{rel}`\n")
            f.write("\n")
        risky = [r for r, _, _, c in rows if c in ("PAPER_SEMANTICS_CHANGE", "PAPER_COUNTING_CHANGE", "UNKNOWN_OR_RISKY")]
        f.write("## Risky differences\n\n")
        if risky:
            for r in risky:
                f.write(f"- `{r}`\n")
        else:
            f.write("No PAPER_SEMANTICS_CHANGE, PAPER_COUNTING_CHANGE, or UNKNOWN_OR_RISKY differences detected.\n")

    # Upstream status.
    try:
        log = subprocess.run(["git", "-C", str(upstream), "log", "-1",
                              "--format=%H %ci %s"], capture_output=True, text=True)
        commit = log.stdout.strip()
    except Exception:
        commit = "unknown"
    (out / "upstream_status.md").write_text(
        "# Upstream comparison status\n\n"
        f"Upstream repository: https://github.com/jangilcher/cryptoTesting\n\n"
        f"Upstream commit: `{commit}`\n\n"
        "Network access was available; upstream was cloned read-only.\n",
        encoding="utf-8")

    # Console summary.
    cats: dict[str, int] = {}
    for _, _, _, cat in rows:
        cats[cat] = cats.get(cat, 0) + 1
    print(f"compared_files: {len(rows)}")
    for cat, n in sorted(cats.items()):
        print(f"  {cat}: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Collect and report PQCFuzz AIGIS evaluation results.

Scans workspace/results/job_aigis*/ for oracle coverage, finding artifacts,
and crash files; replays every finding with replay_one.py; and writes a
markdown report mapping each finding to the DeepSeek test-oracle design
document (third_party/aigis_nist_doc/deepseek_pqc_test_oracle_design.md).

Usage:
    python3 scripts/pqcfuzz_aigis_report.py [--skip-replay] [--out REPORT.md]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS = REPO_ROOT / "workspace" / "results"
JOBS_DIR = REPO_ROOT / "workspace" / "jobs"
CRASHES = REPO_ROOT / "workspace" / "crashes"

DOC_CASES = {
    "noncanonical_secret_key_accepted": "doc 33.4: non-canonical secret-key coefficient accepted (q=7681)",
    "appended_signature_bytes_accepted": "doc 34.2 / AS-SIG-EXACT-LEN: appended signature byte accepted",
    "unused_sign_bit_malleable": "doc 34.3 / AS-SIG-UNUSED-SIGNBITS: unused challenge sign bit malleable",
    "failure_output_length_state_inconsistent": "doc 34.5 / AS-SIG-CTX256-*: output-length state inconsistent on failure",
    "determinism_violation": "doc 34.4 / AS-SIG-DETERMINISM-PROFILE: repeated signing not deterministic",
    "secret_key_malleability": (
        "generic-oracle false positive (kem_decaps_sk): when the NTT-domain ciphertext "
        "coefficient at the mutated secret position is 0 mod q, flipping that secret bit does "
        "not change decapsulation (rate ~1/q per position). Expected lattice-KEM behavior; "
        "not a security finding. kem_decaps_sk is not in the security-tier oracle set."
    ),
}


def job_dirs() -> list[Path]:
    return sorted(RESULTS.glob("job_aigis*"))


def read_coverage(job_dir: Path) -> dict:
    coverage = job_dir / "oracle_coverage.json"
    if not coverage.is_file():
        return {}
    try:
        return json.loads(coverage.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def finding_dirs(job_dir: Path) -> list[Path]:
    out = []
    for entry in job_dir.iterdir():
        if not entry.is_dir() or entry.name.startswith("replay_"):
            continue
        if (entry / "finding.json").is_file():
            out.append(entry)
    return sorted(out)


def replay_finding(job_dir: Path, finding_dir: Path, timeout: int = 120) -> dict:
    job_file = JOBS_DIR / f"{job_dir.name}.json"
    structured = finding_dir / "structured_input.bin"
    if not job_file.is_file() or not structured.is_file():
        return {"status": "missing_job_or_input"}
    cmd = [
        sys.executable, "src/replay/replay_one.py",
        "--job", str(job_file),
        "--input", str(structured),
        "--timeout-seconds", str(timeout),
    ]
    proc = subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout + 120,
    )
    result = {"status": "ok" if proc.returncode == 0 else f"exit_{proc.returncode}"}
    for line in (proc.stdout + proc.stderr).splitlines():
        if "wrote artifacts to" in line:
            replay_dir = Path(line.split("wrote artifacts to", 1)[1].strip())
            result["replay_dir"] = str(replay_dir)
            trace_path = replay_dir / "oracle_trace.json"
            if trace_path.is_file():
                try:
                    replay_trace = json.loads(trace_path.read_text(encoding="utf-8"))
                    reproduced = bool(replay_trace.get("findings")) and \
                        replay_trace.get("disposition") == "raw_candidate"
                    result["reproduced"] = reproduced
                    result["replay_disposition"] = replay_trace.get("disposition", "")
                    result["replay_findings"] = len(replay_trace.get("findings", []))
                except (json.JSONDecodeError, OSError):
                    pass
            break
    return result


def collect(job_dirs: list[Path], skip_replay: bool, max_replay_per_subclass: int) -> list[dict]:
    rows: list[dict] = []
    for job_dir in job_dirs:
        coverage = read_coverage(job_dir)
        totals = coverage.get("totals", {})
        per_subclass: dict[str, int] = {}
        for finding_dir in finding_dirs(job_dir):
            finding = json.loads((finding_dir / "finding.json").read_text(encoding="utf-8"))
            subclass = finding.get("finding_subclass", "")
            key = (job_dir.name, subclass)
            per_subclass[key] = per_subclass.get(key, 0) + 1
            row = {
                "job": job_dir.name,
                "finding_id": finding_dir.name,
                "oracle_id": finding.get("oracle_id", ""),
                "class": finding.get("finding_class", ""),
                "subclass": subclass,
                "algorithm": finding.get("algorithm", ""),
                "doc_case": DOC_CASES.get(subclass, ""),
                "replay": {},
                "totals": {
                    k: totals.get(k) for k in (
                        "inputs", "oracle_invocations", "finding_records",
                        "rng_intervention_observed", "skipped", "not_evaluable",
                    )
                },
            }
            rows.append(row)
    if not skip_replay and rows:
        jobs_by_name = {job_dir.name: job_dir for job_dir in job_dirs}
        sampled = []
        seen: dict[tuple[str, str], int] = {}
        for row in rows:
            key = (row["job"], row["subclass"])
            if seen.get(key, 0) >= max_replay_per_subclass:
                continue
            seen[key] = seen.get(key, 0) + 1
            sampled.append(row)
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {
                pool.submit(replay_finding, jobs_by_name[row["job"]], RESULTS / row["job"] / row["finding_id"]): row
                for row in sampled
            }
            for fut in futures:
                futures[fut]["replay"] = fut.result()
    return rows


def crash_files() -> list[Path]:
    return sorted(CRASHES.glob("job_aigis*/*"))


def render(rows: list[dict], crashes: list[Path], job_dirs: list[Path], out: Path) -> str:
    lines: list[str] = []
    lines.append("# PQCFuzz AIGIS Evaluation Report")
    lines.append("")
    lines.append(f"jobs: {len(job_dirs)}, finding artifacts: {len(rows)}, crash files: {len(crashes)}")
    lines.append("")
    lines.append("## Campaign totals")
    lines.append("")
    lines.append("| job | inputs | oracle_invocations | finding_records | rng_observed | skipped | not_evaluable |")
    lines.append("|---|---|---|---|---|---|---|")
    for job_dir in job_dirs:
        totals = read_coverage(job_dir).get("totals", {})
        lines.append(
            f"| {job_dir.name} | {totals.get('inputs', 0)} | {totals.get('oracle_invocations', 0)} | "
            f"{totals.get('finding_records', 0)} | {totals.get('rng_intervention_observed', 0)} | "
            f"{totals.get('skipped', 0)} | {totals.get('not_evaluable', 0)} |"
        )
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not rows:
        lines.append("no findings recorded")
    replay_rows = [r for r in rows if r["replay"]]
    counted_rows = [r for r in rows if not r["replay"]]
    for row in replay_rows:
        replay = row["replay"]
        replay_note = ""
        if "reproduced" in replay:
            state = "reproduced" if replay["reproduced"] else "NOT reproduced"
            replay_note = f" -> replay: {state} (disposition={replay.get('replay_disposition','')})"
        elif replay.get("status"):
            replay_note = f" -> replay: {replay['status']}"
        lines.append(f"- **{row['algorithm']}** / `{row['oracle_id']}`: "
                     f"`{row['class']}` + `{row['subclass']}`")
        lines.append(f"  - {row['doc_case'] or 'unmapped subclass'}{replay_note}")
    if counted_rows:
        lines.append(f"- ... plus {len(counted_rows)} additional artifacts (counted, not replayed)")
    lines.append("")
    lines.append("## Crashes")
    lines.append("")
    if crashes:
        for crash in crashes:
            lines.append(f"- {crash}")
    else:
        lines.append("no crash artifacts")
    lines.append("")
    text = "\n".join(lines) + "\n"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-replay", action="store_true")
    parser.add_argument("--max-replay-per-subclass", type=int, default=10)
    parser.add_argument("--out", default=str(REPO_ROOT / "workspace" / "aigis_eval_report.md"))
    args = parser.parse_args()

    jobs = job_dirs()
    if not jobs:
        print("no job_aigis* result directories found", file=sys.stderr)
        return 1
    rows = collect(jobs, args.skip_replay, args.max_replay_per_subclass)
    crashes = crash_files()
    out = Path(args.out)
    print(render(rows, crashes, jobs, out))
    print(f"report written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Generate PQCFuzz jobs from externally supplied algorithm-pair metadata."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from jobs.generated_config_writer import SECURITY_TIER_ORACLES, make_job_record, make_metamorphic_job_record, materialize_job, metamorphic_oracle_ids_for_pair, write_json
from pairing.pair_alg_loader import PairAlgError, enabled_pairs_for_family, load_pair_alg


DEFAULT_PAIR_ALG = Path("src/config/pair_alg.default.json")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair-alg", default=str(DEFAULT_PAIR_ALG), help="explicit algorithm-pair JSON")
    parser.add_argument("--algorithm-family", default="ML-KEM", help="algorithm family to materialize")
    parser.add_argument("--jobs-dir", default="workspace/jobs", help="job output directory")
    parser.add_argument("--oracle-suite", choices=["fips", "metamorphic"], default="fips", help="oracle suite to materialize")
    parser.add_argument(
        "--relation-mode",
        choices=["single-target", "self-reference", "cross-implementation", "single-liboqs", "liboqs-vs-pqclean"],
        default="cross-implementation",
        help="relation mode for generated jobs",
    )
    parser.add_argument("--target-runtime", default="liboqs", help="single-target runtime for metamorphic jobs")
    parser.add_argument("--target-version", default="", help="optional target runtime version label")
    parser.add_argument("--target-algorithm", default="", help="optional single algorithm filter")
    parser.add_argument("--oracle-set", choices=["all", "security"], default="all", help="metamorphic oracle subset")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    document = load_pair_alg(args.pair_alg)
    pairs = enabled_pairs_for_family(document, args.algorithm_family)
    # SLH-DSA metadata remains parseable for audit, but no selected liboqs
    # release has a real adapter in this harness.  Never materialize a job
    # whose envelope label could otherwise reach an ML-DSA adapter.
    if args.algorithm_family == "SLH-DSA":
        pairs = []
    if args.target_algorithm:
        pairs = [pair for pair in pairs if pair["algorithm"] == args.target_algorithm]
    if args.oracle_suite == "metamorphic":
        relation_mode = "single-target" if args.relation_mode == "single-liboqs" else args.relation_mode
        if relation_mode != "single-target":
            print("generate_jobs error: metamorphic jobs currently require --relation-mode single-target", file=sys.stderr)
            return 1
        jobs = []
        for pair in sorted(pairs, key=lambda item: item["pair_id"]):
            if pair["left"]["project_id"] != args.target_runtime and pair["right"]["project_id"] != args.target_runtime:
                continue
            oracle_ids = metamorphic_oracle_ids_for_pair(pair)
            if args.oracle_set == "security":
                oracle_ids = [oracle_id for oracle_id in oracle_ids if oracle_id in SECURITY_TIER_ORACLES]
            for oracle_id in oracle_ids:
                jobs.append(make_metamorphic_job_record(pair, REPO_ROOT, args.target_runtime, args.target_version, oracle_id=oracle_id))
    else:
        jobs = [make_job_record(pair, REPO_ROOT) for pair in sorted(pairs, key=lambda item: item["pair_id"])]

    jobs_dir = REPO_ROOT / args.jobs_dir
    jobs_dir.mkdir(parents=True, exist_ok=True)
    for job in jobs:
        materialize_job(REPO_ROOT, job)

    summary_path = jobs_dir / "jobs.json"
    write_json(summary_path, jobs)
    try:
        display_summary = summary_path.relative_to(REPO_ROOT)
    except ValueError:
        display_summary = summary_path
    print(f"wrote {display_summary} with {len(jobs)} PQCFuzz jobs")
    for job in jobs:
        print(f"  {job['paths']['job']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PairAlgError as exc:
        print(f"generate_jobs error: {exc}", file=sys.stderr)
        raise SystemExit(1)

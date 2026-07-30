from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_security_oracle_generation_creates_one_oracle_per_job(tmp_path: Path) -> None:
    jobs_dir = tmp_path / "jobs"
    subprocess.run(
        [
            sys.executable,
            "src/jobs/generate_jobs.py",
            "--oracle-suite",
            "metamorphic",
            "--relation-mode",
            "single-target",
            "--algorithm-family",
            "ML-DSA",
            "--target-algorithm",
            "ML-DSA-44",
            "--oracle-set",
            "security",
            "--jobs-dir",
            str(jobs_dir),
        ],
        cwd=REPO_ROOT,
        check=True,
        text=True,
        capture_output=True,
    )

    jobs = json.loads((jobs_dir / "jobs.json").read_text(encoding="utf-8"))
    assert [job["oracle_id"] for job in jobs] == ["sig_verify_m", "sig_verify_sig", "sig_verify_pk"]
    assert all(len(job["oracles"]) == 1 for job in jobs)
    assert all(job["paths"]["run_dir"].endswith(job["job_id"]) for job in jobs)

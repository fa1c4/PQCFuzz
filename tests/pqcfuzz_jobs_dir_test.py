from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_sidh_jobs_dir_receives_job_files(tmp_path: Path) -> None:
    jobs_dir = tmp_path / "sidh_jobs"
    result = subprocess.run(
        [
            sys.executable,
            "src/jobs/generate_jobs.py",
            "--pair-alg",
            "src/config/pair_alg.sike_sidh.json",
            "--algorithm-family",
            "SIDH",
            "--oracle-suite",
            "fips",
            "--jobs-dir",
            str(jobs_dir),
        ],
        cwd=REPO_ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    assert "with 8 PQCFuzz jobs" in result.stdout

    jobs = json.loads((jobs_dir / "jobs.json").read_text(encoding="utf-8"))
    assert len(jobs) == 8
    for job in jobs:
        job_path = Path(job["paths"]["job"])
        assert job_path == jobs_dir / f"{job['job_id']}.json"
        assert job_path.is_file()
        # Non-job artifacts stay self-contained under the campaign workspace.
        assert job["paths"]["generated_config"].startswith(str(jobs_dir.parent))
        assert job["paths"]["run_dir"].startswith(str(jobs_dir.parent))


def test_include_p2_schedules_opt_in_oracles(tmp_path: Path) -> None:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from jobs.generated_config_writer import (  # noqa: PLC0415
        P2_ORACLES_BY_FAMILY,
        oracle_ids_for_pair,
    )
    from pairing.pair_alg_loader import enabled_pairs_for_family, load_pair_alg  # noqa: PLC0415

    document = load_pair_alg(REPO_ROOT / "src/config/pair_alg.cross.json")
    pair = enabled_pairs_for_family(document, "CROSS")[0]
    default_ids = oracle_ids_for_pair(pair)
    p2_ids = P2_ORACLES_BY_FAMILY["CROSS"]
    assert not set(p2_ids) & set(default_ids)
    with_p2 = oracle_ids_for_pair(pair, include_p2=True)
    assert set(p2_ids) <= set(with_p2)
    assert len(with_p2) == len(default_ids) + len(p2_ids)

    jobs_dir = tmp_path / "p2_jobs"
    subprocess.run(
        [
            sys.executable,
            "src/jobs/generate_jobs.py",
            "--pair-alg",
            "src/config/pair_alg.cross.json",
            "--algorithm-family",
            "CROSS",
            "--oracle-suite",
            "fips",
            "--include-p2",
            "--jobs-dir",
            str(jobs_dir),
        ],
        cwd=REPO_ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    jobs = json.loads((jobs_dir / "jobs.json").read_text(encoding="utf-8"))
    assert all(job["include_p2"] is True for job in jobs)
    assert all(set(p2_ids) <= set(job["oracles"]) for job in jobs)


def test_unknown_algorithm_family_is_rejected(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "src/jobs/generate_jobs.py",
            "--pair-alg",
            "src/config/pair_alg.sike_sidh.json",
            "--algorithm-family",
            "BOGUS",
            "--jobs-dir",
            str(tmp_path / "jobs"),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "unsupported algorithm family 'BOGUS'" in result.stderr

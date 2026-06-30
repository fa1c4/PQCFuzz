from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REPLAY_ONE = REPO_ROOT / "src/replay/replay_one.py"


def write_seed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "magic": "PQCF",
                "version": 1,
                "algorithm": "ML-KEM-768",
                "oracle_id": "kem_decaps_c",
                "seed_b64": "",
                "msg_b64": "",
                "mutation_b64": "",
                "extra_b64": "",
            }
        )
        + "\n",
        encoding="utf-8",
    )


def write_job(tmp_path: Path) -> Path:
    generated_config = tmp_path / "generated_config.json"
    generated_config.write_text("{}\n", encoding="utf-8")
    job = {
        "version": 1,
        "job_id": "job_worker_test",
        "pair_id": "worker_test",
        "oracle_suite": "metamorphic",
        "relation_mode": "single-target",
        "algorithm": "ML-KEM-768",
        "primitive_type": "kem",
        "target": {
            "project_id": "liboqs",
            "implementation_id": "liboqs_mlkem768_wrapper_generic",
        },
        "oracles": ["kem_decaps_c"],
        "paths": {
            "generated_config": str(generated_config),
            "result_dir": str(tmp_path / "results"),
            "crash_dir": str(tmp_path / "crashes"),
            "run_dir": str(tmp_path / "runs"),
        },
    }
    job_path = tmp_path / "job.json"
    job_path.write_text(json.dumps(job) + "\n", encoding="utf-8")
    return job_path


def write_replay_bin(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def run_replay(tmp_path: Path, replay_body: str, timeout: int = 2) -> Path:
    job_path = write_job(tmp_path)
    seed_path = tmp_path / "seed.json"
    write_seed(seed_path)
    replay_bin = tmp_path / "fake_replay.py"
    write_replay_bin(replay_bin, replay_body)
    completed = subprocess.run(
        [
            sys.executable,
            str(REPLAY_ONE),
            "--job",
            str(job_path),
            "--input",
            str(seed_path),
            "--replay-bin",
            str(replay_bin),
            "--timeout-seconds",
            str(timeout),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    artifact_rel = completed.stdout.strip().split(" to ", 1)[1]
    return REPO_ROOT / artifact_rel


def load_trace(artifact: Path) -> dict:
    return json.loads((artifact / "oracle_trace.json").read_text(encoding="utf-8"))


def test_worker_exit_72_becomes_crash(tmp_path: Path) -> None:
    artifact = run_replay(tmp_path, "import sys\nsys.exit(72)\n")
    assert load_trace(artifact)["findings"][0]["class"] == "crash"


def test_worker_timeout_becomes_hang(tmp_path: Path) -> None:
    artifact = run_replay(tmp_path, "import time\ntime.sleep(5)\n", timeout=1)
    assert load_trace(artifact)["findings"][0]["class"] == "hang"


def test_worker_trace_exit_70_is_preserved(tmp_path: Path) -> None:
    artifact = run_replay(
        tmp_path,
        """
import json, sys
trace = sys.argv[sys.argv.index('--trace') + 1]
open(trace, 'w', encoding='utf-8').write(json.dumps({'version': 1, 'oracle_suite': 'metamorphic', 'relation_mode': 'single-target', 'job_id': 'job_worker_test', 'pair_id': 'worker_test', 'algorithm': 'ML-KEM-768', 'oracle_id': 'kem_decaps_c', 'findings': [{'class': 'malleability', 'summary': 'kept'}], 'subtests': [], 'mutations': []}) + '\\n')
sys.exit(70)
""",
    )
    assert load_trace(artifact)["findings"][0]["class"] == "malleability"
    assert (artifact / "finding.json").exists()


def test_worker_exit_zero_without_trace_is_no_finding(tmp_path: Path) -> None:
    artifact = run_replay(tmp_path, "import sys\nsys.exit(0)\n")
    assert load_trace(artifact)["findings"] == []
    assert not (artifact / "finding.json").exists()

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_legacy_migration_writes_manifest_without_rewriting_artifacts(tmp_path: Path) -> None:
    artifact = tmp_path / "results" / "kem" / "legacy"
    artifact.mkdir(parents=True)
    finding_path = artifact / "finding.json"
    original = {
        "version": 3,
        "oracle_semantics_version": 3,
        "finding_id": "legacy",
        "finding_class": "malleability",
        "validated": True,
    }
    finding_path.write_text(json.dumps(original, sort_keys=True) + "\n", encoding="utf-8")
    before = finding_path.read_bytes()
    manifest_path = tmp_path / "legacy_manifest.json"

    subprocess.run(
        [sys.executable, "scripts/migrate_legacy_findings.py", str(tmp_path / "results"), "--output", str(manifest_path)],
        cwd=REPO_ROOT,
        check=True,
        text=True,
        capture_output=True,
    )

    assert finding_path.read_bytes() == before
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["oracle_semantics_version"] == 4
    assert len(manifest["entries"]) == 1
    entry = manifest["entries"][0]
    assert entry["oracle_semantics_version"] == 3
    assert entry["validated"] is False
    assert entry["invalidation_reason"] == "legacy_semantics_requires_v4_replay"

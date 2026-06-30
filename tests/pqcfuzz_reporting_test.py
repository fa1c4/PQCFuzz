from __future__ import annotations

import csv
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src/reporting"))

from summarize_findings import find_finding_files  # noqa: E402
from write_report import write_reports  # noqa: E402


def write_finding(
    eval_root: Path,
    *,
    version: str = "0.8.0",
    primitive: str = "kem",
    finding_id: str = "malleability_a",
    oracle_id: str = "kem_encaps_badrng",
    field: str = "rng",
    finding_class: str = "malleability",
) -> Path:
    artifact = eval_root / "campaigns" / f"liboqs-{version}" / "workspace" / "results" / primitive / finding_id
    artifact.mkdir(parents=True, exist_ok=True)
    finding = {
        "version": 1,
        "finding_id": finding_id,
        "job_id": f"pqcfuzz_eval_{primitive}_liboqs_{version}",
        "pair_id": f"liboqs_{version}_self_reference_{primitive}",
        "algorithm": "ML-KEM-768" if primitive == "kem" else "ML-DSA-44",
        "oracle_suite": "metamorphic",
        "relation_mode": "single-target",
        "oracle_id": oracle_id,
        "finding_class": finding_class,
        "finding_subclass": "encaps_rng_ignored",
        "trace_path": str(artifact / "oracle_trace.json"),
        "artifact_dir": str(artifact),
        "replay_command": f"python3 src/replay/replay_one.py --input {artifact / 'structured_input.bin'}",
    }
    trace = {
        "version": 1,
        "oracle_suite": "metamorphic",
        "relation_mode": "single-target",
        "job_id": finding["job_id"],
        "pair_id": finding["pair_id"],
        "algorithm": finding["algorithm"],
        "oracle_id": oracle_id,
        "field": field,
        "expected_relation": "EXPECT_DIFFERENT",
        "observed_relation": "OBSERVED_EQUAL",
        "finding_class": finding_class,
        "finding_subclass": "encaps_rng_ignored",
        "baseline": {"status": "OK", "accepted": True},
        "mutated": {"status": "OK", "accepted": True},
        "findings": [{"class": finding_class, "subclass": "encaps_rng_ignored"}],
    }
    (artifact / "finding.json").write_text(json.dumps(finding) + "\n", encoding="utf-8")
    (artifact / "oracle_trace.json").write_text(json.dumps(trace) + "\n", encoding="utf-8")
    return artifact / "finding.json"


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def test_discovery_scans_eval_results_and_prunes_heavy_dirs(tmp_path: Path) -> None:
    eval_root = tmp_path / "pqcfuzz_eval"
    expected = write_finding(eval_root)
    ignored = eval_root / "campaigns" / "liboqs-0.8.0" / "workspace" / "build" / "ignored" / "finding.json"
    ignored.parent.mkdir(parents=True)
    ignored.write_text("{}\n", encoding="utf-8")

    assert find_finding_files(eval_root) == [expected]


def test_write_reports_preserves_campaign_summary_and_writes_finding_summary(tmp_path: Path) -> None:
    eval_root = tmp_path / "pqcfuzz_eval"
    write_finding(eval_root, finding_id="malleability_a")
    write_finding(eval_root, finding_id="malleability_b")
    output = tmp_path / "report"
    output.mkdir()
    campaign_summary = output / "summary.tsv"
    campaign_summary.write_text("campaign\tresult\nliboqs-0.8.0\tcompleted\n", encoding="utf-8")

    write_reports([eval_root], output, {"json", "tsv"}, trace_mode="exemplar")

    assert campaign_summary.read_text(encoding="utf-8") == "campaign\tresult\nliboqs-0.8.0\tcompleted\n"
    findings = read_tsv(output / "findings.tsv")
    assert len(findings) == 2
    assert all(row["field"] == "" for row in findings)
    summaries = read_tsv(output / "findings_summary.tsv")
    assert len(summaries) == 1
    assert summaries[0]["count"] == "2"
    assert summaries[0]["field"] == "rng"
    assert summaries[0]["expected_relation"] == "EXPECT_DIFFERENT"
    assert (output / "findings.json").exists()
    assert (output / "findings_summary.json").exists()
    assert (output / "0.8.0" / "findings_summary.tsv").exists()


def test_trace_mode_all_keeps_per_finding_trace_columns(tmp_path: Path) -> None:
    eval_root = tmp_path / "pqcfuzz_eval"
    write_finding(eval_root)
    output = tmp_path / "report"

    write_reports([eval_root], output, {"tsv"}, trace_mode="all")

    findings = read_tsv(output / "findings.tsv")
    assert findings[0]["field"] == "rng"
    assert findings[0]["baseline_status"] == "OK"


def test_summary_only_mode_skips_raw_finding_outputs(tmp_path: Path) -> None:
    eval_root = tmp_path / "pqcfuzz_eval"
    write_finding(eval_root)
    output = tmp_path / "report"

    write_reports([eval_root], output, {"json", "tsv"}, trace_mode="exemplar", findings_mode="summary-only")

    assert not (output / "findings.tsv").exists()
    assert not (output / "findings.json").exists()
    summaries = read_tsv(output / "findings_summary.tsv")
    assert len(summaries) == 1
    assert summaries[0]["count"] == "1"
    assert summaries[0]["summary_mode"] == "exact"


def test_fast_summary_counts_artifact_dirs_and_reads_exemplars(tmp_path: Path) -> None:
    eval_root = tmp_path / "pqcfuzz_eval"
    write_finding(
        eval_root,
        finding_id="confirmed_semantic_bug_0123456789abcdef",
        oracle_id="kem_decaps_c",
        finding_class="confirmed_semantic_bug",
    )
    write_finding(
        eval_root,
        finding_id="confirmed_semantic_bug_fedcba9876543210",
        oracle_id="kem_decaps_c",
        finding_class="confirmed_semantic_bug",
    )
    output = tmp_path / "report"

    write_reports([eval_root], output, {"tsv"}, trace_mode="exemplar", findings_mode="fast-summary")

    assert not (output / "findings.tsv").exists()
    summaries = read_tsv(output / "findings_summary.tsv")
    assert len(summaries) == 1
    assert summaries[0]["count"] == "2"
    assert summaries[0]["summary_mode"] == "fast-directory"
    assert summaries[0]["group_key"] == "0.8.0|kem|confirmed_semantic_bug"
    assert summaries[0]["finding_class"] == "confirmed_semantic_bug"
    assert summaries[0]["oracle_id"] == "kem_decaps_c"

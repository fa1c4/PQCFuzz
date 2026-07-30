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
    legacy: bool = False,
    oracle_semantics_version: int | None = None,
) -> Path:
    artifact = eval_root / "campaigns" / f"liboqs-{version}" / "workspace" / "results" / primitive / finding_id
    artifact.mkdir(parents=True, exist_ok=True)
    semantics_version = None if legacy else (oracle_semantics_version or 4)
    artifact_version = 1 if legacy else semantics_version
    finding = {
        "version": artifact_version,
        "oracle_semantics_version": semantics_version,
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
        "evidence_kind": "semantic",
        "fingerprint": "test-fingerprint",
        "validation_state": "validated" if not legacy else "invalidated",
        "validated": not legacy,
        "validation_attempts": 1 if not legacy else 0,
        "validation_failure_reason": "" if not legacy else "oracle_semantics_version_mismatch",
    }
    trace = {
        "version": artifact_version,
        "oracle_semantics_version": semantics_version,
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
        "configured_algorithm": finding["algorithm"],
        "adapter_algorithm": finding["algorithm"],
        "disposition": "raw_candidate",
        "baseline_setup_valid": True,
        "mutated_setup_valid": True,
        "baseline_adapter_entered": True,
        "baseline_target_entered": True,
        "mutated_adapter_entered": True,
        "mutated_target_entered": True,
        "relation_evaluable": True,
        "intervention_supported": True,
        "intervention_effective": True,
        "baseline": {"status": "OK", "accepted": True},
        "mutated": {"status": "OK", "accepted": True},
        "diagnostics": [],
        "findings": [
            {
                "evidence_kind": "semantic",
                "class": finding_class,
                "subclass": "encaps_rng_ignored",
                "source_phase": "fuzz",
                "fingerprint": "test-fingerprint",
            }
        ],
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


def test_legacy_findings_are_invalidated_and_not_counted(tmp_path: Path) -> None:
    eval_root = tmp_path / "pqcfuzz_eval"
    write_finding(eval_root, legacy=True)
    output = tmp_path / "report"

    write_reports([eval_root], output, {"tsv"}, trace_mode="all")

    assert read_tsv(output / "findings.tsv") == []
    diagnostics = read_tsv(output / "diagnostics.tsv")
    assert diagnostics[0]["invalidated"] == "true"
    assert diagnostics[0]["invalidation_reasons"] == "legacy_semantics"


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
    assert summaries[0]["group_key"] == "0.8.0|4|v4|kem|confirmed_semantic_bug"
    assert summaries[0]["finding_class"] == "confirmed_semantic_bug"
    assert summaries[0]["oracle_id"] == "kem_decaps_c"


def test_fast_summary_prefers_grouped_counter_counts(tmp_path: Path) -> None:
    eval_root = tmp_path / "pqcfuzz_eval"
    finding_path = write_finding(
        eval_root,
        finding_id="malleability_0123456789abcdef",
        oracle_id="kem_keygen_badrng",
    )
    artifact = finding_path.parent
    counter = artifact.parent / "finding_counts.tsv"
    counter.write_text(
        "\t".join(
            [
                "count",
                "group_key",
                "finding_id",
                "oracle_semantics_version",
                "validated",
                "finding_class",
                "finding_subclass",
                "exemplar_artifact_path",
                "exemplar_replay_command",
            ]
        )
        + "\n"
        + "\t".join(
            [
                "42",
                "ML-KEM-768|kem|metamorphic|single-target|kem_keygen_badrng|rng|EXPECT_DIFFERENT|OBSERVED_EQUAL|malleability|encaps_rng_ignored|OK|OK",
                artifact.name,
                "4",
                "true",
                "malleability",
                "encaps_rng_ignored",
                str(artifact),
                f"python3 src/replay/replay_one.py --input {artifact / 'structured_input.bin'}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "report"

    write_reports([eval_root], output, {"tsv"}, trace_mode="exemplar", findings_mode="fast-summary")

    summaries = read_tsv(output / "findings_summary.tsv")
    assert len(summaries) == 1
    assert summaries[0]["count"] == "42"
    assert summaries[0]["summary_mode"] == "grouped-counter"
    assert summaries[0]["oracle_id"] == "kem_keygen_badrng"


def test_fast_summary_uses_counter_fields_when_exemplar_is_missing(tmp_path: Path) -> None:
    eval_root = tmp_path / "pqcfuzz_eval"
    result_dir = eval_root / "campaigns" / "liboqs-0.14.0" / "workspace" / "results" / "kem"
    result_dir.mkdir(parents=True)
    missing_artifact = result_dir / "malleability_missing"
    counter = result_dir / "finding_counts.tsv"
    counter.write_text(
        "\t".join(
            [
                "count",
                "group_key",
                "finding_id",
                "oracle_semantics_version",
                "validated",
                "algorithm",
                "primitive",
                "oracle_suite",
                "relation_mode",
                "oracle_id",
                "field",
                "expected_relation",
                "observed_relation",
                "finding_class",
                "finding_subclass",
                "baseline_status",
                "mutated_status",
                "exemplar_artifact_path",
                "exemplar_replay_command",
            ]
        )
        + "\n"
        + "\t".join(
            [
                "17",
                "ML-KEM-768|kem|metamorphic|single-target|kem_decaps_c|ciphertext|EXPECT_DIFFERENT|OBSERVED_EQUAL|malleability|ciphertext_malleability|OK|OK",
                "malleability_missing",
                "4",
                "true",
                "ML-KEM-768",
                "kem",
                "metamorphic",
                "single-target",
                "kem_decaps_c",
                "ciphertext",
                "EXPECT_DIFFERENT",
                "OBSERVED_EQUAL",
                "malleability",
                "ciphertext_malleability",
                "OK",
                "OK",
                str(missing_artifact),
                "python3 src/replay/replay_one.py --input missing.bin",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "report"

    write_reports([eval_root], output, {"tsv"}, trace_mode="exemplar", findings_mode="fast-summary")

    summaries = read_tsv(output / "findings_summary.tsv")
    assert len(summaries) == 1
    assert summaries[0]["count"] == "17"
    assert summaries[0]["summary_mode"] == "grouped-counter"
    assert summaries[0]["version"] == "0.14.0"
    assert summaries[0]["algorithm"] == "ML-KEM-768"
    assert summaries[0]["oracle_id"] == "kem_decaps_c"
    assert summaries[0]["field"] == "ciphertext"
    assert summaries[0]["baseline_status"] == "OK"
    assert summaries[0]["exemplar_artifact_path"] == str(missing_artifact)


def test_v3_and_v4_findings_are_kept_in_separate_semantic_lanes(tmp_path: Path) -> None:
    eval_root = tmp_path / "pqcfuzz_eval"
    write_finding(eval_root, finding_id="legacy", oracle_semantics_version=3)
    write_finding(eval_root, finding_id="v4", oracle_semantics_version=4)
    output = tmp_path / "report"

    write_reports([eval_root], output, {"tsv"}, trace_mode="all")

    summaries = read_tsv(output / "findings_summary.tsv")
    diagnostics = read_tsv(output / "diagnostics.tsv")
    assert len(summaries) == 1
    assert summaries[0]["oracle_semantics_version"] == "4"
    assert len(diagnostics) == 1
    assert diagnostics[0]["oracle_semantics_version"] == "3"
    assert diagnostics[0]["invalidation_reasons"] == "legacy_semantics"

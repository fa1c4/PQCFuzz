from __future__ import annotations

import importlib.util
import json
import sys
from argparse import Namespace
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src" / "reporting"))
from write_report import write_reports  # noqa: E402

MODULE_PATH = REPO_ROOT / "scripts" / "collect_sanitizer_findings.py"
SPEC = importlib.util.spec_from_file_location("collect_sanitizer_findings", MODULE_PATH)
assert SPEC and SPEC.loader
COLLECTOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COLLECTOR
SPEC.loader.exec_module(COLLECTOR)


def args_for(tmp_path: Path, log: Path) -> Namespace:
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"seed")
    return Namespace(
        log=str(log),
        result_dir=str(tmp_path / "results" / "mldsa44"),
        summary_file=str(tmp_path / "summary.json"),
        target="mldsa44",
        version="0.14.0",
        algorithm="ML-DSA-44",
        primitive="sig",
        job_id="pqcfuzz_eval_mldsa44_liboqs_0.14.0",
        pair_id="liboqs_0.14.0_mldsa44_single_target",
        oracle_suite="metamorphic",
        relation_mode="single-target",
        phase="fuzz",
        binary="/tmp/pqcfuzz_mldsa44",
        seed_file=str(seed),
    )


def test_collector_deduplicates_ubsan_and_writes_reportable_artifacts(tmp_path: Path) -> None:
    log = tmp_path / "fuzz.log"
    report = "/work/sign.c:319:19: runtime error: null pointer passed as argument 2"
    log.write_text(report + "\n" + report + "\n", encoding="utf-8")

    summary = COLLECTOR.collect(args_for(tmp_path, log))

    assert summary["count"] == 1
    finding_path = Path(summary["artifacts"][0])
    finding = json.loads(finding_path.read_text(encoding="utf-8"))
    trace = json.loads((finding_path.parent / "oracle_trace.json").read_text(encoding="utf-8"))
    assert finding["evidence_kind"] == "sanitizer"
    assert finding["validated"] is False
    assert finding["validation_state"] == "raw"
    assert finding["finding_class"] == "ub"
    assert finding["finding_subclass"] == "undefined_behavior"
    assert trace["observed_relation"] == "SANITIZER_DIAGNOSTIC"
    assert (finding_path.parent / "structured_input.bin").read_bytes() == b"seed"

    output = tmp_path / "report"
    write_reports([tmp_path / "results"], output, {"tsv"}, trace_mode="all")
    diagnostics = (output / "diagnostics.tsv").read_text(encoding="utf-8")
    findings = (output / "findings.tsv").read_text(encoding="utf-8")
    assert "undefined_behavior" in diagnostics
    assert "undefined_behavior" not in findings

    fast_output = tmp_path / "fast-report"
    write_reports([tmp_path / "results"], fast_output, {"tsv"}, trace_mode="exemplar", findings_mode="fast-summary")
    fast_summary = (fast_output / "findings_summary.tsv").read_text(encoding="utf-8")
    assert "undefined_behavior" not in fast_summary


def test_collector_keeps_distinct_sanitizer_signatures(tmp_path: Path) -> None:
    log = tmp_path / "fuzz.log"
    log.write_text(
        "ERROR: AddressSanitizer: heap-use-after-free /work/foo.cc:10:2\n"
        "WARNING: MemorySanitizer: use-of-uninitialized-value /work/bar.cc:20:3\n",
        encoding="utf-8",
    )

    summary = COLLECTOR.collect(args_for(tmp_path, log))

    assert summary["count"] == 2
    assert summary["sanitizers"] == ["address", "memory"]


def test_collector_prefers_the_asan_summary_over_the_matching_error_line(tmp_path: Path) -> None:
    log = tmp_path / "fuzz.log"
    log.write_text(
        "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x123\n"
        "SUMMARY: AddressSanitizer: heap-use-after-free /work/foo.cc:10:2\n",
        encoding="utf-8",
    )

    summary = COLLECTOR.collect(args_for(tmp_path, log))

    assert summary["count"] == 1

#!/usr/bin/env python3
"""Turn recoverable sanitizer diagnostics into PQCFuzz finding artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path


UBSAN = re.compile(r"^(?P<location>.+?):\s+runtime error:\s+(?P<message>.+)$")
ASAN = re.compile(r"(?:ERROR|SUMMARY): AddressSanitizer:\s+(?P<message>.+)$")
MSAN = re.compile(r"(?:WARNING|SUMMARY): MemorySanitizer:\s+(?P<message>.+)$")
LOCATION = re.compile(r"(?P<location>(?:/[^\s:]+|[A-Za-z]:[^\s:]+):\d+(?::\d+)?)")


@dataclass(frozen=True)
class Finding:
    sanitizer: str
    location: str
    message: str
    evidence: str

    @property
    def fingerprint(self) -> str:
        material = "\x1f".join((self.sanitizer, self.location, self.message)).encode("utf-8")
        return hashlib.sha256(material).hexdigest()[:16]


def normalized_message(value: str) -> str:
    return " ".join(value.split())


def location_from_message(message: str) -> str:
    match = LOCATION.search(message)
    return match.group("location") if match else ""


def parse_findings(log_path: Path) -> list[Finding]:
    findings: dict[tuple[str, str, str], Finding] = {}
    fallback: dict[str, list[Finding]] = {"address": [], "memory": []}
    for raw in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        match = UBSAN.match(line)
        if match:
            finding = Finding(
                sanitizer="undefined",
                location=match.group("location"),
                message=normalized_message(match.group("message")),
                evidence=raw,
            )
        else:
            match = ASAN.search(line)
            if match:
                message = normalized_message(match.group("message"))
                finding = Finding("address", location_from_message(message), message, raw)
                if "SUMMARY:" not in line:
                    fallback["address"].append(finding)
                    continue
            else:
                match = MSAN.search(line)
                if not match:
                    continue
                message = normalized_message(match.group("message"))
                finding = Finding("memory", location_from_message(message), message, raw)
                if "SUMMARY:" not in line:
                    fallback["memory"].append(finding)
                    continue
        findings.setdefault((finding.sanitizer, finding.location, finding.message), finding)
    seen_sanitizers = {finding.sanitizer for finding in findings.values()}
    for sanitizer, entries in fallback.items():
        if sanitizer in seen_sanitizers:
            continue
        for finding in entries:
            findings.setdefault((finding.sanitizer, finding.location, finding.message), finding)
    return [findings[key] for key in sorted(findings)]


def read_json(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def artifact_payload(args: argparse.Namespace, finding: Finding, artifact_dir: Path) -> tuple[dict[str, object], dict[str, object]]:
    input_path = artifact_dir / "structured_input.bin"
    replay_input = input_path if input_path.is_file() else Path(args.seed_file)
    replay_command = " ".join((shlex.quote(args.binary), shlex.quote(str(replay_input)))) if args.binary else ""
    finding_class = "ub" if finding.sanitizer == "undefined" else "memory_safety"
    finding_json: dict[str, object] = {
        "version": 4,
        "oracle_semantics_version": 4,
        "job_id": args.job_id,
        "pair_id": args.pair_id,
        "liboqs_version": args.version,
        "algorithm": args.algorithm,
        "primitive": args.primitive,
        "oracle_suite": args.oracle_suite,
        "relation_mode": args.relation_mode,
        "oracle_id": f"sanitizer_{finding.sanitizer}",
        "finding_id": f"sanitizer_{finding.sanitizer}_{finding.fingerprint}",
        "finding_class": finding_class,
        "finding_subclass": f"{finding.sanitizer}_behavior",
        "summary": finding.message,
        "source_phase": args.phase,
        "evidence_kind": "sanitizer",
        "fingerprint": finding.fingerprint,
        "sanitizer": finding.sanitizer,
        "source_location": finding.location,
        "artifact_dir": str(artifact_dir),
        "trace_path": str(artifact_dir / "oracle_trace.json"),
        "replay_command": replay_command,
        "validation_state": "raw",
        "validated": False,
        "validation_attempts": 0,
        "validation_failure_reason": "pending_fingerprint_replay",
    }
    trace: dict[str, object] = {
        "version": 4,
        "oracle_semantics_version": 4,
        "job_id": args.job_id,
        "pair_id": args.pair_id,
        "liboqs_version": args.version,
        "algorithm": args.algorithm,
        "oracle_suite": args.oracle_suite,
        "relation_mode": args.relation_mode,
        "oracle_id": finding_json["oracle_id"],
        "field": "memory-safety",
        "expected_relation": "NO_SANITIZER_DIAGNOSTIC",
        "observed_relation": "SANITIZER_DIAGNOSTIC",
        "finding_class": finding_class,
        "finding_subclass": finding_json["finding_subclass"],
        "disposition": "sanitizer_evidence",
        "baseline": {"status": "SANITIZER", "accepted": False},
        "mutated": {"status": "NOT_RUN", "accepted": False},
        "diagnostics": [finding.evidence],
        "findings": [
            {
                "evidence_kind": "sanitizer",
                "class": finding_class,
                "subclass": finding_json["finding_subclass"],
                "source_phase": args.phase,
                "fingerprint": finding.fingerprint,
            }
        ],
    }
    return finding_json, trace


def collect(args: argparse.Namespace) -> dict[str, object]:
    result_dir = Path(args.result_dir)
    evidence = parse_findings(Path(args.log))
    artifacts: list[str] = []
    for finding in evidence:
        artifact_dir = result_dir / f"sanitizer_{finding.sanitizer}_{finding.fingerprint}"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        if args.seed_file and Path(args.seed_file).is_file() and not (artifact_dir / "structured_input.bin").exists():
            shutil.copyfile(args.seed_file, artifact_dir / "structured_input.bin")
        finding_json, trace = artifact_payload(args, finding, artifact_dir)
        existing = read_json(artifact_dir / "sanitizer.json")
        phases = set(existing.get("phases", [])) if isinstance(existing.get("phases"), list) else set()
        phases.add(args.phase)
        sanitizer_record = {
            "sanitizer": finding.sanitizer,
            "source_location": finding.location,
            "message": finding.message,
            "evidence": finding.evidence,
            "phases": sorted(str(phase) for phase in phases),
            "log": args.log,
        }
        write_json(artifact_dir / "finding.json", finding_json)
        write_json(artifact_dir / "oracle_trace.json", trace)
        write_json(artifact_dir / "sanitizer.json", sanitizer_record)
        (artifact_dir / "stderr.txt").write_text(finding.evidence + "\n", encoding="utf-8")
        (artifact_dir / "exit_code.txt").write_text("0\n", encoding="utf-8")
        artifacts.append(str(artifact_dir / "finding.json"))

    summary = {
        "count": len(evidence),
        "sanitizers": sorted({finding.sanitizer for finding in evidence}),
        "artifacts": artifacts,
        "log": args.log,
        "phase": args.phase,
    }
    if args.summary_file:
        write_json(Path(args.summary_file), summary)
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--log", required=True)
    result.add_argument("--result-dir", required=True)
    result.add_argument("--summary-file")
    result.add_argument("--target", required=True)
    result.add_argument("--version", required=True)
    result.add_argument("--algorithm", required=True)
    result.add_argument("--primitive", required=True, choices=("kem", "sig"))
    result.add_argument("--job-id", required=True)
    result.add_argument("--pair-id", required=True)
    result.add_argument("--oracle-suite", required=True)
    result.add_argument("--relation-mode", required=True)
    result.add_argument("--phase", required=True, choices=("fuzz", "leak-check", "regression"))
    result.add_argument("--binary", default="")
    result.add_argument("--seed-file", default="")
    return result


def main() -> int:
    args = parser().parse_args()
    print(json.dumps(collect(args), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

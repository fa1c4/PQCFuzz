#!/usr/bin/env python3
"""Score oracle records against the DeepSeek design doc quality rubric (Section 43).

Each dimension is scored 0-2 from record metadata; a production oracle must
score at least 17/20 and must not score zero on source grounding, predicate,
verdict semantics, or evidence separation.

Usage:
    python3 scripts/check_oracle_rubric.py [--min-score 17] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SPECS_DIR = REPO_ROOT / "src" / "oracles" / "specs"
FIPS_FILES = {"ml_kem.json", "ml_dsa.json", "slh_dsa.json", "aigis_enc.json", "aigis_sig.json", "cross.json", "falcon.json", "ntru.json"}

EVIDENCE_CLASSES = {
    "NORMATIVE",
    "REFERENCE_DERIVED",
    "IMPLEMENTATION_OBSERVED",
    "ENGINEERING_RECOMMENDATION",
    "INFERENCE",
}
SOURCE_SECTION_RE = re.compile(r"(Section|§|Algorithm|FIPS|doc \d|ACVP|PQClean|PQMagic|kem\.c|poly\.c|sign\.c|packing\.c)")
REPRODUCIBILITY_RE = re.compile(r"(Section|§|Algorithm|commit|/|\.c\b|\.md\b)")


def score_record(record: dict[str, Any], *, fips: bool) -> dict[str, int]:
    claim = str(record.get("claim") or "")
    evidence = str(record.get("evidence_class") or "")
    source = str(record.get("source_reference") or "")
    limitations = record.get("limitations")
    limitations_ok = isinstance(limitations, list) and len(limitations) > 0
    controls = record.get("controls")
    controls = controls if isinstance(controls, dict) else {}
    positive = str(controls.get("positive_control") or "")
    negative = str(controls.get("negative_control") or "")
    comparator = str(record.get("comparator") or "")
    expected = str(record.get("expected_relation") or "")
    scope = record.get("scope")
    scope = scope if isinstance(scope, dict) else {}
    mutation = record.get("mutation")
    mutation = mutation if isinstance(mutation, dict) else ({"type": record.get("field")} if record.get("field") else {})

    scores: dict[str, int] = {}

    scores["source_grounding"] = 2 if source and SOURCE_SECTION_RE.search(source) else (1 if source else 0)
    profile_ok = bool(claim) and bool(record.get("algorithm_family")) and bool(record.get("primitive_type"))
    scores["profile_completeness"] = 2 if profile_ok and bool(scope.get("api_layer")) else (1 if claim else 0)
    scores["property_classification"] = 2 if evidence in EVIDENCE_CLASSES and limitations_ok else (
        1 if evidence in EVIDENCE_CLASSES else 0
    )
    has_generator = bool(mutation) and (not fips or bool(record.get("precondition")))
    scores["generator"] = 2 if has_generator else (1 if mutation else 0)
    scores["predicate"] = 2 if expected and comparator else (1 if expected else 0)
    scores["observations"] = 2 if positive and negative else (1 if positive or negative else 0)
    scores["verdict_semantics"] = 2 if evidence in EVIDENCE_CLASSES and limitations_ok else (
        1 if evidence in EVIDENCE_CLASSES else 0
    )
    scores["evidence_separation"] = 2 if evidence in EVIDENCE_CLASSES and source and limitations_ok else (
        1 if evidence in EVIDENCE_CLASSES and source else 0
    )
    scores["controls"] = 2 if positive and negative else (1 if positive or negative else 0)
    scores["reproducibility"] = 2 if source and REPRODUCIBILITY_RE.search(source) else (1 if source else 0)
    return scores


def iter_records() -> list[tuple[str, dict[str, Any], bool]]:
    records: list[tuple[str, dict[str, Any], bool]] = []
    for path in sorted(SPECS_DIR.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        fips = path.name in FIPS_FILES
        for record in payload.get("oracles", []):
            records.append((f"{path.name}:{record.get('oracle_id', '?')}", record, fips))
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min-score", type=int, default=17)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    rows = []
    failures: list[str] = []
    for label, record, fips in iter_records():
        scores = score_record(record, fips=fips)
        total = sum(scores.values())
        zero_forbidden = any(
            scores[dimension] == 0
            for dimension in ("source_grounding", "predicate", "verdict_semantics", "evidence_separation")
        )
        passed = total >= args.min_score and not zero_forbidden
        rows.append({"record": label, "total": total, "scores": scores, "passed": passed})
        if not passed:
            failures.append(f"{label} scored {total}/20 (zero on a mandatory dimension: {zero_forbidden})")

    if args.json:
        print(json.dumps(rows, indent=2, sort_keys=True))
    else:
        for row in rows:
            status = "ok" if row["passed"] else "FAIL"
            print(f"{status:4} {row['total']:2}/20 {row['record']}")

    if failures:
        print(f"\n{len(failures)} oracle record(s) below the rubric floor:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"\nall {len(rows)} oracle records scored at least {args.min_score}/20", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

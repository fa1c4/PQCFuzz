#!/usr/bin/env python3
"""Classify PQCFuzz oracle traces into finding classes."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


FINDING_CLASSES = {
    "malleability",
    "non_malleability",
    "crash",
    "hang",
    "unsupported",
    "confirmed_semantic_bug",
    "potential_crypto_vuln",
    "memory_safety",
    "ub",
    "timeout",
    "api_policy_difference",
}


def classify_trace(trace: dict[str, Any]) -> str | None:
    statuses = [
        call.get("status")
        for subtest in trace.get("subtests", [])
        for call in subtest.get("calls", [])
        if isinstance(call, dict)
    ]
    for item in trace.get("findings", []):
        finding_class = item.get("class")
        if finding_class in FINDING_CLASSES:
            return finding_class
    if trace.get("finding_class") in FINDING_CLASSES:
        return str(trace["finding_class"])
    if "CRASH" in statuses:
        return "memory_safety"
    if "TIMEOUT" in statuses:
        return "hang"
    expected = trace.get("expected_relation")
    observed = trace.get("observed_relation")
    if expected == "EXPECT_DIFFERENT" and observed == "OBSERVED_EQUAL":
        return "malleability"
    if expected == "EXPECT_EQUAL" and observed == "OBSERVED_DIFFERENT":
        return "non_malleability"
    if any(not subtest.get("passed", True) for subtest in trace.get("subtests", [])):
        return "confirmed_semantic_bug"
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", help="oracle_trace.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    trace = json.loads(Path(args.trace).read_text(encoding="utf-8"))
    finding_class = classify_trace(trace)
    print(finding_class or "no_finding")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

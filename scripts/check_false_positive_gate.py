#!/usr/bin/env python3
"""Validate the false-positive remediation Gate A summary."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SECURITY_SMOKE_ORACLES = {
    "kem_decaps_c",
    "sig_verify_m",
    "sig_verify_sig",
    "sig_verify_pk",
}
CONTEXT_CASES = {"0", "1", "255", "256"}
FUNNEL_FIELDS = {
    "total_inputs",
    "baseline_setup_valid",
    "mutation_effective",
    "mutated_target_reached",
    "relation_evaluable",
}


def _as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bool(value: Any) -> bool:
    return bool(value) if isinstance(value, bool) else False


def _count(summary: dict[str, Any], key: str) -> int:
    counts = _as_mapping(summary.get("finding_counts"))
    if key in counts:
        return _int(counts.get(key))
    return _int(summary.get(f"{key}_count"))


def _semantics_versions(summary: dict[str, Any]) -> set[int]:
    versions: set[int] = set()
    if "oracle_semantics_version" in summary:
        versions.add(_int(summary.get("oracle_semantics_version"), -1))
    for value in _as_list(summary.get("artifact_semantics_versions")):
        versions.add(_int(value, -1))
    return versions


def check_gate(raw: dict[str, Any]) -> list[str]:
    summary = _as_mapping(raw.get("gate_a")) or raw
    failures: list[str] = []

    full_suite = _as_mapping(summary.get("full_test_suite"))
    if full_suite.get("status") != "passed":
        failures.append("full_test_suite.status must be passed")
    if _int(full_suite.get("failed")) != 0:
        failures.append("full_test_suite.failed must be 0")
    skip_key = "unexpected_skips" if "unexpected_skips" in full_suite else "skipped"
    if _int(full_suite.get(skip_key)) != 0:
        failures.append(f"full_test_suite.{skip_key} must be 0")
    if _bool(full_suite.get("timed_out")):
        failures.append("full_test_suite.timed_out must be false")
    if _int(full_suite.get("compile_failures")) != 0:
        failures.append("full_test_suite.compile_failures must be 0")

    versions = _semantics_versions(summary)
    if versions != {4}:
        failures.append("all artifact semantics versions must be exactly 4")

    for key in (
        "unsupported",
        "unknown_oracle",
        "noop_mutation",
        "baseline_reject_verify",
        "mutated_target_not_reached",
    ):
        if _count(summary, key) != 0:
            failures.append(f"finding_counts.{key} must be 0")

    smoke = _as_mapping(summary.get("smoke_matrix"))
    if smoke.get("liboqs_version") != "0.14.0":
        failures.append("smoke_matrix.liboqs_version must be 0.14.0")
    smoke_oracles = set(str(item) for item in _as_list(smoke.get("security_oracles")))
    if not SECURITY_SMOKE_ORACLES.issubset(smoke_oracles):
        failures.append("smoke_matrix.security_oracles is missing the bounded security set")

    enabled_oracles = _as_list(summary.get("enabled_oracles"))
    if not enabled_oracles:
        failures.append("enabled_oracles must be non-empty")
    for index, oracle in enumerate(enabled_oracles):
        item = _as_mapping(oracle)
        label = item.get("oracle_id") or f"enabled_oracles[{index}]"
        for key in ("job_id", "seed", "budget_seconds", "run_dir"):
            if not item.get(key):
                failures.append(f"{label}.{key} must be present")
        if _int(item.get("budget_seconds")) <= 0:
            failures.append(f"{label}.budget_seconds must be positive")

    funnel = _as_mapping(summary.get("security_oracle_funnel"))
    for oracle_id in sorted(SECURITY_SMOKE_ORACLES):
        item = _as_mapping(funnel.get(oracle_id))
        if not item:
            failures.append(f"security_oracle_funnel.{oracle_id} must be present")
            continue
        for key in sorted(FUNNEL_FIELDS):
            if _int(item.get(key)) <= 0:
                failures.append(f"security_oracle_funnel.{oracle_id}.{key} must be > 0")

    context = _as_mapping(summary.get("context_contract"))
    if set(context) != CONTEXT_CASES:
        failures.append("context_contract must contain exactly 0, 1, 255, and 256")
    for key, value in context.items():
        if value not in {"passed", "matched", True}:
            failures.append(f"context_contract.{key} must match the declared capability contract")

    rng = _as_mapping(summary.get("rng_scope"))
    for key in ("restoration", "nesting", "non_periodicity", "causal_streams"):
        if not _bool(rng.get(key)):
            failures.append(f"rng_scope.{key} must be true")

    sanitizer = _as_mapping(summary.get("sanitizer_process_validation"))
    for key in ("fingerprint_required", "exact_provenance_required"):
        if not _bool(sanitizer.get(key)):
            failures.append(f"sanitizer_process_validation.{key} must be true")

    reporting = _as_mapping(summary.get("reporting"))
    if not _bool(reporting.get("reconciled")):
        failures.append("reporting.reconciled must be true")
    totals = [_int(reporting.get(key)) for key in ("full_confirmed", "summary_confirmed", "fast_confirmed")]
    if len(set(totals)) != 1:
        failures.append("confirmed report totals must reconcile across full, summary-only, and fast-summary modes")

    if _int(summary.get("harness_errors")) != 0:
        failures.append("harness_errors must be 0")

    leak = _as_mapping(summary.get("leak_detection"))
    state = leak.get("state")
    if state not in {"on", "off", "auto"}:
        failures.append("leak_detection.state must be explicit")
    if state == "off" and _bool(leak.get("no_leaks_claim")):
        failures.append("disabled leak detection cannot support a no-leaks claim")

    if not _bool(summary.get("schemas_valid")):
        failures.append("schemas_valid must be true")

    regressions = _as_mapping(summary.get("false_positive_regressions"))
    if _int(regressions.get("xfail_count")) != 0:
        failures.append("false_positive_regressions.xfail_count must be 0")

    if _bool(summary.get("long_campaign_run")):
        failures.append("long_campaign_run must be false for Gate A")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary_json", type=Path)
    args = parser.parse_args(argv)

    with args.summary_json.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        print("Gate A failed: summary root must be an object", file=sys.stderr)
        return 1

    failures = check_gate(raw)
    if failures:
        print(f"Gate A failed with {len(failures)} issue(s):", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("Gate A passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

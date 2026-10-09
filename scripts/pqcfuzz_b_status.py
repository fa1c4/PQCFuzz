#!/usr/bin/env python3
"""Summarize B-tier SOP stages from pinned inventory and verified run artifacts."""
import json
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "workspace/b_targets_sop"
HASH_IDS = {"hash-05", "hash-10", "hash-11", "hash-14", "hash-18",
            "hash-19", "hash-20", "hash-27", "hash-30", "hash-31", "hash-32"}
PROBE_IDS = {"kem-37", "sign-02", "kex-09"}


def campaign_run(target):
    runs = ROOT / "workspace" / target / "runs"
    matches = []
    for path in runs.iterdir():
        report = path / "report.json"
        if report.is_file():
            data = json.loads(report.read_text())
            if data["counts"]["pass"] > 0:
                matches.append((path, data))
    if not matches:
        raise RuntimeError(f"no campaign run for {target}")
    return max(matches, key=lambda row: row[0].name)


def controls(run):
    trace = json.loads((run / "trace.json").read_text())
    by_oracle = {}
    for entry in trace:
        oracle = entry["oracle"]
        by_oracle.setdefault(oracle, []).append(entry)
    for oracle, rows in by_oracle.items():
        smoke = [row for row in rows if row["mode"] == "smoke"]
        campaign = [row for row in rows if row["mode"] == "campaign"]
        if len(smoke) != 2 or len(campaign) != 18:
            raise RuntimeError(f"unexpected smoke/campaign counts: {run} {oracle}")
        good = next((x for x in smoke if x["verdict"] == "pass" and
                     x.get("fault_relation", {}).get("holds") is False), None)
        bad = next((x for x in smoke if x["verdict"] == "inconclusive"), None)
        if good is None or bad is None or any(x["verdict"] != "pass" for x in campaign):
            raise RuntimeError(f"failed oracle controls: {run} {oracle}")
    return sorted(by_oracle)


def main():
    inventory = json.loads((WORK / "inventory.json").read_text())
    matrix = {x["target"]: x for x in json.loads((WORK / "api_matrix.json").read_text())}
    probes = {x["target"]: x for x in
              json.loads((WORK / "probes/asymmetric/report.json").read_text())}
    rows = []
    for item in inventory:
        target = item["target"]
        api = matrix[target]
        row = {key: item[key] for key in
               ("target", "name", "primitive", "score", "source_sha256", "document_sha256")}
        row["reference_header_count"] = len(api["primary_reference_headers"])
        primary_name = {"hash": "CryptHash_AlgorithmInstance.h",
                        "sign": "SIG_AlgorithmInstance.h",
                        "kem": "KEM_AlgorithmInstance.h",
                        "kex": "KEX_AlgorithmInstance.h"}[item["primitive"]]
        top_headers = [header for header in api["primary_reference_headers"]
                       if header["path"].endswith(primary_name)]
        row["top_level_standard_header_count"] = len(top_headers)
        row["declared_top_level_functions"] = sorted({function for header in top_headers
                                                      for function in header["functions"]})
        row["submitted_vector_files"] = len(api["submitted_vector_files"])
        row["sop_completion"] = False
        if target in HASH_IDS:
            run, report = campaign_run(target)
            command = ["python3", str(ROOT / "scripts/pqcfuzz_target.py"),
                       "verify", "--run", str(run)]
            checked = subprocess.run(command, capture_output=True, text=True, check=True)
            integrity = json.loads(checked.stdout)["integrity"]
            if integrity != "ok" or report["stage"] != "ready" or \
                    report["counts"]["harness_error"] or report["counts"]["counterexample_candidate"]:
                raise RuntimeError(f"run gate failed: {run}")
            oracles = controls(run)
            kat = json.loads((WORK / "full_kat" / f"{target}.json").read_text())
            if kat["run"] != str(run.relative_to(ROOT)) or kat["records"] != 4097 or \
                    kat["status"] != "submitted_kat_match":
                raise RuntimeError(f"full KAT gate failed: {target}")
            row.update(stage="first_instance_campaign_ready", parameter_set=report["parameter_set"],
                       registered_oracles=oracles, campaign_run=str(run.relative_to(ROOT)),
                       campaign_counts=report["counts"], evidence_integrity=integrity,
                       evidence_class=report["evidence_class"],
                       full_submitted_kat=kat,
                       remaining="other instances/functions, full KAT suite and coverage instrumentation")
        elif target in PROBE_IDS:
            if probes[target]["status"] != "submitted_vector_calls_match" or \
                    probes[target]["vector_count"] != 10 or probes[target]["vector_matches"] != 10:
                raise RuntimeError(f"probe failed: {target}")
            row.update(stage="submitted_vector_api_diagnostic", registered_oracles=[],
                       diagnostic_vector_count=probes[target]["vector_count"],
                       evidence="workspace/b_targets_sop/probes/asymmetric/report.json",
                       remaining="target design, controls, registration, preflight, smoke and campaign")
        else:
            row.update(stage="api_and_vector_inventory", registered_oracles=[],
                       evidence="workspace/b_targets_sop/api_matrix.json",
                       remaining="PDF claim extraction, target design, build, controls, SOP campaign and coverage")
        rows.append(row)
    if len(rows) != 74:
        raise RuntimeError(f"expected 74 B targets, found {len(rows)}")
    output = WORK / "status.json"
    output.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"targets": len(rows),
                      "stages": dict(Counter(x["stage"] for x in rows)),
                      "campaign_pass": sum(x.get("campaign_counts", {}).get("pass", 0) for x in rows),
                      "status": str(output)}))


if __name__ == "__main__":
    main()

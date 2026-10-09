#!/usr/bin/env python3
"""Audit one complete A-tier batch and refresh the first-instance SOP status."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path)
    args = parser.parse_args()
    summary_path = args.summary.resolve()
    if not summary_path.is_relative_to(ROOT / "workspace/a_targets_fuzz/runs"):
        raise SystemExit("summary must be in A-tier workspace")
    summary = json.loads(summary_path.read_text())
    rows = json.loads((ROOT / "workspace/a_targets_sop/status.json").read_text())
    inventory = {x["target"]: x for x in
                 json.loads((ROOT / "workspace/a_targets_sop/inventory.json").read_text())}
    completed = {x["target"]: x for x in summary["completed"]}
    if (summary["status"] != "complete" or summary["failures"] or
            summary["pending_targets"] or len(completed) != 33 or
            set(completed) != set(inventory) or len(summary["completed"]) != 33):
        raise SystemExit("batch is not a complete 33-target A-tier campaign")
    total = 0
    for row in rows:
        item = completed[row["target"]]
        run = ROOT / item["run"]
        manifest = json.loads((run / "manifest.json").read_text())
        trace = json.loads((run / "trace.json").read_text())
        report = json.loads((run / "report.json").read_text())
        oracles = manifest["oracle_ids"]
        if (item["integrity"] != "ok" or report["stage"] != "ready" or
                report["evidence_class"] != "unverified_spec" or
                report["confirmed_findings"] != 0 or report["replay_status"] != "not_run" or
                any(v for k, v in report["counts"].items() if k != "pass") or
                report["counts"]["pass"] != len(oracles) * item["iterations_per_oracle"]):
            raise SystemExit("run verdict mismatch: " + row["target"])
        for oracle in oracles:
            entries = [x for x in trace if x["oracle"] == oracle]
            if (len(entries) != item["iterations_per_oracle"] + 2 or
                    [(x["kind"], x["verdict"]) for x in entries[:2]] !=
                    [("positive", "pass"), ("negative", "inconclusive")] or
                    entries[0].get("fault_relation", {}).get("holds") is not False or
                    any(x["verdict"] != "pass" for x in entries[2:])):
                raise SystemExit("control/campaign mismatch: " + row["target"] + "/" + oracle)
            if row["primitive"] != "hash":
                indices = {x["case"]["baseline"]["record_index"] for x in entries[2:]}
                if indices != set(range(10)):
                    raise SystemExit("incomplete submitted KAT index sweep: " + row["target"])
        row.update(stage="first_instance_campaign_ready", parameter_set=item["parameter_set"],
                   registered_oracles=len(oracles), campaign_run=item["run"],
                   counts=item["counts"], evidence_class=item["evidence_class"],
                   source_sha256=inventory[row["target"]]["source_sha256"],
                   campaign_summary=str(summary_path.relative_to(ROOT)),
                   remaining=("other parameter sets, public APIs, additional applicable patterns, "
                              "full KAT corpus and function/branch coverage"))
        row.pop("evidence", None)
        total += report["counts"]["pass"]
    (ROOT / "workspace/a_targets_sop/status.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"targets": len(rows), "instances": len(completed), "pass": total,
                      "candidate": 0, "harness_error": 0,
                      "summary": str(summary_path.relative_to(ROOT))}))


if __name__ == "__main__":
    main()

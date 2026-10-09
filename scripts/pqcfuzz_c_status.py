#!/usr/bin/env python3
"""Verify and summarize all five C-tier first-slice SOP packages and controls."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "workspace/c_targets_sop"
EXPECTED = {"hash-22": ("Pavelor-512", "Pavelor-768", "Pavelor-1024"),
            "sign-33": ("VDOO-128", "VDOO-256", "VDOO-512"),
            "kem-17": ("hep-qc-1", "hep-qc-3", "hep-qc-5", "hep-qc-7"),
            "kex-01": ("ADKEX-128", "ADKEX-256", "ADKEX-512"),
            "kex-04": ("DKEX-128", "DKEX-256", "DKEX-512")}


def current_runs(target):
    selected = {}
    for path in (ROOT / "workspace" / target / "runs").iterdir():
        report = path / "report.json"
        if not report.is_file():
            continue
        value = json.loads(report.read_text())
        if value["counts"]["pass"]:
            instance = value["parameter_set"]
            if instance not in selected or path.name > selected[instance][0].name:
                selected[instance] = (path, value)
    return selected


def check_trace(run, report, iterations):
    trace = json.loads((run / "trace.json").read_text())
    by_oracle = {}
    for row in trace:
        by_oracle.setdefault(row["oracle"], []).append(row)
    expected_oracles = (3 if report["target"] == "sign-33" else
                        2 if report["target"] in ("hash-22", "kem-17") else 1)
    if len(by_oracle) != expected_oracles:
        raise RuntimeError(f"unexpected oracle count: {run}")
    for oracle, rows in by_oracle.items():
        smoke = [x for x in rows if x["mode"] == "smoke"]
        campaign = [x for x in rows if x["mode"] == "campaign"]
        if len(smoke) != 2 or len(campaign) != iterations:
            raise RuntimeError(f"unexpected case count: {run} {oracle}")
        positive = next((x for x in smoke if x["kind"] == "positive"), None)
        negative = next((x for x in smoke if x["kind"] == "negative"), None)
        if positive is None or negative is None or positive["verdict"] != "pass" or \
                positive.get("fault_relation", {}).get("holds") is not False or \
                negative["verdict"] != "inconclusive" or \
                any(x["verdict"] != "pass" for x in campaign):
            raise RuntimeError(f"control/campaign failure: {run} {oracle}")
    return sorted(by_oracle)


def main():
    inventory = {x["target"]: x for x in json.loads((WORK / "inventory.json").read_text())}
    status = []
    for target, instances in EXPECTED.items():
        runs = current_runs(target)
        if set(runs) != set(instances):
            raise RuntimeError(f"missing campaign instance: {target} {set(instances)-set(runs)}")
        for instance in instances:
            run, report = runs[instance]
            checked = subprocess.run(["python3", str(ROOT / "scripts/pqcfuzz_target.py"),
                                      "verify", "--run", str(run)],
                                     text=True, capture_output=True, check=True)
            if json.loads(checked.stdout)["integrity"] != "ok" or \
                    report["stage"] != "ready" or report["evidence_class"] != "unverified_spec" or \
                    report["replay_status"] != "not_run" or report["confirmed_findings"] != 0 or \
                    any(report["counts"][key] for key in ("counterexample_candidate", "harness_error")):
                raise RuntimeError(f"run report/integrity gate failed: {run}")
            iterations = 24 if target == "hash-22" else 10 if target.startswith("kex-") else 8
            oracles = check_trace(run, report, iterations)
            kat_path = (WORK / "full_kat" / f"{instance}.json" if target == "hash-22" else
                        WORK / "full_kat_api" / f"{instance}.json")
            kat = json.loads(kat_path.read_text())
            if kat["run"] != str(run.relative_to(ROOT)) or kat["status"] != "submitted_kat_match":
                raise RuntimeError(f"KAT diagnostic mismatch: {instance}")
            row = inventory[target]
            status.append({"target": target, "algorithm": report["algorithm"],
                           "primitive": row["primitive"], "parameter_set": instance,
                           "api": report["api"], "source_sha256": row["source_sha256"],
                           "document_sha256": row["document_sha256"],
                           "sop_stage": "first_slice_campaign_ready",
                           "registered_oracles": oracles, "campaign_run": str(run.relative_to(ROOT)),
                           "campaign_counts": report["counts"], "evidence_integrity": "ok",
                           "evidence_class": report["evidence_class"],
                           "full_submitted_kat": kat,
                           "all_public_functions_covered": False,
                           "limits": ("Only fixed-output CryptHash P1/P3; internal/source branch coverage unmeasured"
                                      if target == "hash-22" else
                                      "Public verification, message binding and fresh sign/verify on submitted keypairs; keygen only directly probed, wider malformed inputs untested"
                                      if target == "sign-33" else
                                      "Public submitted-vector decapsulation and seeded honest keygen/enc/dec; invalid ciphertext/fallback untested"
                                      if target == "kem-17" else
                                      "Only final role derivation on submitted transcript; init/pass generation and auth/replay untested")})
    output = WORK / "status.json"
    output.write_text(json.dumps(status, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"targets": len(EXPECTED), "instances": len(status),
                      "campaign_pass": sum(x["campaign_counts"]["pass"] for x in status),
                      "kat_api_calls": sum(x["full_submitted_kat"]["api_calls"] for x in status),
                      "status": str(output)}))


if __name__ == "__main__":
    main()

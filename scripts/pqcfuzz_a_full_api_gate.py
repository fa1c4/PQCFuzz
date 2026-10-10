#!/usr/bin/env python3
"""Run fresh SOP preflight, smoke/campaign and verify for registered A-tier APIs."""
import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import threading
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "workspace/a_targets_full_api/runs"


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(args, timeout):
    proc = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"rc={proc.returncode} stdout={proc.stdout[-1000:]} "
                           f"stderr={proc.stderr[-1000:]}")
    return json.loads(proc.stdout.splitlines()[-1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append")
    parser.add_argument("--iterations", type=int, default=2)
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args()
    if args.iterations < 1 or args.workers < 1:
        parser.error("iterations/workers must be positive")
    inventory = {x["target"] for x in json.loads(
        (ROOT / "workspace/a_targets_sop/inventory.json").read_text())}
    registry = json.loads((ROOT / "configs/targets.json").read_text())
    targets = [x for x in registry["targets"] if x["target"] in inventory]
    if len(targets) != 33:
        raise SystemExit("expected 33 A-tier targets")
    if args.target:
        unknown = set(args.target) - inventory
        if unknown:
            parser.error("unknown A-tier target(s): " + ",".join(sorted(unknown)))
        targets = [x for x in targets if x["target"] in set(args.target)]
    name = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    out = OUT / name
    out.mkdir(parents=True, exist_ok=False)
    lock = threading.Lock()
    status = {"run_id": name, "status": "running", "started_utc": utc(),
              "targets": len(targets), "registered_apis": sum(len(x["apis"]) for x in targets),
              "completed": [], "failures": [], "counts": {},
              "registry_sha256": sha(ROOT / "configs/targets.json"),
              "driver_sha256": sha(Path(__file__).resolve())}

    def save():
        temp = out / "progress.json.tmp"
        temp.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
        temp.replace(out / "progress.json")

    def event(kind, **payload):
        with lock:
            with (out / "events.jsonl").open("a") as log:
                log.write(json.dumps({"time_utc": utc(), "kind": kind, **payload}) + "\n")
                log.flush()
                os.fsync(log.fileno())
            save()

    save()

    def one(target):
        name = target["target"]
        for api in target["apis"]:
            for profile in api["profiles"]:
                selected = ["--target", name, "--algorithm", target["algorithm"],
                            "--parameter-set", api["parameter_set"],
                            "--api", api["name"], "--profile", profile["id"]]
                row = {"target": name, "algorithm": target["algorithm"],
                       "parameter_set": api["parameter_set"], "api": api["name"],
                       "profile": profile["id"]}
                try:
                    preflight = invoke([sys.executable, "scripts/pqcfuzz_target.py",
                                        "preflight", *selected], 180)
                    if preflight.get("stage") != "ready":
                        raise RuntimeError("preflight not ready")
                    seed = profile["seed"] + 20261010
                    result = invoke([sys.executable, "scripts/pqcfuzz_target.py",
                                     "run", *selected, "--iterations", str(args.iterations),
                                     "--seed", str(seed)], 900)
                    run = Path(result["run"]).resolve()
                    if not run.is_relative_to(ROOT / "workspace" / name / "runs"):
                        raise RuntimeError("run escaped target workspace")
                    checked = invoke([sys.executable, "scripts/pqcfuzz_target.py",
                                      "verify", "--run", str(run)], 180)
                    report = json.loads((run / "report.json").read_text())
                    trace = json.loads((run / "trace.json").read_text())
                    oracles = json.loads((run / "manifest.json").read_text())["oracle_ids"]
                    for oid in oracles:
                        rows = [x for x in trace if x["oracle"] == oid]
                        if (len(rows) != args.iterations + 2 or
                                [(x["kind"], x["verdict"]) for x in rows[:2]] !=
                                [("positive", "pass"), ("negative", "inconclusive")] or
                                rows[0].get("fault_relation", {}).get("holds") is not False):
                            raise RuntimeError("smoke controls invalid: " + oid)
                    if (result.get("stage") != "ready" or checked.get("integrity") != "ok" or
                            report.get("evidence_class") != "unverified_spec" or
                            report.get("replay_status") != "not_run" or
                            report.get("confirmed_findings") != 0 or
                            report.get("counts") != result.get("counts")):
                        raise RuntimeError("stage, evidence or identity mismatch")
                    item = {**row, "run": str(run.relative_to(ROOT)),
                            "oracles": oracles, "counts": report["counts"],
                            "integrity": "ok", "seed": seed}
                    with lock:
                        status["completed"].append(item)
                        for key, value in report["counts"].items():
                            status["counts"][key] = status["counts"].get(key, 0) + value
                    event("campaign", **item)
                except Exception as exc:
                    item = {**row, "error": str(exc)}
                    with lock:
                        status["failures"].append(item)
                    event("failure", **item)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.workers, len(targets))) as pool:
        futures = [pool.submit(one, target) for target in targets]
        for future in concurrent.futures.as_completed(futures):
            future.result()
    status["finished_utc"] = utc()
    status["status"] = "complete" if not status["failures"] else "partial"
    (out / "summary.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
    save()
    print(json.dumps({"summary": str((out / "summary.json").relative_to(ROOT)),
                      "status": status["status"], "completed": len(status["completed"]),
                      "failed": len(status["failures"]), "counts": status["counts"]}))
    return 0 if not status["failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

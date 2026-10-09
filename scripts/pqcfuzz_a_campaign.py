#!/usr/bin/env python3
"""Run one candidate-only SOP campaign for every currently registered A-tier instance."""
import argparse
import datetime as dt
import hashlib
import json
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "workspace/a_targets_fuzz"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(path)


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def select(primitive):
    inventory = {item["target"]: item for item in
                 json.loads((ROOT / "workspace/a_targets_sop/inventory.json").read_text())}
    registry = json.loads((ROOT / "configs/targets.json").read_text())
    if registry["schema_version"] != 2 or len(inventory) != 33:
        raise RuntimeError("unexpected A-tier inventory/registry")
    rows = []
    registered = set()
    registry_primitive = "signature" if primitive == "sign" else primitive
    for item in registry["targets"]:
        target = item["target"]
        if target not in inventory or (primitive != "all" and item["primitive"] != registry_primitive):
            continue
        registered.add(target)
        for api in item["apis"]:
            for profile in api["profiles"]:
                rows.append({"target": target, "primitive": item["primitive"],
                             "algorithm": item["algorithm"],
                             "parameter_set": api["parameter_set"],
                             "api": api["name"], "profile": profile["id"],
                             "base_seed": profile["seed"]})
    pending = sorted(target for target, item in inventory.items()
                     if target not in registered and
                     (primitive == "all" or item["primitive"] == primitive))
    return sorted(rows, key=lambda x: (x["target"], x["parameter_set"],
                                       x["api"], x["profile"])), pending


def command(action, row, iterations=None, seed=None):
    args = [sys.executable, "scripts/pqcfuzz_target.py", action,
            "--target", row["target"], "--algorithm", row["algorithm"],
            "--parameter-set", row["parameter_set"], "--api", row["api"],
            "--profile", row["profile"]]
    if iterations is not None:
        args += ["--iterations", str(iterations), "--seed", str(seed)]
    return args


def invoke(args, timeout):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[2]} failed: rc={result.returncode}; "
                           f"stdout={result.stdout[-1000:]}; stderr={result.stderr[-1000:]}")
    return json.loads(result.stdout.splitlines()[-1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--primitive", choices=("all", "hash", "kem", "sign"), default="all")
    parser.add_argument("--hash-iterations", type=int, default=128)
    parser.add_argument("--asym-iterations", type=int, default=16)
    args = parser.parse_args()
    if args.hash_iterations <= 0 or args.asym_iterations <= 0:
        parser.error("iteration counts must be positive")
    rows, pending = select(args.primitive)
    if not rows:
        raise SystemExit("no registered A-tier instances for this selection")
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    out = WORK / "runs" / run_id
    out.mkdir(parents=True, exist_ok=False)
    status = {"run_id": run_id, "started_utc": utc(), "status": "running",
              "registered_instances": len(rows), "registered_targets": len({x["target"] for x in rows}),
              "pending_targets": pending, "completed": [], "failures": [],
              "driver_sha256": sha(Path(__file__).resolve()),
              "registry_sha256": sha(ROOT / "configs/targets.json")}
    write_json(out / "progress.json", status)
    write_json(out / "instances.json", rows)
    with (out / "events.jsonl").open("w") as log:
        for index, row in enumerate(rows):
            status["current"] = row
            write_json(out / "progress.json", status)
            try:
                preflight = invoke(command("preflight", row), 120)
                if preflight["stage"] != "ready":
                    raise RuntimeError("preflight was not ready")
                iterations = (args.hash_iterations if row["primitive"] == "hash"
                              else args.asym_iterations)
                seed = row["base_seed"] + index * 7919
                result = invoke(command("run", row, iterations, seed), 900)
                if result["stage"] != "ready":
                    raise RuntimeError("campaign was not ready")
                run = Path(result["run"]).resolve()
                if not run.is_relative_to(ROOT / "workspace" / row["target"] / "runs"):
                    raise RuntimeError("run path escaped target workspace")
                verified = invoke([sys.executable, "scripts/pqcfuzz_target.py",
                                   "verify", "--run", str(run)], 120)
                if verified["integrity"] != "ok":
                    raise RuntimeError("evidence integrity failed")
                report = json.loads((run / "report.json").read_text())
                item = {"target": row["target"], "parameter_set": row["parameter_set"],
                        "api": row["api"], "profile": row["profile"],
                        "run": str(run.relative_to(ROOT)), "iterations_per_oracle": iterations,
                        "seed": seed, "counts": report["counts"],
                        "evidence_class": report["evidence_class"],
                        "integrity": verified["integrity"]}
                status["completed"].append(item)
                print(json.dumps(item), flush=True)
                event = {"time_utc": utc(), "kind": "campaign", **item}
            except (OSError, KeyError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
                item = {"target": row["target"], "parameter_set": row["parameter_set"],
                        "error": str(exc)}
                status["failures"].append(item)
                print(json.dumps(item), flush=True)
                event = {"time_utc": utc(), "kind": "failure", **item}
            log.write(json.dumps(event) + "\n")
            log.flush()
            write_json(out / "progress.json", status)
    status["finished_utc"] = utc()
    status["status"] = "complete" if not status["failures"] else "partial"
    status.pop("current", None)
    write_json(out / "summary.json", status)
    write_json(out / "progress.json", status)
    print(json.dumps({"summary": str((out / "summary.json").relative_to(ROOT)),
                      "completed": len(status["completed"]),
                      "failed": len(status["failures"]), "pending_targets": pending}), flush=True)
    if status["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Time-boxed round-robin SOP campaign for the seven registered S-tier hashes.

Each target run remains a normal immutable PQCFuzz run. This driver records
its own progress and checks every completed run's manifest integrity.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGETS = {"hash-03", "hash-15", "hash-16", "hash-23", "hash-28", "hash-29", "hash-34"}
STOP = False


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def request_stop(_signum, _frame):
    global STOP
    STOP = True


def process(argv, timeout, progress, progress_path):
    child = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, start_new_session=True)
    started = time.monotonic()
    timed_out = False
    while child.poll() is None:
        if time.monotonic() - started > timeout:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            break
        progress["heartbeat_utc"] = now()
        atomic_json(progress_path, progress)
        try:
            child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            pass
    stdout, stderr = child.communicate()
    return {"returncode": child.returncode, "timeout": timed_out,
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "stdout": stdout[-4000:], "stderr": stderr[-4000:]}


def event(log, payload):
    log.write(json.dumps({"time_utc": now(), **payload}, sort_keys=True) + "\n")
    log.flush()
    os.fsync(log.fileno())


def current_instances():
    registry = json.loads((ROOT / "configs/targets.json").read_text(encoding="utf-8"))
    if registry.get("schema_version") != 2:
        raise RuntimeError("S-tier soak requires registered schema 2")
    found = []
    for target in registry["targets"]:
        if target["target"] not in TARGETS:
            continue
        for api in target["apis"]:
            for profile in api["profiles"]:
                found.append({"target": target["target"], "algorithm": target["algorithm"],
                              "parameter_set": api["parameter_set"], "api": api["name"],
                              "profile": profile["id"], "base_seed": profile["seed"]})
    if len(found) != 21 or {row["target"] for row in found} != TARGETS:
        raise RuntimeError("expected exactly 21 instances across seven S-tier targets")
    return found


def selectors(row):
    return ["--target", row["target"], "--algorithm", row["algorithm"],
            "--parameter-set", row["parameter_set"], "--api", row["api"],
            "--profile", row["profile"]]


def validate_matrix(path):
    report = json.loads((path / "report.json").read_text(encoding="utf-8"))
    hashes = json.loads((path / "sha256.json").read_text(encoding="utf-8"))
    if not all(sha(path / name) == digest for name, digest in hashes.items()):
        raise RuntimeError("diagnostic artifact hash mismatch")
    return {"run": str(path), "cases": report["cases"],
            "kat_matched": report["kat_matched"], "direct_checks_matched": report["matched"],
            "digest_calls": sum((row.get("worker_result") or {}).get("digest_calls", 0)
                                for row in report["results"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", type=int, default=21600)
    parser.add_argument("--iterations", type=int, default=128)
    parser.add_argument("--kat-period-seconds", type=int, default=3600)
    parser.add_argument("--max-runs", type=int, default=0, help="pilot limit; 0 means no limit")
    parser.add_argument("--min-free-gb", type=int, default=50)
    args = parser.parse_args()
    if args.duration_seconds <= 0 or args.iterations <= 0 or args.kat_period_seconds < 0:
        parser.error("duration/iterations must be positive and KAT period nonnegative")
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    instances = current_instances()
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    out = ROOT / "workspace/s_hash_soak/runs" / run_id
    out.mkdir(parents=True, exist_ok=False)
    progress_path = out / "progress.json"
    progress = {"run_id": run_id, "status": "preflight", "started_utc": now(),
                "planned_seconds": args.duration_seconds, "iterations_per_oracle_per_run": args.iterations,
                "instances": len(instances), "completed_runs": 0, "failed_runs": 0,
                "pass": 0, "counterexample_candidate": 0, "harness_error": 0,
                "diagnostics": 0, "diagnostic_errors": 0,
                "registry_sha256": sha(ROOT / "configs/targets.json"),
                "driver_sha256": sha(Path(__file__).resolve()), "heartbeat_utc": now()}
    atomic_json(progress_path, progress)
    atomic_json(out / "instances.json", instances)
    started = time.monotonic()
    deadline = started + args.duration_seconds
    next_kat = started if args.kat_period_seconds else float("inf")
    run_index = 0
    with (out / "events.jsonl").open("a", encoding="utf-8") as log:
        try:
            for row in instances:
                result = process([sys.executable, "scripts/pqcfuzz_target.py", "preflight",
                                  *selectors(row)], 120, progress, progress_path)
                if result["returncode"] != 0 or result["timeout"]:
                    raise RuntimeError(f"preflight failed for {row['parameter_set']}: {result}")
            progress["status"] = "running"
            progress["preflight_utc"] = now()
            atomic_json(progress_path, progress)
            event(log, {"kind": "preflight", "instances": len(instances), "result": "ready"})
            while not STOP and time.monotonic() < deadline:
                if shutil.disk_usage(ROOT).free < args.min_free_gb * 1024**3:
                    raise RuntimeError("free disk space fell below configured floor")
                if time.monotonic() >= next_kat:
                    progress["current"] = "full submitted KAT matrix"
                    atomic_json(progress_path, progress)
                    result = process([sys.executable, "scripts/pqcfuzz_s_hash_api_matrix.py"],
                                     1800, progress, progress_path)
                    try:
                        last = json.loads(result["stdout"].splitlines()[-1])
                        matrix = validate_matrix(Path(last["run"]))
                        # The two known WChain SIMD direct-helper mismatches return 1;
                        # their digest KATs still match and are reported separately.
                        if matrix["cases"] != 49 or matrix["kat_matched"] != 49:
                            raise RuntimeError("not all submitted KAT builds matched")
                        progress["diagnostics"] += 1
                        event(log, {"kind": "kat_matrix", "result": matrix,
                                    "process_returncode": result["returncode"]})
                    except (OSError, ValueError, IndexError, KeyError, RuntimeError) as exc:
                        progress["diagnostic_errors"] += 1
                        event(log, {"kind": "kat_matrix_error", "error": str(exc),
                                    "process": result})
                    next_kat = time.monotonic() + args.kat_period_seconds
                    atomic_json(progress_path, progress)
                    if time.monotonic() >= deadline:
                        break
                row = instances[run_index % len(instances)]
                cycle = run_index // len(instances)
                seed = row["base_seed"] + cycle * 1000003 + (run_index % len(instances)) * 7919
                progress["current"] = {"target": row["target"],
                                       "parameter_set": row["parameter_set"],
                                       "cycle": cycle, "seed": seed}
                atomic_json(progress_path, progress)
                result = process([sys.executable, "scripts/pqcfuzz_target.py", "run",
                                  *selectors(row), "--iterations", str(args.iterations),
                                  "--seed", str(seed)], 900, progress, progress_path)
                try:
                    summary = json.loads(result["stdout"].splitlines()[-1])
                    run_path = Path(summary["run"])
                    verified = process([sys.executable, "scripts/pqcfuzz_target.py", "verify",
                                        "--run", str(run_path)], 120, progress, progress_path)
                    if (result["returncode"] != 0 or result["timeout"] or
                            summary["stage"] != "ready" or verified["returncode"] != 0):
                        raise RuntimeError("run or evidence integrity failed")
                    report = json.loads((run_path / "report.json").read_text(encoding="utf-8"))
                    if (report["replay_status"] != "not_run" or
                            report["confirmed_findings"] != 0 or
                            report["parameter_set"] != row["parameter_set"]):
                        raise RuntimeError("report identity or candidate-only status mismatch")
                    for key in ("pass", "counterexample_candidate", "harness_error"):
                        progress[key] += summary["counts"][key]
                    progress["completed_runs"] += 1
                    progress["last_run"] = {"target": row["target"],
                                            "parameter_set": row["parameter_set"],
                                            "run": str(run_path), "counts": summary["counts"]}
                    event(log, {"kind": "campaign", "cycle": cycle,
                                "target": row["target"], "parameter_set": row["parameter_set"],
                                "seed": seed, "result": summary, "integrity": "ok"})
                except (OSError, ValueError, IndexError, KeyError, RuntimeError) as exc:
                    progress["failed_runs"] += 1
                    event(log, {"kind": "campaign_error", "cycle": cycle,
                                "target": row["target"], "parameter_set": row["parameter_set"],
                                "seed": seed, "error": str(exc), "process": result})
                run_index += 1
                atomic_json(progress_path, progress)
                if args.max_runs and run_index >= args.max_runs:
                    break
            progress["status"] = "stopped" if STOP else "complete"
        except Exception as exc:
            progress["status"] = "failed"
            progress["fatal_error"] = repr(exc)
            event(log, {"kind": "fatal_error", "error": repr(exc)})
        finally:
            progress["finished_utc"] = now()
            progress["actual_seconds"] = round(time.monotonic() - started, 2)
            progress.pop("current", None)
            atomic_json(progress_path, progress)
            atomic_json(out / "summary.json", progress)
            print(json.dumps({"run": str(out), "status": progress["status"],
                              "completed_runs": progress["completed_runs"],
                              "failed_runs": progress["failed_runs"]}), flush=True)
    return 0 if progress["status"] == "complete" and progress["failed_runs"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

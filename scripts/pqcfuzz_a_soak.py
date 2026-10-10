#!/usr/bin/env python3
"""Run the registered A-tier SOP instances concurrently for a wall-clock budget.

Each target has one worker, so its declared profile concurrency of one is
respected. Every completed PQCFuzz run is independently integrity-checked.
"""
import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pqcfuzz_a_campaign as campaign


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "workspace/a_targets_soak/runs"
STOP = threading.Event()


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def invoke(argv, timeout):
    child = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        stdout, stderr = child.communicate()
        raise RuntimeError(f"timeout after {timeout}s: {argv[2:5]}; "
                           f"stdout={stdout[-1000:]}; stderr={stderr[-1000:]}")
    if child.returncode:
        raise RuntimeError(f"exit {child.returncode}: {argv[2:5]}; "
                           f"stdout={stdout[-1000:]}; stderr={stderr[-1000:]}")
    try:
        return json.loads(stdout.splitlines()[-1])
    except (IndexError, ValueError) as exc:
        raise RuntimeError(f"missing JSON result: {argv[2:5]}; stdout={stdout[-1000:]}") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", type=int, default=43200)
    parser.add_argument("--hash-iterations", type=int, default=128)
    parser.add_argument("--asym-iterations", type=int, default=16)
    parser.add_argument("--cycle-seconds", type=int, default=180,
                        help="minimum steady-state interval between starts for one target")
    parser.add_argument("--min-free-gb", type=int, default=150)
    parser.add_argument("--target", action="append", help="restrict selection for a pilot")
    parser.add_argument("--max-runs-per-target", type=int, default=0,
                        help="pilot limit; zero means run until the deadline")
    args = parser.parse_args()
    if (args.duration_seconds <= 0 or args.hash_iterations <= 0 or
            args.asym_iterations <= 0 or args.cycle_seconds <= 0 or
            args.min_free_gb <= 0 or args.max_runs_per_target < 0):
        parser.error("duration, iterations, cycle and free-space floor must be positive")

    rows, pending = campaign.select("all")
    registry = json.loads((ROOT / "configs/targets.json").read_text())
    first = {}
    for entry in registry["targets"]:
        if entry["target"] not in {row["target"] for row in rows}:
            continue
        api = entry["apis"][0]
        profile = api["profiles"][0]
        first[entry["target"]] = (api["parameter_set"], api["name"], profile["id"])
    rows = [row for row in rows if (row["parameter_set"], row["api"], row["profile"]) ==
            first.get(row["target"])]
    if pending or len(rows) != 33 or len({row["target"] for row in rows}) != 33:
        raise SystemExit("expected exactly 33 registered A-tier targets")
    if args.target:
        unknown = set(args.target) - {row["target"] for row in rows}
        if unknown:
            parser.error("unknown A-tier target(s): " + ", ".join(sorted(unknown)))
        rows = [row for row in rows if row["target"] in set(args.target)]

    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    out = WORK / run_id
    out.mkdir(parents=True, exist_ok=False)
    progress_path = out / "progress.json"
    events_path = out / "events.jsonl"
    lock = threading.Lock()
    progress = {
        "run_id": run_id, "status": "preflight", "created_utc": utc(),
        "planned_seconds": args.duration_seconds, "cycle_seconds": args.cycle_seconds,
        "hash_iterations": args.hash_iterations, "asym_iterations": args.asym_iterations,
        "min_free_gb": args.min_free_gb, "registered_targets": len(rows),
        "pending_targets": pending, "preflight_ready": 0, "completed_runs": 0,
        "failed_runs": 0, "counts": {}, "heartbeat_utc": utc(),
        "driver_sha256": digest(Path(__file__)),
        "registry_sha256": digest(ROOT / "configs/targets.json"),
        "inventory_sha256": digest(ROOT / "workspace/a_targets_sop/inventory.json"),
        "targets": {row["target"]: {"completed_runs": 0, "failed_runs": 0,
                                   "counts": {}, "state": "pending"} for row in rows},
    }
    atomic_json(progress_path, progress)
    atomic_json(out / "instances.json", rows)

    def record(kind, **fields):
        with lock:
            payload = {"time_utc": utc(), "kind": kind, **fields}
            with events_path.open("a", encoding="utf-8") as log:
                log.write(json.dumps(payload, sort_keys=True) + "\n")
                log.flush()
                os.fsync(log.fileno())
            progress["heartbeat_utc"] = payload["time_utc"]
            atomic_json(progress_path, progress)

    def preflight(row):
        result = invoke(campaign.command("preflight", row), 180)
        if result.get("stage") != "ready":
            raise RuntimeError(f"{row['target']} preflight: {result}")
        with lock:
            progress["preflight_ready"] += 1
            progress["targets"][row["target"]]["state"] = "ready"
            atomic_json(progress_path, progress)
        record("preflight", target=row["target"], result="ready")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(rows)) as pool:
            checks = {pool.submit(preflight, row): row for row in rows}
            errors = []
            for future in concurrent.futures.as_completed(checks):
                try:
                    future.result()
                except Exception as exc:
                    target = checks[future]["target"]
                    errors.append({"target": target, "error": str(exc)})
                    with lock:
                        progress["targets"][target]["state"] = "blocked"
                    record("preflight_error", target=target, error=str(exc))
        if errors:
            progress["status"] = "blocked"
            progress["preflight_errors"] = errors
            return 1

        started = time.monotonic()
        deadline = started + args.duration_seconds
        progress["status"] = "running"
        progress["started_utc"] = utc()
        progress["deadline_utc"] = (dt.datetime.now(dt.timezone.utc) +
                                    dt.timedelta(seconds=args.duration_seconds)).isoformat()
        atomic_json(progress_path, progress)
        record("start", targets=len(rows), deadline_utc=progress["deadline_utc"])

        def worker(index, row):
            target = row["target"]
            cycle = 0
            # First wave starts in parallel. Later starts are spread across the
            # cycle so some targets remain active throughout the wall-clock run.
            next_start = started
            phase = args.cycle_seconds * index / len(rows)
            while not STOP.is_set() and time.monotonic() < deadline:
                delay = next_start - time.monotonic()
                if delay > 0 and STOP.wait(min(delay, 15)):
                    break
                if delay > 0:
                    continue
                if shutil.disk_usage(ROOT).free < args.min_free_gb * 1024**3:
                    with lock:
                        progress["fatal_error"] = "free disk space below configured floor"
                    record("disk_floor", target=target, free_bytes=shutil.disk_usage(ROOT).free)
                    STOP.set()
                    break
                seed = row["base_seed"] + cycle * 1000003 + index * 7919
                iterations = (args.hash_iterations if row["primitive"] == "hash"
                              else args.asym_iterations)
                with lock:
                    progress["targets"][target]["state"] = "running"
                    progress["targets"][target]["cycle"] = cycle
                    progress["targets"][target]["seed"] = seed
                    atomic_json(progress_path, progress)
                try:
                    result = invoke(campaign.command("run", row, iterations, seed), 1800)
                    if result.get("stage") != "ready":
                        raise RuntimeError(f"campaign stage: {result}")
                    run = Path(result["run"]).resolve()
                    if not run.is_relative_to(ROOT / "workspace" / target / "runs"):
                        raise RuntimeError("run path escaped target workspace")
                    checked = invoke([sys.executable, "scripts/pqcfuzz_target.py",
                                      "verify", "--run", str(run)], 300)
                    if checked.get("integrity") != "ok":
                        raise RuntimeError("evidence integrity failed")
                    report = json.loads((run / "report.json").read_text(encoding="utf-8"))
                    if (report.get("stage") != "ready" or
                            report.get("evidence_class") != "unverified_spec" or
                            report.get("replay_status") != "not_run" or
                            report.get("confirmed_findings") != 0 or
                            report.get("parameter_set") != row["parameter_set"] or
                            report.get("counts") != result.get("counts")):
                        raise RuntimeError("candidate-only report or run identity mismatch")
                    counts = report["counts"]
                    with lock:
                        progress["completed_runs"] += 1
                        state = progress["targets"][target]
                        state["completed_runs"] += 1
                        state["last_run"] = str(run.relative_to(ROOT))
                        state["last_completed_utc"] = utc()
                        for key, value in counts.items():
                            progress["counts"][key] = progress["counts"].get(key, 0) + value
                            state["counts"][key] = state["counts"].get(key, 0) + value
                    record("campaign", target=target, cycle=cycle, seed=seed,
                           iterations_per_oracle=iterations,
                           run=str(run.relative_to(ROOT)), counts=counts, integrity="ok")
                except Exception as exc:
                    with lock:
                        progress["failed_runs"] += 1
                        progress["targets"][target]["failed_runs"] += 1
                        progress["targets"][target]["last_error"] = str(exc)
                    record("campaign_error", target=target, cycle=cycle, seed=seed, error=str(exc))
                cycle += 1
                with lock:
                    progress["targets"][target]["state"] = "waiting"
                    atomic_json(progress_path, progress)
                if args.max_runs_per_target and cycle >= args.max_runs_per_target:
                    break
                next_start = started + 30 + phase + (cycle - 1) * args.cycle_seconds
            with lock:
                progress["targets"][target]["state"] = "stopped"
                atomic_json(progress_path, progress)

        def request_stop(_signum, _frame):
            STOP.set()

        signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(rows)) as pool:
            futures = [pool.submit(worker, i, row) for i, row in enumerate(rows)]
            while not all(future.done() for future in futures):
                with lock:
                    progress["heartbeat_utc"] = utc()
                    atomic_json(progress_path, progress)
                concurrent.futures.wait(futures, timeout=15,
                                        return_when=concurrent.futures.ALL_COMPLETED)
            for future in futures:
                future.result()
        progress["actual_seconds"] = round(time.monotonic() - started, 2)
        reached_deadline = time.monotonic() >= deadline
        complete_targets = all(x["completed_runs"] > 0 for x in progress["targets"].values())
        clean = complete_targets and progress["failed_runs"] == 0 and not STOP.is_set()
        progress["status"] = ("complete" if reached_deadline and clean
                              else "pilot_complete" if args.max_runs_per_target and clean
                              else "failed" if progress.get("fatal_error")
                              else "partial" if reached_deadline or args.max_runs_per_target
                              else "stopped")
        return 0 if progress["status"] in ("complete", "pilot_complete") else 1
    finally:
        progress["finished_utc"] = utc()
        atomic_json(out / "summary.json", progress)
        atomic_json(progress_path, progress)
        print(json.dumps({"run": str(out), "status": progress["status"],
                          "completed_runs": progress["completed_runs"],
                          "failed_runs": progress["failed_runs"]}), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())

"""
Instructions to run this code.
==============================
"""
import json
import collections
import tqdm
import multiprocessing
import subprocess
import psutil
import time
import hashlib
import os
import signal
from datetime import datetime, timezone
from pathlib import Path


LOGFILE=None


def timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def task_id(testpath, alg):
    return hashlib.sha256(f"{testpath}\0{alg}".encode("utf-8")).hexdigest()[:20]


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def write_task(output_root, task):
    task["updated_at"] = timestamp()
    write_json(Path(output_root) / "metadata" / "tasks" / f"{task['id']}.json", task)


def collect_tasks(output_root):
    task_dir = Path(output_root) / "metadata" / "tasks"
    tasks = []
    for path in sorted(task_dir.glob("*.json")):
        try:
            tasks.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    write_json(Path(output_root) / "metadata" / "tasks.json", tasks)
    return tasks


def mark_running_tasks_interrupted(output_root, reason):
    """Turn durable in-flight task records into terminal budget evidence."""
    tasks = collect_tasks(output_root)
    for task in tasks:
        if task.get("state") != "running":
            continue
        task.update({
            "state": "interrupted",
            "stop_reason": reason,
            "interrupted_at": timestamp(),
        })
        write_task(output_root, task)
    return collect_tasks(output_root)


def property_name(testpath):
    marker = "liboqs/"
    return testpath.split(marker, 1)[1] if marker in testpath else testpath


def configured_workers(raw):
    if raw and raw != "auto":
        value = int(raw)
        if value <= 0:
            raise ValueError("--workers must be positive or 'auto'")
        return raw, value

    try:
        available = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        available = psutil.cpu_count(logical=False) or psutil.cpu_count() or 1
    quota_raw = os.environ.get("CRYPTO_TESTING_CPU_QUOTA", str(available))
    try:
        quota = int(quota_raw)
    except ValueError:
        quota = available
    return "auto", max(1, min(available, max(1, quota)))


TESTPATHS=(
    "tech/paper_fuzzing/liboqs/KEM/Decaps/c",
    "tech/paper_fuzzing/liboqs/KEM/Decaps/sk",
    "tech/paper_fuzzing/liboqs/KEM/Encaps/badrng",
    "tech/paper_fuzzing/liboqs/KEM/Encaps/pk-0",
    "tech/paper_fuzzing/liboqs/KEM/Encaps/pk",
    "tech/paper_fuzzing/liboqs/KEM/Keygen/badrng",
    "tech/paper_fuzzing/liboqs/SIGN/Keygen/badrng",
    "tech/paper_fuzzing/liboqs/SIGN/Sign/badrng",
    "tech/paper_fuzzing/liboqs/SIGN/Sign/m",
    "tech/paper_fuzzing/liboqs/SIGN/Sign/sk",
    "tech/paper_fuzzing/liboqs/SIGN/Verify/m",
    "tech/paper_fuzzing/liboqs/SIGN/Verify/sig",
    "tech/paper_fuzzing/liboqs/SIGN/Verify/pk",
)


BLACKLIST=(
    # the three entries below slow significantly the process
    # full results do however include these experiments
    ("McEliece", "Encaps/pk"),      # huge pk, makes the test take really long
    ("BIKE", "Encaps/pk"),          # ditto
    ("Frodo", "Encaps/pk"),         # ditto
    ("sntrup761", "Keygen/badrng"),  # hangs
)


def blacklisted(alg, testpath):
    for n, t in BLACKLIST:
        if      n.lower() in alg.lower() \
            and t.lower() in testpath.lower():
            if LOGFILE:
                print(f"Skipping {n}, {t}", file=LOGFILE)
                LOGFILE.flush()
            return True
    return False


def get_algs(testpath, liboqs):
    shellcmd = f'bash -c "cd {testpath}; DIRNAME={liboqs} make clean all > /dev/null 2>&1; python3 run_all.py --n_algs_only; exit $?"'
    proc = subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    algs_d = collections.OrderedDict(json.loads(proc.stdout.decode('ascii').strip()))
    return algs_d


def experiment(ctr_testpath_alg_mutator_liboqs_algsd):
    ctr, testpath, alg, mutator, liboqs, algs_d, output_root, workers, geninput_timeout, task_max_time = ctr_testpath_alg_mutator_liboqs_algsd
    task = {
        "id": task_id(testpath, alg),
        "algorithm": algs_d[alg],
        "algorithm_index": alg,
        "primitive": "KEM" if "/KEM/" in testpath else "SIGN",
        "property": property_name(testpath),
        "state": "pending",
    }

    if blacklisted(algs_d[alg], testpath):
        task.update({"state": "skipped", "reason": "blacklist"})
        write_task(output_root, task)
        return { 'ctr': ctr, 'testpath': testpath, 'alg': alg, 'state': task['state'] }

    raw_property = Path(output_root) / "afl" / property_name(testpath)
    task_time_argument = f" --task-max-time {task_max_time}" if task_max_time else ""
    shellcmd = (
        f"cd {testpath}; make clone; bash clone.sh {alg}; cd {alg}; "
        f"DIRNAME={liboqs} make clean all > /dev/null 2>&1; "
        f"python3 run_all.py --mutator {mutator} --base_path {raw_property} "
        f"--run_specific_alg_only {alg} --run_inside_clone --geninput-timeout {geninput_timeout}{task_time_argument}"
    )
    task.update({
        "state": "running",
        "command": shellcmd,
        "geninput_timeout_seconds": geninput_timeout,
        "task_max_time_seconds": task_max_time,
        "workers": workers,
        "started_at": timestamp(),
    })
    write_task(output_root, task)
    started = time.monotonic()
    try:
        subprocess.run(shellcmd, shell=True,
                        stdout = subprocess.PIPE,
                        stderr = subprocess.STDOUT,
                        check=True,
                        universal_newlines=True)
        setup_timeout = raw_property / str(alg) / "fuzzoutputs" / "default" / "setup-timeout" / "GenInput.json"
        task["state"] = "setup-timeout" if setup_timeout.exists() else "completed"
        task["elapsed_seconds"] = round(time.monotonic() - started, 6)
        write_task(output_root, task)
        return { 'ctr': ctr, 'testpath': testpath, 'alg': alg, 'state': task['state'] }
    except Exception as error:
        task.update({
            "state": "target-failed",
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "error": str(error),
        })
        write_task(output_root, task)
        if LOGFILE:
            print(shellcmd, file=LOGFILE)
            LOGFILE.flush()
        else:
            print(shellcmd)
        return { 'ctr': ctr, 'testpath': testpath, 'alg': alg, 'state': task['state'] }

def main(mutator, liboqs, version, output_root, requested_workers, geninput_timeout,
         task_max_time, max_total_time):
    requested_workers, nproc = configured_workers(requested_workers)
    print(f"Using pool of size {nproc} (requested: {requested_workers})")
    metadata_root = Path(output_root) / "metadata"
    metadata_root.mkdir(parents=True, exist_ok=True)
    bars = []
    algs = []
    for ctr in range(len(TESTPATHS)):
        testpath = TESTPATHS[ctr]
        algs_d = get_algs(testpath, liboqs)
        algs.append(algs_d)
        for alg, alg_name in algs_d.items():
            state = "skipped" if blacklisted(alg_name, testpath) else "pending"
            task = {
                "id": task_id(testpath, alg), "algorithm": alg_name, "algorithm_index": alg,
                "primitive": "KEM" if "/KEM/" in testpath else "SIGN",
                "property": property_name(testpath), "state": state,
                **({"reason": "blacklist"} if state == "skipped" else {}),
            }
            write_task(output_root, task)
        bars.append(tqdm.tqdm(total=len(list(algs_d.keys())), position=ctr, desc='/'.join(testpath.split('/')[-3:])))

    schedule = collect_tasks(output_root)
    scheduled_count = sum(task.get("state") != "skipped" for task in schedule)
    if task_max_time is not None:
        effective_task_max_time = task_max_time
        task_budget_strategy = "explicit"
    elif max_total_time is not None and scheduled_count:
        effective_task_max_time = max(1, max_total_time // scheduled_count)
        task_budget_strategy = "equal-share"
    else:
        effective_task_max_time = None
        task_budget_strategy = "unbounded"
    campaign = {
        "baseline": "cryptoTesting",
        "mode": "functional",
        "liboqs": liboqs,
        "version": version,
        "requested_workers": requested_workers,
        "effective_workers": nproc,
        "cpu_allocation": os.environ.get("CRYPTO_TESTING_CPU_QUOTA", f"workers:{nproc}"),
        "geninput_timeout_seconds": geninput_timeout,
        "requested_task_max_time_seconds": task_max_time,
        "effective_task_max_time_seconds": effective_task_max_time,
        "task_budget_strategy": task_budget_strategy,
        "max_total_time_seconds": max_total_time,
        "scheduled_task_count": scheduled_count,
        "created_at": timestamp(),
    }
    write_json(metadata_root / "campaign.json", campaign)
    write_json(metadata_root / "schedule.json", {
        "version": version,
        "liboqs": liboqs,
        "mode": "functional",
        "tasks": [
            {
                **task,
                "enabled": task.get("state") != "skipped",
                "skip_reason": task.get("reason") if task.get("state") == "skipped" else None,
            }
            for task in schedule
        ],
    })

    work_by_property = [
        [
            (ctr, TESTPATHS[ctr], alg, mutator, liboqs, algs[ctr], output_root, nproc,
             geninput_timeout, effective_task_max_time)
            for alg in algs[ctr].keys()
        ]
        for ctr in range(len(TESTPATHS))
    ]
    work_items = []
    while any(work_by_property):
        for queue in work_by_property:
            if queue:
                work_items.append(queue.pop(0))

    interrupted_by = {"signal": None}

    def handle_termination(signum, _frame):
        interrupted_by["signal"] = signum
        raise KeyboardInterrupt

    previous_sigterm = signal.signal(signal.SIGTERM, handle_termination)
    try:
        with multiprocessing.Pool(nproc) as pool:
            for rv in pool.imap_unordered(
                        experiment,
                        work_items
            ):
                # rv['ctr']
                # rv['testpath']
                # rv['alg']
                bars[rv['ctr']].update(1)
            pool.close()
            pool.join()
    except KeyboardInterrupt:
        subprocess.run(f"echo -ne '%s'" % ('\x1bD' * len(TESTPATHS)), shell=True)
        print("\n\nAborting.\n")
        signal_name = "SIGTERM" if interrupted_by["signal"] == signal.SIGTERM else "SIGINT"
        tasks = mark_running_tasks_interrupted(output_root, signal_name)
        write_json(Path(output_root) / "metadata" / "partial-summary.json", {
            "state": "interrupted", "stop_reason": signal_name,
            "interrupted_at": timestamp(), "tasks": tasks,
        })
        return 128 + interrupted_by["signal"] if interrupted_by["signal"] else 130
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)

    for bar in bars:
        bar.close()
    subprocess.run(f"echo -ne '%s'" % ('\x1bD' * len(TESTPATHS)), shell=True)
    tasks = collect_tasks(output_root)
    return 1 if any(task.get("state") == "target-failed" for task in tasks) else 0


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--liboqs', type=str, default="cur_liboqs")
    parser.add_argument('--mutator', type=str, default="python")
    parser.add_argument('--testpath', type=str, default=None)
    parser.add_argument('--logfile', type=str, default=None)
    parser.add_argument('--output-root', type=str, default=os.environ.get("CRYPTO_TESTING_OUTPUT_ROOT", "aggregatedfuzzingoutputs"))
    parser.add_argument('--workers', default=os.environ.get("CRYPTO_TESTING_WORKERS", "1"))
    parser.add_argument('--geninput-timeout', type=int, default=int(os.environ.get("CRYPTO_TESTING_GENINPUT_TIMEOUT", "10")))
    parser.add_argument('--version', default=os.environ.get("CRYPTO_TESTING_VERSION", "unknown"))
    parser.add_argument('--task-max-time', type=int, default=None,
                        help='maximum AFL seconds per scheduled task')
    parser.add_argument('--max-total-time', type=int, default=None,
                        help='campaign budget used to derive an equal per-task AFL limit')

    args = parser.parse_args()
    mutator = args.mutator
    liboqs = args.liboqs
    testpath = args.testpath
    logfile = args.logfile
    if testpath:
        TESTPATHS = [ testpath ]
    if logfile:
        LOGFILE = open(logfile, 'w')

    if args.task_max_time is not None and args.task_max_time <= 0:
        parser.error('--task-max-time must be positive')
    if args.max_total_time is not None and args.max_total_time <= 0:
        parser.error('--max-total-time must be positive')

    # print (args)
    if "old" in liboqs:
        TESTPATHS = [_ for _ in TESTPATHS if "Verify" not in _]

    dt = time.time()
    status = main(mutator, liboqs, args.version, args.output_root, args.workers, args.geninput_timeout,
                  args.task_max_time, args.max_total_time)
    dt = time.time() - dt

    print("Wall time:", dt)
    print(f"Run status: {status}")

    if LOGFILE:
        LOGFILE.close()
    raise SystemExit(status)

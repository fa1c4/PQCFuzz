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


def setup_timeout_record(output_root, testpath, alg):
    directory = (
        Path(output_root) / "afl" / property_name(testpath) / str(alg) /
        "fuzzoutputs" / "default" / "setup-timeout"
    )
    for name in ("GenInput.json", "GenInput"):
        record = directory / name
        if record.is_file():
            return record
    return None


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
    "tech/paper_fuzzing/vanilla/liboqs/KEM/Decaps/c-sk-eq",
    "tech/paper_fuzzing/vanilla/liboqs/KEM/Encaps/pk-eq",
    "tech/paper_fuzzing/vanilla/liboqs/SIGN/Sign",
    "tech/paper_fuzzing/vanilla/liboqs/SIGN/Verify/m-pk-sig",
)


BLACKLIST=()

WHITELIST = (
    # ("SIDH", "Encaps/pk-eq"),
)

def whitelisted(alg, testpath):
    for n, t in WHITELIST:
        if n.lower() in alg.lower() and t.lower() in testpath.lower():
            if LOGFILE:
                print(f"Not Skipping {alg.lower()}, {testpath.lower()}", file=LOGFILE)
                LOGFILE.flush()
            return True
    else:
        if LOGFILE:
            print(f"Skipping {alg.lower()}, {testpath.lower()}", file=LOGFILE)
            LOGFILE.flush()
    return False

def blacklisted(alg, testpath):
    for n, t in BLACKLIST:
        if      n.lower() in alg.lower() \
            and t.lower() in testpath.lower():
            if LOGFILE:
                print(f"Skipping {n}, {t}", file=LOGFILE)
                LOGFILE.flush()
            return True
    else:
        if LOGFILE:
            print(f"Not Skipping {alg.lower()}, {testpath.lower()}", file=LOGFILE)
            LOGFILE.flush()
    return False

FILTER_KEM = [1]
FILTER_SIG = [1]

def get_algs(testpath, liboqs):
    shellcmd = f'cd {testpath} && DIRNAME={liboqs} make clean all > /dev/null 2>&1 && python3 run_all.py --n_algs_only'
    proc = subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = proc.stdout.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"algorithm discovery failed for {testpath} with exit status {proc.returncode}: {detail[-1000:]}"
        )
    try:
        return collections.OrderedDict(json.loads(output))
    except json.JSONDecodeError as error:
        raise RuntimeError(f"algorithm discovery emitted invalid JSON for {testpath}: {output[-1000:]}") from error


def experiment(ctr_testpath_alg_mutator_liboqs_algsd):
    ctr, testpath, alg, mutator, liboqs, algs_d, output_root, workers, geninput_timeout = ctr_testpath_alg_mutator_liboqs_algsd
    task = {
        "id": task_id(testpath, alg), "algorithm": algs_d[alg], "algorithm_index": alg,
        "primitive": "KEM" if "/KEM/" in testpath else "SIGN",
        "property": property_name(testpath), "state": "pending",
    }

    if blacklisted(algs_d[alg], testpath):
        task.update({"state": "skipped", "reason": "blacklist"})
        write_task(output_root, task)
        return { 'ctr': ctr, 'testpath': testpath, 'alg': alg, 'state': task['state'] }

    # if not whitelisted(algs_d[alg], testpath):
    #     return { 'ctr': ctr, 'testpath': testpath, 'alg': alg }
    # if "KEM" in testpath and alg not in FILTER_KEM:
    #     return { 'ctr': ctr, 'testpath': testpath, 'alg': alg }
    # if "SIGN" in testpath and alg not in FILTER_SIG:
    #     return { 'ctr': ctr, 'testpath': testpath, 'alg': alg }
    
    raw_property = Path(output_root) / "afl" / property_name(testpath)
    shellcmd = (
        f"cd {testpath}; make clone; bash clone.sh {alg}; cd {alg}; "
        f"DIRNAME={liboqs} DESIRED_ALG_TO_FUZZ={alg} make clean all > /dev/null 2>&1; "
        f"python3 run_all.py --base_path {raw_property} --run_specific_alg_only {alg} --run_inside_clone --geninput-timeout {geninput_timeout}"
    )
    task.update({
        "state": "running", "command": shellcmd, "geninput_timeout_seconds": geninput_timeout,
        "workers": workers, "started_at": timestamp(),
    })
    write_task(output_root, task)
    started = time.monotonic()
    try:
        subprocess.run(shellcmd,
                        shell=True,
                        stdout = subprocess.PIPE,
                        stderr = subprocess.STDOUT,
                        check=True,
                        universal_newlines=True)
        timeout_record = setup_timeout_record(output_root, testpath, alg)
        if timeout_record is not None:
            task.update({
                "state": "setup-timeout",
                "stop_reason": "GenInput-timeout",
                "setup_timeout_record": str(timeout_record.relative_to(output_root)),
            })
        else:
            task["state"] = "completed"
        task["elapsed_seconds"] = round(time.monotonic() - started, 6)
        write_task(output_root, task)
        return { 'ctr': ctr, 'testpath': testpath, 'alg': alg, 'state': task['state'] }
    except Exception as e:
        task.update({
            "state": "target-failed", "elapsed_seconds": round(time.monotonic() - started, 6),
            "error": str(e),
        })
        output = getattr(e, "stdout", None)
        if output:
            task["output_tail"] = output[-2000:]
        write_task(output_root, task)
        if LOGFILE:
            print(shellcmd, file=LOGFILE)
            print(e, file=LOGFILE)
            LOGFILE.flush()
        else:
            print(shellcmd)
            print(e)
        return { 'ctr': ctr, 'testpath': testpath, 'alg': alg, 'state': task['state'] }

def main(mutator, liboqs, version, output_root, requested_workers, geninput_timeout):
    requested_workers, nproc = configured_workers(requested_workers)
    print(f"Using pool of size {nproc} (requested: {requested_workers})")
    metadata_root = Path(output_root) / "metadata"
    metadata_root.mkdir(parents=True, exist_ok=True)
    write_json(metadata_root / "campaign.json", {
        "baseline": "cryptoTesting", "mode": "vanilla", "liboqs": liboqs, "version": version,
        "requested_workers": requested_workers, "effective_workers": nproc,
        "cpu_allocation": os.environ.get("CRYPTO_TESTING_CPU_QUOTA", f"workers:{nproc}"),
        "geninput_timeout_seconds": geninput_timeout, "created_at": timestamp(),
    })

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
    write_json(metadata_root / "schedule.json", {
        "version": version, "liboqs": liboqs, "mode": "vanilla",
        "tasks": [
            {
                **task,
                "enabled": task.get("state") != "skipped",
                "skip_reason": task.get("reason") if task.get("state") == "skipped" else None,
            }
            for task in schedule
        ],
    })

    interrupted_by = {"signal": None}

    def handle_termination(signum, _frame):
        interrupted_by["signal"] = signum
        raise KeyboardInterrupt

    previous_sigterm = signal.signal(signal.SIGTERM, handle_termination)
    try:
        with multiprocessing.Pool(nproc) as pool:
            for rv in pool.imap_unordered(
                        experiment,
                        list(
                            (_ctr, TESTPATHS[_ctr], _alg, mutator, liboqs, algs[_ctr], output_root, nproc, geninput_timeout)
                            for _ctr in range(len(TESTPATHS))
                            for _alg in algs[_ctr].keys()
                        )
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

    args = parser.parse_args()
    mutator = args.mutator
    liboqs = args.liboqs
    testpath = args.testpath
    logfile = args.logfile
    if testpath:
        TESTPATHS = [ testpath ]
    if logfile:
        LOGFILE = open(logfile, 'w')

    dt = time.time()
    try:
        status = main(mutator, liboqs, args.version, args.output_root, args.workers, args.geninput_timeout)
    except Exception as error:
        write_json(Path(args.output_root) / "metadata" / "driver-error.json", {
            "state": "harness-error", "stage": "driver", "error": str(error), "at": timestamp(),
        })
        print(f"Driver failure: {error}")
        status = 1
    dt = time.time() - dt

    print("Wall time:", dt)
    print(f"Run status: {status}")

    if LOGFILE:
        LOGFILE.close()
    raise SystemExit(status)

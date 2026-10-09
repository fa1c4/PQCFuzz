#!/usr/bin/env python3
"""Diagnostic one-KAT build probe for primary B-tier 512-bit CryptHash paths.

This is not SOP smoke or a claim of full KAT/parameter/function coverage.
"""
import ctypes
import hashlib
import json
import multiprocessing as mp
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "workspace/b_targets_sop/probes"
KAT_RE = re.compile(r"Msg_Len = (\d+)\nMsg = ([0-9A-F]*)\nDst_Len = (\d+)\nDst = ([0-9A-F]+)")
EXCLUDE = {"KAT_CryptHash.c", "drng.c", "quick_test.c", "benchmark.c",
           "profile_info.c", "hash_cli.c"}


def normalized(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())


def select(inventory, source):
    headers = []
    for relative in inventory["api_headers"]:
        if ("Reference_Implementation" not in relative or "Others" in relative or
                "self" in relative.lower() or "XOF" in relative.upper()):
            continue
        path = source / relative
        data = path.read_text(errors="replace")
        bits = re.search(r"#define\s+DIGEST_BIT_LENGTH\s+(\d+)", data)
        name = re.search(r'#define\s+ALGORITHM_INSTANCE\s+"([^"]+)"', data)
        if bits and name and int(bits.group(1)) == 512:
            headers.append((relative, name.group(1)))
    headers.sort(key=lambda x: (len(Path(x[0]).parts), x[0]))
    return headers[0] if headers else (None, None)


def one_call(library, record, queue):
    try:
        bits, msg, expected = record
        function = ctypes.CDLL(str(library.resolve())).CryptHash
        function.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong,
                             ctypes.c_void_p)
        function.restype = ctypes.c_int
        message = bytes.fromhex(msg)
        input_buffer = ctypes.create_string_buffer(message if message else b"\x00")
        output = (ctypes.c_ubyte * 80)(*([0xa5] * 80))
        code = function(512, input_buffer, bits, output)
        queue.put({"return_code": code, "kat_match": code == 0 and
                   bytes(output[:64]).hex() == expected.lower(),
                   "guard_modified": any(x != 0xa5 for x in output[64:])})
    except Exception as exc:
        queue.put({"error": repr(exc)})


def probe(target, source, header, instance, kat, backend):
    directory = (source / header).parent
    sources = sorted(p for p in directory.glob("*.c") if p.name not in EXCLUDE)
    row = {"target": target, "instance": instance, "backend": backend,
           "header": str((source / header).relative_to(source)),
           "kat": str(kat.relative_to(source)),
           "kat_sha256": hashlib.sha256(kat.read_bytes()).hexdigest(),
           "sources": [str(p.relative_to(source)) for p in sources]}
    if not sources:
        row["status"] = "no_c_sources"
        return row
    library = OUT / f"{target}-{backend}.so"
    command = ["gcc", "-std=c11", "-O2", "-march=native", "-fPIC", "-shared",
               "-Wl,-z,defs", "-o", str(library), *(str(p) for p in sources)]
    try:
        build = subprocess.run(command, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        row["status"] = "build_timeout"
        return row
    row["build_returncode"] = build.returncode
    row["build_stderr"] = build.stderr[-1200:]
    if build.returncode:
        row["status"] = "build_failed"
        return row
    match = KAT_RE.search(kat.read_text(encoding="ascii").replace("\r\n", "\n"))
    if not match or int(match.group(3)) != 512:
        row["status"] = "kat_parse_or_profile_failed"
        return row
    queue = mp.Queue()
    child = mp.Process(target=one_call,
                       args=(library, (int(match.group(1)), match.group(2), match.group(4)), queue))
    child.start()
    child.join(10)
    if child.is_alive():
        child.kill()
        child.join()
        row["status"] = "call_timeout"
    elif child.exitcode or queue.empty():
        row["status"] = "call_crash"
        row["call_exitcode"] = child.exitcode
    else:
        row["call"] = queue.get_nowait()
        row["status"] = "one_kat_match" if row["call"].get("kat_match") else "one_kat_mismatch"
    return row


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    for item in json.loads((ROOT / "workspace/b_targets_sop/inventory.json").read_text()):
        if item["primitive"] != "hash":
            continue
        target = item["target"]
        source = ROOT / "third_party" / target / "source"
        header, instance = select(item, source)
        if not header:
            results.append({"target": target, "status": "no_standard_primary_reference_header"})
            print(target, results[-1]["status"], flush=True)
            continue
        kat_candidates = [source / p for p in item["kat_texts"]
                          if normalized(Path(p).stem) == normalized("KAT_2_12_" + instance)]
        kat_candidates.sort(key=lambda p: ("Test_Vectors" not in str(p),
                                           "Optimized_Implementation" in str(p),
                                           len(p.parts), str(p)))
        if not kat_candidates:
            results.append({"target": target, "instance": instance,
                            "header": header, "status": "exact_submitted_kat_missing"})
            print(target, results[-1]["status"], flush=True)
            continue
        kat = kat_candidates[0]
        for backend, path in (("reference", header),
                              ("optimized", header.replace("Reference_Implementation",
                                                           "Optimized_Implementation"))):
            if not (source / path).is_file():
                results.append({"target": target, "instance": instance, "backend": backend,
                                "status": "backend_header_missing", "header": path})
            else:
                results.append(probe(target, source, path, instance, kat, backend))
            print(target, backend, results[-1]["status"], flush=True)
    (OUT / "hash_report.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({"rows": len(results), "one_kat_match":
                      sum(x["status"] == "one_kat_match" for x in results)}))


if __name__ == "__main__":
    main()

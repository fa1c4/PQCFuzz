#!/usr/bin/env python3
"""Non-SOP build/KAT probe for primary A-tier CryptHash submissions.

This only inventories the submitted one-shot entry point. It does not create
an oracle, infer a normative property, or register a target.
"""
import ctypes
import hashlib
import json
import multiprocessing as mp
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IDS = ("hash-01", "hash-02", "hash-04", "hash-06", "hash-07", "hash-08",
       "hash-09", "hash-12", "hash-13", "hash-17", "hash-21", "hash-24",
       "hash-25", "hash-26", "hash-33", "hash-35")
EXCLUDE_C = {"KAT_CryptHash.c", "drng.c", "quick_test.c", "benchmark.c",
             "profile_info.c", "hash_cli.c", "iphe_selftest.c"}
KAT = re.compile(r"Msg_Len = (\d+)\nMsg = ([0-9A-F]*)\nDst_Len = (\d+)\nDst = ([0-9A-F]+)")


def pick(source):
    headers = [p for p in source.rglob("CryptHash_AlgorithmInstance.h")
               if "Others" not in p.parts and any("Reference_Implementation" in x for x in p.parts)
               and p.parent.name.endswith("512")]
    headers.sort(key=lambda p: ("x86" not in str(p).lower(), len(p.parts), str(p)))
    return headers[0] if headers else None


def call_one(library, bits, message_hex, message_bits, expected, queue):
    function = ctypes.CDLL(str(library)).CryptHash
    function.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p)
    function.restype = ctypes.c_int
    message = bytes.fromhex(message_hex)
    inbuf = ctypes.create_string_buffer(message if message else b"\x00")
    output = (ctypes.c_ubyte * (bits // 8 + 16))()
    code = function(bits, inbuf, message_bits, output)
    queue.put({"return_code": code, "kat_match": code == 0 and
               bytes(output[:bits // 8]).hex() == expected.lower()})


def main():
    out = ROOT / "workspace/a_targets_sop/probes"
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for target in IDS:
        source = ROOT / "third_party" / target / "source"
        header = pick(source)
        row = {"target": target, "header": str(header.relative_to(source)) if header else None}
        if header is None:
            row["status"] = "no_standard_reference_header"
            results.append(row)
            continue
        text = header.read_text(encoding="utf-8", errors="replace")
        name = re.search(r'#define\s+ALGORITHM_INSTANCE\s+"([^"]+)"', text)
        bits = re.search(r"#define\s+DIGEST_BIT_LENGTH\s+(\d+)", text)
        if not name or not bits:
            row["status"] = "header_identity_unparsed"
            results.append(row)
            continue
        row["instance"] = name.group(1)
        row["digest_bits"] = int(bits.group(1))
        kat_name = "KAT_2_12_" + row["instance"] + ".txt"
        candidates = [p for p in source.rglob(kat_name) if "Others" not in p.parts]
        candidates.sort(key=lambda p: (len(p.parts), str(p)))
        if not candidates:
            row["status"] = "submitted_kat_missing"
            results.append(row)
            continue
        kat = candidates[0]
        row["kat"] = str(kat.relative_to(source))
        row["kat_sha256"] = hashlib.sha256(kat.read_bytes()).hexdigest()
        sources = sorted(p for p in header.parent.glob("*.c") if p.name not in EXCLUDE_C)
        row["sources"] = [str(p.relative_to(source)) for p in sources]
        library = out / (target + ".so")
        command = ["gcc", "-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs",
                   "-o", str(library), *(str(p) for p in sources)]
        try:
            built = subprocess.run(command, capture_output=True, text=True, timeout=90)
            row["build_returncode"] = built.returncode
            row["build_stderr"] = built.stderr[-1500:]
            if built.returncode:
                row["status"] = "build_failed"
                results.append(row)
                continue
            match = KAT.search(kat.read_text(encoding="ascii"))
            if match is None:
                row["status"] = "kat_parse_failed"
                results.append(row)
                continue
            message_bits, message_hex, digest_bits, expected = match.groups()
            if int(digest_bits) != row["digest_bits"]:
                row["status"] = "kat_profile_mismatch"
                results.append(row)
                continue
            queue = mp.Queue()
            child = mp.Process(target=call_one,
                               args=(library, row["digest_bits"], message_hex,
                                     int(message_bits), expected, queue))
            child.start()
            child.join(10)
            if child.is_alive():
                child.kill()
                child.join()
                row["status"] = "call_timeout"
            elif child.exitcode != 0 or queue.empty():
                row["status"] = "call_crash"
                row["call_exitcode"] = child.exitcode
            else:
                observation = queue.get_nowait()
                row.update(observation)
                row["status"] = "one_kat_match" if row["kat_match"] else "one_kat_mismatch"
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            row["status"] = "probe_error"
            row["error"] = repr(exc)
        results.append(row)
        print(target, row["status"], flush=True)
    (out / "report.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"targets": len(results), "one_kat_match": sum(x["status"] == "one_kat_match"
                     for x in results), "report": str(out / "report.json")}))


if __name__ == "__main__":
    main()

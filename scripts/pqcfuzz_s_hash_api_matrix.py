#!/usr/bin/env python3
"""Diagnostic: exercise every submitted S-tier public CryptHash instance against its KAT.

This is deliberately separate from the registered SOP runtime. It never calls
an unregistered instance a passed SOP campaign or treats submitted KATs as an
independent specification.
"""
import argparse
import ctypes
import datetime as dt
import hashlib
import json
import platform
import re
import subprocess
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("03", "15", "16", "23", "28", "29", "34")
KAT_ROW = re.compile(r"Msg_Len = (\d+)\nMsg = ([0-9A-F]*)\nDst_Len = (\d+)\nDst = ([0-9A-F]+)")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree_sha(path):
    digest = hashlib.sha256()
    for file in sorted(p for p in path.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        digest.update(file.relative_to(path).as_posix().encode())
        digest.update(bytes.fromhex(sha(file)))
    return digest.hexdigest()


def submitted_cases(target, source):
    for header in sorted(source.rglob("CryptHash_AlgorithmInstance.h")):
        relative = header.relative_to(source)
        if "Others" in relative.parts:
            continue
        directory = header.parent
        instance = directory.name
        kat_instance = instance.removesuffix("-avxopt")
        backend = "optimized" if "Optimized_Implementation" in relative.parts else "reference"
        if target == "15":
            kat_name = "KAT_2_12_" + instance.lower().replace("-", "_") + ".txt"
        elif target == "03":
            kat_name = "KAT_2_12_" + kat_instance + ".txt"
        else:
            kat_name = "KAT_2_12_" + kat_instance + ".txt"
        candidates = [p for p in source.rglob(kat_name)
                      if "output" not in p.relative_to(source).parts]
        if len(candidates) != 1:
            raise RuntimeError(f"{target} {instance}: expected one submitted KAT, found {len(candidates)}")
        kat = candidates[0]
        bits = int(re.search(r"(256|512|768|1024)$", kat_instance).group(1)) if instance != "Litchi-XOF" else 1024
        sources = [directory / "CryptHash_AlgorithmInstance.c"]
        if target == "15":
            sources.append(directory / (instance.lower().replace("-", "_") + ".c"))
        if target == "34":
            sources.append(directory / "wchain_c.c")
        if target in ("28", "29") and backend == "optimized":
            sources.append(directory / "CryptHash_AlgorithmInstance_AVX2.s")
        if not all(p.is_file() for p in sources):
            raise RuntimeError(f"{target} {instance} {backend}: missing source")
        flags = ["-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs"]
        if backend == "optimized" and target in ("03", "16", "28", "29"):
            flags.append("-mavx2")
        if backend == "optimized" and target == "16":
            flags.append("-DLLH_FORCE_AVX2=1")
        if instance.endswith("avxopt"):
            flags.append("-mavx2")
        yield {"target": "hash-" + target, "instance": instance, "backend": backend,
               "digest_bits": bits, "kat": str(kat.relative_to(source)),
               "kat_sha256": sha(kat), "sources": [str(p.relative_to(source)) for p in sources],
               "source_sha256": {str(p.relative_to(source)): sha(p) for p in sources},
               "flags": flags, "core": None if target != "15" else instance.lower().replace("-", "_"),
               "wrapper": True}
    if target == "15":
        optimized = source / "Litchi/Implementations/Optimized_Implementation"
        for directory in sorted(p for p in optimized.iterdir() if p.is_dir()):
            instance = directory.name
            symbol = instance.lower().replace("-", "_")
            implementation = directory / (symbol + ".c")
            if not implementation.is_file():
                raise RuntimeError(f"{instance}: missing optimized core source")
            kat = source / "Litchi/Test_Vectors" / ("KAT_2_12_" + symbol + ".txt")
            bits = 1024 if instance == "Litchi-XOF" else int(instance.rsplit("-", 1)[1])
            path = str(implementation.relative_to(source))
            yield {"target": "hash-15", "instance": instance, "backend": "optimized-core",
                   "digest_bits": bits, "kat": str(kat.relative_to(source)),
                   "kat_sha256": sha(kat), "sources": [path],
                   "source_sha256": {path: sha(implementation)},
                   "flags": ["-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs"],
                   "core": symbol, "wrapper": False, "byte_length_api": True}
    if target == "03":
        for header in sorted(source.rglob("CryptHash_AlgorithmInstance.h")):
            relative = header.relative_to(source)
            if "Others" not in relative.parts:
                continue
            directory = header.parent
            instance = directory.name
            bits = int(instance.rsplit("-", 1)[1])
            kat = source / "C Hash/Test_Vectors" / f"KAT_2_12_CHash_{bits}.txt"
            backend = "other-" + next(part for part in relative.parts
                                      if part.endswith("_Implementation")).lower()
            sources = [directory / "CryptHash_AlgorithmInstance.c", directory / "c-hash.c"]
            engine_header = (directory / "c-hash.h").read_text(encoding="utf-8")
            exported_engine = bool(re.search(r"(?m)^int c_engine_permute\(", engine_header))
            flags = ["-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs"]
            if "Optimized_Implementation" in relative.parts:
                flags.append("-mavx2")
            yield {"target": "hash-03", "instance": instance, "backend": backend,
                   "digest_bits": bits, "kat": str(kat.relative_to(source)),
                   "kat_sha256": sha(kat), "sources": [str(p.relative_to(source)) for p in sources],
                   "source_sha256": {str(p.relative_to(source)): sha(p) for p in sources},
                   "flags": flags,
                   "core": None, "wrapper": True, "other_c_hash": True,
                   "engine_expected_exported": exported_engine}


def check_wchain_helpers(library, source):
    """Exercise every public function declared by the submitted wchain_c.h."""
    checked = {}
    mismatches = []
    mismatch_counts = {}
    crypt = library.wchain_crypt_hash_c
    crypt.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p)
    crypt.restype = ctypes.c_int
    for version, digest_bits, words, block_bytes in ((1, 512, 9, 144), (2, 1024, 18, 288)):
        kat = source / ("WChain/Implementations and Test_Vectors/Test_Vectors/"
                        f"KAT_2_12_WChain-V{version}-{digest_bits}.txt")
        rows = {}
        for match in KAT_ROW.finditer(kat.read_text(encoding="ascii")):
            bits, message_hex, out_bits, digest_hex = match.groups()
            bits = int(bits)
            if bits in (0, 1, 24, 1152, 1153, 2304, 4096):
                if int(out_bits) != digest_bits:
                    raise RuntimeError("WChain helper KAT profile mismatch")
                rows[bits] = (bytes.fromhex(message_hex), bytes.fromhex(digest_hex))
        if len(rows) != 7:
            raise RuntimeError("WChain helper KAT samples missing")
        bit_hash = getattr(library, f"wchain_v{version}_hash_bits_c")
        bit_hash.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p)
        byte_hash = getattr(library, f"wchain_v{version}_hash_c")
        byte_hash.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)
        calls = 0
        for bits, (message, expected) in rows.items():
            input_buffer = ctypes.create_string_buffer(message if message else b"\0")
            for name in ("bits", "crypt", "bytes") if bits % 8 == 0 else ("bits", "crypt"):
                output = (ctypes.c_ubyte * 256)(*([0xa5] * 256))
                if name == "bits":
                    bit_hash(input_buffer, bits, output)
                elif name == "crypt":
                    if crypt(digest_bits, input_buffer, bits, output) != 0:
                        raise RuntimeError(f"WChain V{version} direct crypt status mismatch")
                else:
                    byte_hash(input_buffer, bits // 8, output)
                if bytes(output[:len(expected)]) != expected or any(
                        value != 0xa5 for value in output[len(expected):]):
                    raise RuntimeError(f"WChain V{version} {name} helper KAT mismatch at {bits} bits")
                calls += 1
        scalar = getattr(library, f"wchain_v{version}_compress_c")
        scalar.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
        for lanes, suffix in ((4, "avx2"), (8, "avx512")):
            vector = getattr(library, f"wchain_v{version}_compress{lanes}_{suffix}")
            vector.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
            States = (ctypes.c_uint64 * words) * lanes
            Blocks = (ctypes.c_ubyte * block_bytes) * lanes
            states, blocks, observed = States(), Blocks(), States()
            for lane in range(lanes):
                for index in range(words):
                    states[lane][index] = ((lane + 1) * 0x9e3779b97f4a7c15 + index * 17) & ((1 << 64) - 1)
                for index in range(block_bytes):
                    blocks[lane][index] = (lane * 17 + index * 23) & 255
            vector(observed, states, blocks)
            for lane in range(lanes):
                expected = (ctypes.c_uint64 * words)()
                scalar(expected, states[lane], blocks[lane])
                if list(observed[lane]) != list(expected):
                    key = f"V{version}-{suffix}"
                    mismatch_counts[key] = mismatch_counts.get(key, 0) + 1
                    if mismatch_counts[key] == 1:
                        mismatches.append({
                            "diagnostic": "WChain direct SIMD compression differs from scalar",
                            "version": version, "simd": suffix, "lane": lane,
                            "state_u64": list(states[lane]),
                            "block_hex": bytes(blocks[lane]).hex(),
                            "scalar_u64": list(expected), "simd_u64": list(observed[lane])})
            calls += lanes + 1
        checked[f"V{version}"] = {"direct_hash_calls": calls,
                                  "sampled_kat_bits": sorted(rows),
                                  "simd_lanes_checked": [4, 8]}
    return {"checks": checked, "mismatches": mismatches,
            "mismatch_counts": mismatch_counts}


def worker(payload):
    source = Path(payload["source"])
    case = payload["case"]
    for relative, expected in case["source_sha256"].items():
        if sha(source / relative) != expected:
            raise RuntimeError("submitted source digest drift: " + relative)
    library = ctypes.CDLL(payload["library"])
    wrapper = library.CryptHash if case["wrapper"] else None
    if wrapper:
        wrapper.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p)
        wrapper.restype = ctypes.c_int
    core = getattr(library, case["core"]) if case["core"] else None
    if core:
        core.argtypes = ((ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_ulonglong)
                         if case["core"] == "litchi_xof" else
                         (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong))
        core.restype = None
    streaming = None
    if case.get("byte_length_api"):
        class State(ctypes.Structure):
            _fields_ = [("A", ctypes.c_uint64 * 25), ("S", ctypes.c_uint64 * 25),
                        ("sec", ctypes.c_uint64), ("pos", ctypes.c_uint64),
                        ("counter", ctypes.c_uint64)]
        streaming = [getattr(library, case["core"] + suffix)
                     for suffix in ("_init", "_absorb", "_finalize", "_squeeze")]
        streaming[0].argtypes = (ctypes.c_void_p,)
        streaming[1].argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong)
        streaming[2].argtypes = (ctypes.c_void_p,)
        streaming[3].argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p)
    other_bits = other_bytes = engine = None
    if case.get("other_c_hash"):
        prefix = f"c_hash_{case['digest_bits']}"
        other_bits = getattr(library, prefix + "_bits")
        other_bits.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p)
        other_bits.restype = ctypes.c_int
        other_bytes = getattr(library, prefix)
        other_bytes.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)
        other_bytes.restype = ctypes.c_int
        engine = (getattr(library, "c_engine_permute", None)
                  if case["engine_expected_exported"] else None)
        if engine:
            engine.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
            engine.restype = ctypes.c_int
    kat = source / case["kat"]
    if sha(kat) != case["kat_sha256"]:
        raise RuntimeError("KAT digest drift")
    text = kat.read_text(encoding="ascii")
    count = 0
    calls = 0
    skipped = 0
    stream_cases = 0
    for match in KAT_ROW.finditer(text):
        bits, msg_hex, out_bits, expected_hex = match.groups()
        bits, out_bits = int(bits), int(out_bits)
        message, expected = bytes.fromhex(msg_hex), bytes.fromhex(expected_hex)
        if (bits != count or out_bits != case["digest_bits"] or
                len(message) != (bits + 7) // 8 or len(expected) != out_bits // 8):
            raise RuntimeError(f"malformed KAT row {count}")
        if case.get("sample_indices") is not None and bits not in case["sample_indices"]:
            skipped += 1
            count += 1
            continue
        if case.get("byte_length_api") and bits % 8:
            skipped += 1
            count += 1
            continue
        input_buffer = ctypes.create_string_buffer(message if message else b"\0")
        functions = (("CryptHash", case["core"]) if core and wrapper else
                     ((case["core"],) if core else ("CryptHash",)))
        for function_name in functions:
            output = (ctypes.c_ubyte * 256)(*([0xa5] * 256))
            if function_name == "CryptHash":
                code = wrapper(out_bits, input_buffer, bits, output)
                if code != 0:
                    raise RuntimeError(f"row {count} CryptHash status {code}")
            elif function_name == "litchi_xof":
                core(output, out_bits // 8 if case.get("byte_length_api") else out_bits,
                     input_buffer, bits // 8 if case.get("byte_length_api") else bits)
            else:
                core(output, input_buffer, bits // 8 if case.get("byte_length_api") else bits)
            if bytes(output[:len(expected)]) != expected:
                raise RuntimeError(f"row {count} {function_name} digest mismatch")
            if any(value != 0xa5 for value in output[len(expected):]):
                raise RuntimeError(f"row {count} {function_name} wrote past declared digest")
            calls += 1
        if streaming:
            state = State()
            stream_output = (ctypes.c_ubyte * 256)(*([0xa5] * 256))
            streaming[0](ctypes.byref(state))
            split = len(message) // 2
            first = ctypes.create_string_buffer(message[:split] if split else b"\0")
            second = ctypes.create_string_buffer(message[split:] if len(message) != split else b"\0")
            streaming[1](ctypes.byref(state), first, split)
            streaming[1](ctypes.byref(state), second, len(message) - split)
            streaming[2](ctypes.byref(state))
            half = len(expected) // 2
            streaming[3](stream_output, half, ctypes.byref(state))
            streaming[3](ctypes.byref(stream_output, half), len(expected) - half, ctypes.byref(state))
            if bytes(stream_output[:len(expected)]) != expected or any(
                    value != 0xa5 for value in stream_output[len(expected):]):
                raise RuntimeError(f"row {count} {case['core']} incremental digest mismatch")
            stream_cases += 1
        if other_bits:
            output = (ctypes.c_ubyte * 256)(*([0xa5] * 256))
            code = other_bits(input_buffer, bits, output)
            if code != 0 or bytes(output[:len(expected)]) != expected or any(
                    value != 0xa5 for value in output[len(expected):]):
                raise RuntimeError(f"row {count} c_hash_{case['digest_bits']}_bits mismatch")
            calls += 1
            if bits % 8 == 0:
                output = (ctypes.c_ubyte * 256)(*([0xa5] * 256))
                code = other_bytes(input_buffer, bits // 8, output)
                if code != 0 or bytes(output[:len(expected)]) != expected or any(
                        value != 0xa5 for value in output[len(expected):]):
                    raise RuntimeError(f"row {count} c_hash_{case['digest_bits']} mismatch")
                calls += 1
        count += 1
    if count != 4097:
        raise RuntimeError(f"expected 4097 KAT rows, got {count}")
    if case["core"] == "litchi_xof" and case.get("byte_length_api"):
        blocks = library.litchi_xof_squeezeblocks
        blocks.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p)
        state = State()
        message = ctypes.create_string_buffer(b"abc")
        streaming[0](ctypes.byref(state))
        streaming[1](ctypes.byref(state), message, 3)
        streaming[2](ctypes.byref(state))
        block_output = (ctypes.c_ubyte * 256)()
        direct_output = (ctypes.c_ubyte * 256)()
        blocks(block_output, 2, ctypes.byref(state))
        core(direct_output, 256, message, 3)
        if bytes(block_output) != bytes(direct_output):
            raise RuntimeError("litchi_xof_squeezeblocks differs from one-shot output")
    engine_output = None
    if engine:
        seed = ctypes.create_string_buffer(bytes(range(192)))
        first, second = (ctypes.c_ubyte * 192)(), (ctypes.c_ubyte * 192)()
        if engine(seed, first) != 0 or engine(seed, second) != 0 or bytes(first) != bytes(second):
            raise RuntimeError("c_engine_permute did not return deterministic output")
        engine_output = bytes(first).hex()
    wchain_helpers = check_wchain_helpers(library, source) if case["target"] == "hash-34" else None
    discrepancy = bool(wchain_helpers and wchain_helpers["mismatches"])
    missing_symbol = bool(case.get("engine_expected_exported") and not engine)
    print(json.dumps({"status": "discrepancy" if discrepancy else
                      "missing_public_symbol" if missing_symbol else "matched",
                      "records": count,
                      "records_checked": count - skipped, "records_skipped": skipped,
                      "digest_calls": calls, "stream_cases": stream_cases,
                      "engine_determinism_case": bool(engine),
                      "engine_direct_test": ("called" if engine else
                                             "missing_export" if missing_symbol else
                                             "not_applicable_static_inline" if case.get("other_c_hash") else None),
                      "engine_output_hex": engine_output,
                      "wchain_helpers": wchain_helpers,
                      "xof_two_block_case": case["core"] == "litchi_xof" and
                      bool(case.get("byte_length_api"))}))
    if discrepancy or missing_symbol:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--target", choices=["hash-" + t for t in TARGETS])
    parser.add_argument("--coverage", action="store_true",
                        help="instrument algorithm C functions with gcov (diagnostic only)")
    args = parser.parse_args()
    if args.worker:
        worker(json.loads(args.worker.read_text()))
        return 0
    config = json.loads((ROOT / "configs/targets.json").read_text())
    registered = {record["target"]: record for record in config["targets"]}
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    run = ROOT / "workspace/s_hash_api_matrix/runs" / run_id
    run.mkdir(parents=True)
    cases = []
    source_digests = {}
    for target in TARGETS:
        name = "hash-" + target
        if args.target and args.target != name:
            continue
        source = ROOT / registered[name]["source"]
        digest = tree_sha(source)
        if digest != registered[name]["source_digest"]:
            raise RuntimeError(f"{name}: source digest drift")
        source_digests[name] = digest
        cases.extend(submitted_cases(target, source))
    results = []
    for index, case in enumerate(cases):
        source = ROOT / registered[case["target"]]["source"]
        library = run / f"{case['target']}-{case['instance']}-{case['backend']}.so"
        coverage_optimization = ("-O1" if case["target"] == "hash-16" and
                                 case["instance"] == "LLH-1024" and
                                 case["backend"] == "optimized" else "-O0")
        flags = ([coverage_optimization if value == "-O2" else value for value in case["flags"]] +
                 ["--coverage"] if args.coverage else case["flags"])
        command = ["gcc", *flags, "-o", str(library),
                   *(str(source / path) for path in case["sources"])]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=120)
        result = {"case": case, "build_argv": command, "build_returncode": compiled.returncode,
                  "build_stdout": compiled.stdout[-10000:], "build_stderr": compiled.stderr[-10000:]}
        if compiled.returncode == 0:
            result["library_sha256"] = sha(library)
            payload = run / f"case-{index}.json"
            worker_case = dict(case)
            if args.coverage:
                worker_case["sample_indices"] = [0, 1, 7, 8, 511, 512, 513,
                                                 1023, 1024, 1152, 2304, 4096]
            payload.write_text(json.dumps({"source": str(source), "library": str(library),
                                           "case": worker_case}))
            try:
                tested = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                         "--worker", str(payload)],
                                        capture_output=True, text=True, timeout=180)
                result.update({"test_returncode": tested.returncode,
                               "test_stdout": tested.stdout[-10000:],
                               "test_stderr": tested.stderr[-10000:]})
                try:
                    result["worker_result"] = json.loads(tested.stdout)
                except json.JSONDecodeError:
                    result["worker_result"] = None
            except subprocess.TimeoutExpired:
                result.update({"test_returncode": None, "test_stderr": "worker timeout"})
            if args.coverage:
                functions = []
                for notes in sorted(run.glob(library.name + "-*.gcno")):
                    covered = subprocess.run(["gcov", "-f", "-o", str(run), str(notes)],
                                             cwd=run, capture_output=True, text=True, timeout=30)
                    if covered.returncode != 0:
                        result.setdefault("coverage_errors", []).append(covered.stderr[-2000:])
                    for match in re.finditer(r"Function '([^']+)'\nLines executed:([0-9.]+)% of (\d+)",
                                             covered.stdout):
                        functions.append({"name": match.group(1), "line_percent": float(match.group(2)),
                                          "lines": int(match.group(3)), "notes": notes.name})
                result["function_coverage"] = {
                    "instrumented": len(functions),
                    "executed": sum(item["line_percent"] > 0 for item in functions),
                    "unhit": [item for item in functions if item["line_percent"] == 0]}
        results.append(result)
        status = (result.get("worker_result") or {}).get("status", "build_or_worker_failed")
        print(case["target"], case["instance"], case["backend"], status, flush=True)
    report = {"kind": "diagnostic_submitted_api_kat_matrix_not_sop_campaign",
              "run_id": run_id, "script_sha256": sha(Path(__file__).resolve()),
              "source_tree_sha256": source_digests,
              "compiler_version": subprocess.run(["gcc", "--version"], capture_output=True,
                                                  text=True, check=True).stdout.splitlines()[0],
              "python_version": platform.python_version(),
              "machine": platform.machine(),
              "coverage_instrumented": args.coverage,
              "kat_scope": "representative_rows_for_coverage" if args.coverage else "all_4097_rows_per_case",
              "cases": len(cases),
              "matched": sum(x.get("test_returncode") == 0 for x in results),
              "kat_matched": sum((x.get("worker_result") or {}).get("records_checked", 0) > 0
                                 for x in results),
              "results": results}
    (run / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (run / "sha256.json").write_text(json.dumps({p.name: sha(p) for p in run.iterdir()
                                                 if p.is_file() and p.name != "sha256.json"}, indent=2) + "\n")
    print(json.dumps({"run": str(run), "cases": report["cases"], "matched": report["matched"]}))
    return 0 if report["matched"] == report["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

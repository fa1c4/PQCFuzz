#!/usr/bin/env python3
"""Non-SOP submitted-vector ABI probes for one B-tier KEM, signature and KEX.

The submitted KAT drivers provide the RNG symbol required by their libraries.
No generated key material is printed or registered as a campaign result.
"""
import ctypes
import hashlib
import json
import multiprocessing as mp
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "workspace/b_targets_sop/probes/asymmetric"
CASES = {
    "kem-37": ("Implementations/Reference_Implementation/TriQ-KEM-128",
               "Test_Vectors/KAT_KEM_TriQ-KEM-128.txt", "KAT_KEM.c"),
    "sign-02": ("Implementations/Reference_Implementation/BiT-128",
                "Test_Vectors/KAT_SIG_BiT-128.txt", "KAT_SIG.c"),
    "kex-09": ("TriQ-KEX/Implementations/Reference_Implementation/TriQ-KEX-128",
               "TriQ-KEX/Test_Vectors/KAT_KEX_TriQ-KEX-128.txt", "KAT_KEX.c"),
}


def records(path):
    rows, row = [], {}
    with path.open(encoding="ascii", errors="replace") as stream:
        for line in stream:
            if line.startswith("Count =") and row:
                rows.append(row)
                row = {}
            if " = " in line:
                key, value = line.split(" = ", 1)
                row[key.strip()] = value.strip()
    if row:
        rows.append(row)
    return rows


def buffer(value):
    data = bytes.fromhex(value)
    return ctypes.create_string_buffer(data if data else b"\x00"), len(data)


def observe(library, target, row, queue):
    try:
        lib = ctypes.CDLL(str(library.resolve()))
        if target == "kem-37":
            expected = bytes.fromhex(row["SS"])
            sk, sklen = buffer(row["SK"])
            ct, ctlen = buffer(row["CT"])
            output = (ctypes.c_ubyte * (len(expected) + 16))()
            length = ctypes.c_ulonglong(len(expected))
            call = lib.kem_dec
            call.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong,
                             ctypes.c_void_p, ctypes.c_ulonglong,
                             ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong))
            call.restype = ctypes.c_int
            code = call(sk, sklen, ct, ctlen, output, ctypes.byref(length))
            queue.put({"return_code": code, "output_length": length.value,
                       "kat_match": code == 0 and length.value == len(expected) and
                       bytes(output[:len(expected)]) == expected})
        elif target == "sign-02":
            pk, pklen = buffer(row["PK"])
            signature, snlen = buffer(row["Sn"])
            message, mlen = buffer(row["M"])
            call = lib.sig_verify
            call.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong,
                             ctypes.c_void_p, ctypes.c_ulonglong,
                             ctypes.c_void_p, ctypes.c_ulonglong)
            call.restype = ctypes.c_int
            code = call(pk, pklen, signature, snlen, message, mlen)
            queue.put({"return_code": code, "valid_signature_accepted": code == 0})
        else:
            expected = bytes.fromhex(row["SS"])
            argtypes = (ctypes.c_void_p, ctypes.c_ulonglong,
                        ctypes.c_void_p, ctypes.c_ulonglong,
                        ctypes.c_void_p, ctypes.c_ulonglong,
                        ctypes.c_void_p, ctypes.c_ulonglong,
                        ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong))
            observations = {}
            for role, keys in (("a", ("SKa", "PKb", "M2", "Pass1_Sta")),
                               ("b", ("SKb", "PKa", "M1", "Pass2_Stb"))):
                inputs = [buffer(row[key]) for key in keys]
                output = (ctypes.c_ubyte * (len(expected) + 16))()
                length = ctypes.c_ulonglong(len(expected))
                call = getattr(lib, "kex_derive_ss_" + role)
                call.argtypes = argtypes
                call.restype = ctypes.c_int
                argv = [value for pair in inputs for value in pair]
                code = call(*argv, output, ctypes.byref(length))
                observations[role] = {"return_code": code, "output_length": length.value,
                    "kat_match": code == 0 and length.value == len(expected) and
                    bytes(output[:len(expected)]) == expected}
            queue.put(observations)
    except Exception as exc:
        queue.put({"error": repr(exc)})


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    for target, (directory, kat_relative, driver) in CASES.items():
        source = ROOT / "third_party" / target / "source"
        implementation = source / directory
        kat = source / kat_relative
        if target == "sign-02":
            files = sorted(path for path in implementation.glob("*.c")
                           if path.name != "packing.c") + [implementation / "packing.c"]
            include_dirs = [implementation]
        else:
            files = [implementation / name for name in
                     ("KEM_AlgorithmInstance.c" if target == "kem-37" else "KEX_AlgorithmInstance.c",
                      "drng.c", "auxfunc.c")]
            files += sorted((implementation / "src/common").glob("*.c"))
            files += sorted((implementation / "src/ref").glob("*.c"))
            files.append(implementation / driver)
            include_dirs = [implementation, implementation / "src/common",
                            implementation / "src/common/triq-128",
                            implementation / "src/ref", implementation / "src/ref/triq-128"]
        library = OUT / f"{target}.so"
        command = ["gcc", "-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs",
                   *(flag for directory in include_dirs for flag in ("-I", str(directory))),
                   "-o", str(library), *(str(path) for path in files)]
        build = subprocess.run(command, capture_output=True, text=True, timeout=90)
        result = {"target": target, "source_files":
                  [str(path.relative_to(source)) for path in files],
                  "kat": kat_relative, "kat_sha256": hashlib.sha256(kat.read_bytes()).hexdigest(),
                  "build_returncode": build.returncode, "build_stderr": build.stderr[-1000:]}
        if build.returncode:
            result["status"] = "build_failed"
        else:
            rows = records(kat)
            result["vector_count"] = len(rows)
            result["vector_matches"] = 0
            for index, row in enumerate(rows):
                queue = mp.Queue()
                child = mp.Process(target=observe, args=(library, target, row, queue))
                child.start()
                child.join(20)
                if child.is_alive():
                    child.kill()
                    child.join()
                    result["status"] = "call_timeout"
                    result["first_failed_index"] = index
                    break
                if child.exitcode or queue.empty():
                    result["status"] = "call_crash"
                    result["call_exitcode"] = child.exitcode
                    result["first_failed_index"] = index
                    break
                observation = queue.get_nowait()
                if index == 0:
                    result["observation"] = observation
                if target == "sign-02":
                    match = observation.get("valid_signature_accepted") is True
                elif target == "kem-37":
                    match = observation.get("kat_match") is True
                else:
                    match = all(observation.get(role, {}).get("kat_match") is True
                                for role in ("a", "b"))
                if not match:
                    result["status"] = "vector_mismatch"
                    result["first_failed_index"] = index
                    result["failed_observation"] = observation
                    break
                result["vector_matches"] += 1
            else:
                result["status"] = "submitted_vector_calls_match"
        results.append(result)
        print(target, result["status"], result.get("observation"), flush=True)
    (OUT / "report.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()

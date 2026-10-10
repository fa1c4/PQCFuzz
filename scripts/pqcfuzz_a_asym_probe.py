#!/usr/bin/env python3
"""Probe one submitted public KAT against each A-tier asymmetric reference API."""
import ctypes
import hashlib
import json
import multiprocessing as mp
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "workspace/a_targets_sop/probes/asymmetric/auto"
CHOICES = {
    "sign-01": ("Aigis-Sig+-I", "Test_Vectors/KAT_SIG_Aigis-sig1.txt"),
    "sign-10": ("Facto-DSA-128", "Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-128.txt"),
    "sign-17": ("OPSsig-128", "Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-128/KAT_SIG_OPSsig-128-reference.txt"),
    "sign-23": ("SHUTTLE-128", "Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-128.txt"),
    "sign-31": ("TSUOV_128", "Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_128.txt"),
    "kem-01": ("Aigis-Enc+-I", "Test_Vectors/KAT_KEM_Aigis-enc1.txt"),
    "kem-02": ("Amoeba-576", "Test_Vectors/KAT_KEM_Amoeba128.txt"),
    "kem-04": ("bag_piglet128", "Test_Vectors/KAT_KEM_bag_piglet_128.txt"),
    "kem-15": ("FLIT128", "Test_Vectors/KAT_KEM_FLIT128_REF.txt"),
    "kem-16": ("HARE-128", "Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-128-kr.txt"),
    "kem-19": ("Lore-L1", "Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L1.txt"),
    "kem-26": ("HQC-128", "Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-128.txt"),
    "kem-27": ("NTRE-128", "Implementations/Reference_Implementation/NTRE-128/output/KAT_KEM_NTRE-128.txt"),
    "kem-28": ("OAEP-NTRU-648", "Test_Vectors/KAT_KEM_OAEP-NTRU-648.txt"),
    "kem-29": ("PolarKEM-128", "Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-128.txt"),
    "kem-30": ("POLARLAC-128", "Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-128.txt"),
    "kem-36": ("TRIKE-2", "Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-2.txt"),
}

SOURCE_OVERRIDES = {
    "sign-01": "sign.c polyvec.c packing.c poly.c reduce.c ntt.c rounding.c fips202.c hashkdf.c auxfunc.c SIG_AlgorithmInstance.c drng.c pspm.c rng.c KAT_SIG.c".split(),
    "kem-01": "cbd.c fips202.c poly.c speed_test/cpucycles.c reduce.c precomp.c ntt.c polyvec.c owcpa.c kem.c verify.c hashkdf.c gen_a.c speed_test/speed_print.c kat_test/auxfunc.c kat_test/KEM_AlgorithmInstance.c kat_test/drng.c pack.c kat_test/rng.c kat_test/KAT_KEM.c".split(),
}
FLAG_OVERRIDES = {
    "sign-01": ["-DPARAMS=1", "-DUSE_ICCS"],
    "kem-01": ["-DPARAMS=1", "-DUSE_NICCS_API"],
    "kem-02": ["-Dinline=static inline"],
    "kem-16": ["-DHARE_BACKEND_KR", "-DHARE_SYMMETRIC_MODE_B"],
    "kem-19": ["-DLORE_LEVEL=1"],
}


def first_row(path):
    row = {}
    with path.open("rb") as stream:
        for line in stream:
            if line.startswith(b"Count =") and row:
                break
            if b" = " in line:
                key, value = line.rstrip(b"\r\n").split(b" = ", 1)
                row[key.decode("ascii")] = value.decode("ascii")
    return row


def observe(library, primitive, row, queue):
    try:
        lib = ctypes.CDLL(str(library))
        def buffer(key):
            data = bytes.fromhex(row[key])
            if len(data) != int(row[key + "_Len"]):
                raise ValueError("submitted length mismatch: " + key)
            return ctypes.create_string_buffer(data if data else b"\x00"), len(data)
        if primitive == "sign":
            pk, pklen = buffer("PK")
            signature, snlen = buffer("Sn")
            message, mlen = buffer("M")
            call = lib.sig_verify
            call.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                             ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_ulonglong)
            call.restype = ctypes.c_int
            code = call(pk, pklen, signature, snlen, message, mlen)
            queue.put({"reached": True, "return_code": code,
                       "kat_match": code == 0})
        else:
            sk, sklen = buffer("SK")
            ct, ctlen = buffer("CT")
            expected = bytes.fromhex(row["SS"])
            if len(expected) != int(row["SS_Len"]):
                raise ValueError("submitted SS length mismatch")
            output = (ctypes.c_ubyte * (len(expected) + 16))(*([0xa5] * (len(expected) + 16)))
            size = ctypes.c_ulonglong(len(expected))
            call = lib.kem_dec
            call.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                             ctypes.c_ulonglong, ctypes.c_void_p,
                             ctypes.POINTER(ctypes.c_ulonglong))
            call.restype = ctypes.c_int
            code = call(sk, sklen, ct, ctlen, output, ctypes.byref(size))
            queue.put({"reached": True, "return_code": code,
                       "output_length": size.value,
                       "guard_modified": any(x != 0xa5 for x in output[len(expected):]),
                       "kat_match": code == 0 and size.value == len(expected) and
                                    bytes(output[:len(expected)]) == expected})
    except Exception as exc:
        queue.put({"error": repr(exc)})


def probe(target, instance, kat_relative, matrix, *, header_override=None,
          parameter_set=None):
    source = ROOT / "third_party" / target / "source"
    header = header_override or next((entry["path"] for entry in matrix["primary_reference_headers"]
                                      if "/" + instance + "/" in entry["path"]), None)
    if header is None:
        raise RuntimeError("primary reference header not found")
    root_relative = header.split("/" + instance + "/")[0] + "/" + instance
    implementation = source / root_relative
    files = sorted(path for path in implementation.rglob("*.c")
                   if (path.name.startswith("KAT_") or
                       not any(token in path.name.lower() for token in
                               ("test", "bench", "speed", "selftest", "hardening")))
                   and not ("tests" in path.parts and not path.name.startswith("KAT_")))
    if target in SOURCE_OVERRIDES:
        files = [implementation / name for name in SOURCE_OVERRIDES[target]]
    if target == "kem-16":
        shared = implementation.parents[1] / "_shared"
        files += sorted((shared / "hare_core/common").glob("*.c"))
        files += sorted((shared / "hare_core/ref").glob("*.c"))
        files += sorted((shared / "api_pkc").glob("*.c"))
    includes = sorted({path.parent for path in implementation.rglob("*.h")} |
                      {path.parent for path in files} |
                      ({shared / "hare_core/common", shared / "hare_core/ref"}
                       if target == "kem-16" else set()))
    kat = source / kat_relative
    row = first_row(kat)
    library = OUT / f"{target}.so"
    argv = ["gcc", "-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs",
            "-march=native", *FLAG_OVERRIDES.get(target, []), *(flag for directory in includes
                                for flag in ("-I", str(directory))),
            "-o", str(library), *(str(path) for path in files)]
    build = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    report = {"target": target, "parameter_set": parameter_set or instance,
              "primitive": matrix["primitive"], "header": header,
              "kat": kat_relative,
              "kat_sha256": hashlib.sha256(kat.read_bytes()).hexdigest(),
              "sources": [str(path.relative_to(source)) for path in files],
              "includes": [str(path.relative_to(source)) for path in includes],
              "flags": ["-march=native", *FLAG_OVERRIDES.get(target, [])],
              "build_returncode": build.returncode,
              "build_stderr_tail": build.stderr[-3000:]}
    if build.returncode:
        report["status"] = "build_failed"
        return report
    queue = mp.Queue()
    child = mp.Process(target=observe, args=(library, matrix["primitive"], row, queue))
    child.start()
    child.join(40)
    if child.is_alive():
        child.kill()
        child.join()
        report["status"] = "call_timeout"
    elif child.exitcode or queue.empty():
        report["status"] = "call_crash"
        report["exitcode"] = child.exitcode
    else:
        report["observation"] = queue.get_nowait()
        report["status"] = ("first_vector_match" if report["observation"].get("kat_match")
                            else "first_vector_mismatch")
    return report


def main():
    matrix = {item["target"]: item for item in
              json.loads((ROOT / "workspace/a_targets_sop/api_matrix.json").read_text())}
    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    for target, (instance, kat) in CHOICES.items():
        try:
            result = probe(target, instance, kat, matrix[target])
        except Exception as exc:
            result = {"target": target, "parameter_set": instance,
                      "status": "probe_error", "error": repr(exc)}
        results.append(result)
        (OUT / "report.json").write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
        print(json.dumps({"target": target, "parameter_set": instance,
                          "status": result["status"],
                          "observation": result.get("observation"),
                          "build_stderr_tail": result.get("build_stderr_tail", "")[-350:]}),
              flush=True)


if __name__ == "__main__":
    main()

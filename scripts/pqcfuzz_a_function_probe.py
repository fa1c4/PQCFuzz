#!/usr/bin/env python3
"""Isolated first-instance diagnostics for A-tier KEM/signature public calls.

This qualifies API wiring for later SOP registration. It is not a campaign and
does not turn a submitted KAT into an independent normative claim.
"""
import argparse
import concurrent.futures
import ctypes
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BATCH = ROOT / "workspace/a_targets_fuzz/runs/20261009T142035Z-44cb8b81ca19/summary.json"
OUT = ROOT / "workspace/a_targets_sop/probes/public_functions"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_row(path, signature):
    rows = []
    for block in path.read_text(encoding="ascii").replace("\r\n", "\n").split("Count = ")[1:]:
        row = {key: value for key, value in
               (line.split(" = ", 1) for line in block.splitlines() if " = " in line)}
        if not signature or int(row.get("M_Len", 0)) > 0:
            rows.append(row)
            break
    if not rows:
        raise ValueError("no suitable submitted record")
    return rows[0]


def buffer(raw):
    return ctypes.create_string_buffer(raw if raw else b"\x00")


def sized(capacity):
    return (ctypes.c_ubyte * (capacity + 16))(*([0xa5] * (capacity + 16)))


def guard_ok(value, capacity):
    return all(x == 0xa5 for x in value[capacity:])


def reseed(lib, seed):
    context = ctypes.c_char.in_dll(lib, "drng_algorithm")
    call = lib.init_random_number
    call.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong)
    call.restype = ctypes.c_int
    return call(ctypes.addressof(context), buffer(seed), len(seed))


def first_instance(target):
    batch = json.loads(BATCH.read_text())
    return next(x for x in batch["completed"] if x["target"] == target)


def child(target):
    prior = first_instance(target)
    instance = prior["parameter_set"]
    run = ROOT / prior["run"]
    cfg = json.loads((ROOT / "oracles" / target / "data/instances.json").read_text())[instance]
    kat = run / "source" / cfg["kat"]
    if sha(kat) != cfg["kat_sha256"]:
        raise ValueError("KAT digest drift")
    row = source_row(kat, target.startswith("sign-"))
    library = run / "build" / (instance + ".so")
    lib = ctypes.CDLL(str(library))
    seed = bytes.fromhex(row["Seed"])
    if len(seed) != int(row["Seed_Len"]):
        raise ValueError("submitted seed length mismatch")
    ull = ctypes.c_ulonglong
    ptr = ctypes.c_void_p
    lengths = {}
    for name in (("pk", "sk", "sn") if target.startswith("sign-") else
                 ("pk", "sk", "ss", "ct")):
        fn = getattr(lib, ("sig_" if target.startswith("sign-") else "kem_") +
                     "get_" + name + "_len_bytes")
        fn.argtypes = ()
        fn.restype = ull
        lengths[name] = fn()
        if not 0 < lengths[name] < 100000000:
            raise ValueError("unreasonable getter: " + name)
    expected_lengths = {name: int(row[("Sn" if name == "sn" else name.upper()) + "_Len"])
                        for name in lengths}
    getter_matches = {name: (lengths[name] == expected_lengths[name] if name != "sn"
                             else lengths[name] >= expected_lengths[name]) for name in lengths}
    result = {"target": target, "parameter_set": instance,
              "source_run": prior["run"], "library_sha256": sha(library),
              "kat_sha256": cfg["kat_sha256"], "getter_lengths": lengths,
              "submitted_lengths": expected_lengths,
              "getter_matches_or_bounds": getter_matches}

    keygen = getattr(lib, "sig_keygen" if target.startswith("sign-") else "kem_keygen")
    keygen.argtypes = (ptr, ctypes.POINTER(ull), ptr, ctypes.POINTER(ull))
    keygen.restype = ctypes.c_int
    if target.startswith("sign-"):
        sign = lib.sig_sign
        sign.argtypes = (ptr, ull, ptr, ull, ptr, ctypes.POINTER(ull))
        sign.restype = ctypes.c_int
        verify = lib.sig_verify
        verify.argtypes = (ptr, ull, ptr, ull, ptr, ull)
        verify.restype = ctypes.c_int

        def sign_verify(pk, pklen, sk, sklen, message):
            sn = sized(lengths["sn"])
            snlen = ull(lengths["sn"])
            sc = sign(sk, sklen, buffer(message), len(message), sn, ctypes.byref(snlen))
            vc = (verify(pk, pklen, sn, snlen.value, buffer(message), len(message))
                  if sc == 0 and snlen.value <= lengths["sn"] else None)
            return {"sign_code": sc, "signature_length": snlen.value,
                    "verify_code": vc, "guard_ok": guard_ok(sn, lengths["sn"]),
                    "roundtrip": sc == 0 and vc == 0 and
                    0 < snlen.value <= lengths["sn"] and guard_ok(sn, lengths["sn"])}

        if reseed(lib, seed) != 0:
            raise ValueError("submitted DRNG initialization failed")
        kat_pk = bytes.fromhex(row["PK"])
        kat_sk = bytes.fromhex(row["SK"])
        message = bytes.fromhex(row["M"])
        result["sign_on_submitted_key"] = sign_verify(buffer(kat_pk), len(kat_pk),
                                                        buffer(kat_sk), len(kat_sk), message)
        if reseed(lib, seed) != 0:
            raise ValueError("submitted DRNG initialization failed")
        pk, sk = sized(lengths["pk"]), sized(lengths["sk"])
        pklen, sklen = ull(lengths["pk"]), ull(lengths["sk"])
        kc = keygen(pk, ctypes.byref(pklen), sk, ctypes.byref(sklen))
        key_result = {"keygen_code": kc, "pk_length": pklen.value,
                      "sk_length": sklen.value, "pk_guard_ok": guard_ok(pk, lengths["pk"]),
                      "sk_guard_ok": guard_ok(sk, lengths["sk"])}
        if kc == 0 and pklen.value == lengths["pk"] and sklen.value == lengths["sk"]:
            key_result["roundtrip"] = sign_verify(pk, pklen.value, sk, sklen.value, message)
        result["fresh_keygen"] = key_result
    else:
        enc = lib.kem_enc
        enc.argtypes = (ptr, ull, ptr, ctypes.POINTER(ull), ptr, ctypes.POINTER(ull))
        enc.restype = ctypes.c_int
        dec = lib.kem_dec
        dec.argtypes = (ptr, ull, ptr, ull, ptr, ctypes.POINTER(ull))
        dec.restype = ctypes.c_int

        def enc_dec(pk, pklen, sk, sklen):
            ss, ct, ss2 = sized(lengths["ss"]), sized(lengths["ct"]), sized(lengths["ss"])
            sslen, ctlen, ss2len = ull(lengths["ss"]), ull(lengths["ct"]), ull(lengths["ss"])
            ec = enc(pk, pklen, ss, ctypes.byref(sslen), ct, ctypes.byref(ctlen))
            dc = (dec(sk, sklen, ct, ctlen.value, ss2, ctypes.byref(ss2len))
                  if ec == 0 and sslen.value <= lengths["ss"] and
                  ctlen.value <= lengths["ct"] else None)
            return {"enc_code": ec, "dec_code": dc,
                    "ss_length": sslen.value, "ct_length": ctlen.value,
                    "dec_ss_length": ss2len.value, "guard_ok":
                    all((guard_ok(ss, lengths["ss"]), guard_ok(ct, lengths["ct"]),
                         guard_ok(ss2, lengths["ss"]))),
                    "roundtrip": ec == 0 and dc == 0 and
                    sslen.value == ss2len.value == lengths["ss"] and
                    ctlen.value == lengths["ct"] and
                    bytes(ss[:sslen.value]) == bytes(ss2[:ss2len.value])}

        if reseed(lib, seed) != 0:
            raise ValueError("submitted DRNG initialization failed")
        kat_pk, kat_sk = bytes.fromhex(row["PK"]), bytes.fromhex(row["SK"])
        result["enc_on_submitted_key"] = enc_dec(buffer(kat_pk), len(kat_pk),
                                                  buffer(kat_sk), len(kat_sk))
        if reseed(lib, seed) != 0:
            raise ValueError("submitted DRNG initialization failed")
        pk, sk = sized(lengths["pk"]), sized(lengths["sk"])
        pklen, sklen = ull(lengths["pk"]), ull(lengths["sk"])
        kc = keygen(pk, ctypes.byref(pklen), sk, ctypes.byref(sklen))
        key_result = {"keygen_code": kc, "pk_length": pklen.value,
                      "sk_length": sklen.value, "pk_guard_ok": guard_ok(pk, lengths["pk"]),
                      "sk_guard_ok": guard_ok(sk, lengths["sk"])}
        if kc == 0 and pklen.value == lengths["pk"] and sklen.value == lengths["sk"]:
            key_result["roundtrip"] = enc_dec(pk, pklen.value, sk, sklen.value)
        result["fresh_keygen"] = key_result
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append")
    parser.add_argument("--child")
    args = parser.parse_args()
    if args.child:
        print(json.dumps(child(args.child)))
        return
    batch = json.loads(BATCH.read_text())
    targets = sorted(row["target"] for row in batch["completed"]
                     if row["target"].startswith(("kem-", "sign-")))
    if args.target:
        unknown = set(args.target) - set(targets)
        if unknown:
            parser.error("unknown selected target(s): " + ", ".join(sorted(unknown)))
        targets = [t for t in targets if t in set(args.target)]
    OUT.mkdir(parents=True, exist_ok=True)

    def one(target):
        try:
            proc = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                   "--child", target], cwd=ROOT, capture_output=True,
                                  text=True, timeout=180)
            if proc.returncode:
                return {"target": target, "status": "probe_failed", "returncode": proc.returncode,
                        "stderr_tail": proc.stderr[-1200:]}
            return {**json.loads(proc.stdout.splitlines()[-1]), "status": "observed"}
        except (OSError, subprocess.TimeoutExpired, IndexError, ValueError) as exc:
            return {"target": target, "status": "probe_error", "error": str(exc)[-1200:]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        reports = list(pool.map(one, targets))
    out = OUT / "report.json"
    out.write_text(json.dumps(reports, indent=2, ensure_ascii=False) + "\n")
    for row in reports:
        print(json.dumps({"target": row["target"], "status": row["status"],
                          "getter_ok": all(row.get("getter_matches_or_bounds", {}).values()),
                          "existing_key_roundtrip": (row.get("enc_on_submitted_key") or
                                                     row.get("sign_on_submitted_key") or {}).get("roundtrip"),
                          "fresh_key_roundtrip": row.get("fresh_keygen", {}).get("roundtrip", {}).get("roundtrip")
                          if row["target"].startswith("sign-") else
                          row.get("fresh_keygen", {}).get("roundtrip", {}).get("roundtrip")},
                         ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()

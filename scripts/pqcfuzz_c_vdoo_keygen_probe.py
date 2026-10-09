#!/usr/bin/env python3
"""Directly probe VDOO keygen/sign/verify with run-local public test seeds."""
import ctypes
import hashlib
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "workspace/c_targets_sop/vdoo_keygen_probe.json"


def public_record(path, offsets):
    with path.open("rb") as stream:
        stream.seek(offsets[0])
        block = stream.read(offsets[1] - offsets[0])
    return {key.decode("ascii"): value.decode("ascii")
            for key, value in (line.split(b" = ", 1) for line in block.splitlines()
                               if b" = " in line)}


def probe(instance, run):
    package = run / "package"
    cfg = json.loads((package / "data/instances.json").read_text())[instance]
    offsets = json.loads((run / "build" / f"{instance}-offsets.json").read_text())
    row = public_record(run / "source" / cfg["kat"], offsets)
    lib = ctypes.CDLL(str(run / "build" / f"{instance}.so"))
    sizes = {}
    for name in ("pk", "sk", "sn"):
        getter = getattr(lib, f"sig_get_{name}_len_bytes")
        getter.restype = ctypes.c_ulonglong
        sizes[name] = getter()
    seed = bytes.fromhex(row["Seed"])
    message = bytes.fromhex(row["M"])
    if len(seed) != int(row["Seed_Len"]) or len(message) != int(row["M_Len"]) or \
            any(sizes[name] != int(row[{"pk": "PK_Len", "sk": "SK_Len", "sn": "Sn_Len"}[name]])
                for name in sizes):
        raise RuntimeError("public record/API length mismatch")
    seed_buffer = ctypes.create_string_buffer(seed)
    lib.init_randombytes.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong)
    lib.init_randombytes(seed_buffer, len(seed))
    buffers = {name: (ctypes.c_ubyte * (size + 16))(*([0xa5] * (size + 16)))
               for name, size in sizes.items()}
    reported = {name: ctypes.c_ulonglong(size) for name, size in sizes.items()}
    lib.sig_keygen.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong),
                               ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong))
    lib.sig_keygen.restype = ctypes.c_int
    start = time.monotonic()
    key_code = lib.sig_keygen(buffers["pk"], ctypes.byref(reported["pk"]),
                              buffers["sk"], ctypes.byref(reported["sk"]))
    key_seconds = time.monotonic() - start
    message_buffer = ctypes.create_string_buffer(message)
    lib.sig_sign.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                             ctypes.c_ulonglong, ctypes.c_void_p,
                             ctypes.POINTER(ctypes.c_ulonglong))
    lib.sig_sign.restype = ctypes.c_int
    sign_code = lib.sig_sign(buffers["sk"], sizes["sk"], message_buffer, len(message),
                             buffers["sn"], ctypes.byref(reported["sn"])) if key_code == 0 else None
    lib.sig_verify.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                               ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_ulonglong)
    lib.sig_verify.restype = ctypes.c_int
    verify_code = lib.sig_verify(buffers["pk"], sizes["pk"], buffers["sn"],
                                 sizes["sn"], message_buffer, len(message)) if sign_code == 0 else None
    row_out = {
        "parameter_set": instance, "run": str(run.relative_to(ROOT)),
        "kat": cfg["kat"], "kat_sha256": cfg["kat_sha256"],
        "seed_sha256": hashlib.sha256(seed).hexdigest(),
        "source_sha256": json.loads((run / "manifest.json").read_text())["source_sha256"],
        "api": ["sig_keygen", "sig_sign", "sig_verify"],
        "codes": [key_code, sign_code, verify_code],
        "lengths_ok": all(reported[name].value == sizes[name] for name in sizes),
        "guards_ok": all(all(x == 0xa5 for x in buffers[name][sizes[name]:])
                         for name in sizes),
        "keygen_seconds": round(key_seconds, 3),
        "kat_bytes_equal": {
            name: bytes(buffers[name][:sizes[name]]).hex() == row["Sn" if name == "sn" else name.upper()]
            for name in sizes},
        "scope": "direct public-seed API diagnostic, not a registered SOP oracle",
    }
    if row_out["codes"] != [0, 0, 0] or not row_out["lengths_ok"] or not row_out["guards_ok"]:
        raise RuntimeError(f"VDOO keygen direct probe failed: {instance}")
    return row_out


def main():
    status = json.loads((ROOT / "workspace/c_targets_sop/status.json").read_text())
    rows = []
    for item in status:
        if item["target"] == "sign-33":
            row = probe(item["parameter_set"], ROOT / item["campaign_run"])
            rows.append(row)
            OUTPUT.write_text(json.dumps(rows, indent=2) + "\n")
            print(json.dumps({key: row[key] for key in
                              ("parameter_set", "codes", "lengths_ok", "guards_ok",
                               "keygen_seconds", "kat_bytes_equal")}), flush=True)
    if len(rows) != 3:
        raise RuntimeError("expected all three VDOO instances")


if __name__ == "__main__":
    main()

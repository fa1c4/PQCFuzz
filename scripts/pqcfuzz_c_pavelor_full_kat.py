#!/usr/bin/env python3
"""Check one Pavelor run against all 4097 submitted KAT records."""
import argparse
import ctypes
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROW = re.compile(r"Msg_Len = (\d+)\nMsg = ([0-9A-F]*)\nDst_Len = (\d+)\nDst = ([0-9A-F]+)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    run = parser.parse_args().run.resolve()
    manifest = json.loads((run / "manifest.json").read_text())
    instance = manifest["parameter_set"]
    if manifest["target"] != "hash-22" or instance not in ("Pavelor-512", "Pavelor-768", "Pavelor-1024"):
        raise SystemExit("wrong run identity")
    bits = int(instance.split("-")[1])
    corpus = json.loads((ROOT / "oracles/hash-22/data" / f"kat_pavelor{bits}_subset.json").read_text())
    source = (ROOT / "third_party/hash-22/source").resolve()
    kat = (source / corpus["source_path"]).resolve()
    if not kat.is_relative_to(source) or hashlib.sha256(kat.read_bytes()).hexdigest() != corpus["source_sha256"]:
        raise SystemExit("KAT provenance mismatch")
    functions = {}
    for backend in ("reference", "optimized"):
        library = ctypes.CDLL(str(run / "build" / f"pavelor{bits}-{backend}.so"))
        fn = library.CryptHash
        fn.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p)
        fn.restype = ctypes.c_int
        functions[backend] = (library, fn)
    count = 0
    for match in ROW.finditer(kat.read_text(encoding="ascii")):
        length, message_hex, digest_bits, digest_hex = match.groups()
        length, digest_bits = int(length), int(digest_bits)
        message, digest = bytes.fromhex(message_hex), bytes.fromhex(digest_hex)
        if length != count or digest_bits != bits or len(message) != (length + 7) // 8 or len(digest) != bits // 8:
            raise SystemExit(f"malformed KAT row {count}")
        input_buffer = ctypes.create_string_buffer(message if message else b"\x00")
        for backend, (_, fn) in functions.items():
            output = (ctypes.c_ubyte * (bits // 8 + 16))(*([0xa5] * (bits // 8 + 16)))
            code = fn(bits, input_buffer, length, output)
            if code != 0 or bytes(output[:bits // 8]) != digest or any(value != 0xa5 for value in output[bits // 8:]):
                raise SystemExit(f"{instance} {backend} KAT mismatch at row {count}: rc={code}")
        count += 1
    if count != 4097:
        raise SystemExit(f"expected 4097 records, got {count}")
    report = {"instance": instance, "run": str(run.relative_to(ROOT)),
              "kat": corpus["source_path"], "kat_sha256": corpus["source_sha256"],
              "records": count, "api_calls": count * 2, "backends": list(functions),
              "status": "submitted_kat_match", "scope": "diagnostic; not an independent SOP oracle"}
    output = ROOT / "workspace/c_targets_sop/full_kat" / f"{instance}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

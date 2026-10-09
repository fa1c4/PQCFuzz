#!/usr/bin/env python3
"""Check every submitted KAT row for one registered B-tier 512-bit hash run."""
import argparse
import ctypes
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD = re.compile(r"Msg_Len = (\d+)\nMsg = ([0-9A-F]*)\nDst_Len = (\d+)\nDst = ([0-9A-F]+)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    args = parser.parse_args()
    run = args.run.resolve()
    manifest = json.loads((run / "manifest.json").read_text())
    target = manifest["target"]
    if target not in {"hash-05", "hash-10", "hash-11", "hash-14", "hash-18",
                      "hash-19", "hash-20", "hash-27", "hash-30", "hash-31", "hash-32"}:
        raise SystemExit("run is not a B-tier hash slice")
    corpus = json.loads((ROOT / "oracles" / target / "data/kat_512_subset.json").read_text())
    source = (ROOT / "third_party" / target / "source").resolve()
    kat = (source / corpus["source_path"]).resolve()
    if not kat.is_relative_to(source) or hashlib.sha256(kat.read_bytes()).hexdigest() != corpus["source_sha256"]:
        raise SystemExit("KAT provenance mismatch")
    build = json.loads((ROOT / "oracles" / target / "data/build_sources.json").read_text())
    functions = {}
    for backend in build.get("backends", ["reference", "optimized"]):
        path = run / "build" / f"hash512-{backend}.so"
        library = ctypes.CDLL(str(path))
        function = library.CryptHash
        function.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p)
        function.restype = ctypes.c_int
        functions[backend] = (library, function)
    count = 0
    for match in RECORD.finditer(kat.read_text(encoding="ascii").replace("\r\n", "\n")):
        bits_text, message_hex, length_text, digest_hex = match.groups()
        bits, length = int(bits_text), int(length_text)
        message, digest = bytes.fromhex(message_hex), bytes.fromhex(digest_hex)
        if bits != count or length != 512 or len(message) != (bits + 7) // 8 or len(digest) != 64:
            raise SystemExit(f"malformed KAT row {count}")
        if bits % 8 and message[-1] & ((1 << (8 - bits % 8)) - 1):
            raise SystemExit(f"non-canonical partial-byte KAT row {count}")
        input_buffer = ctypes.create_string_buffer(message if message else b"\x00")
        for backend, (_, function) in functions.items():
            output = (ctypes.c_ubyte * 80)(*([0xa5] * 80))
            result = function(512, input_buffer, bits, output)
            if result != 0 or bytes(output[:64]) != digest or any(x != 0xa5 for x in output[64:]):
                raise SystemExit(f"{target} {backend} KAT mismatch at row {count}: rc={result}")
        count += 1
    if count != 4097:
        raise SystemExit(f"expected 4097 KAT rows, got {count}")
    report = {"target": target, "run": str(run.relative_to(ROOT)),
              "kat": corpus["source_path"], "kat_sha256": corpus["source_sha256"],
              "records": count, "backends": list(functions),
              "matched_api_calls": count * len(functions),
              "status": "submitted_kat_match", "scope": "diagnostic; not an independent SOP oracle"}
    output = ROOT / "workspace/b_targets_sop/full_kat" / f"{target}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

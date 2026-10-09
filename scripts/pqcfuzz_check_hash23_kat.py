"""Check both run-local QILIN-512 backends against every submitted KAT row."""
import argparse
import ctypes
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KAT = ROOT / "third_party/hash-23/source/QILIN/Test_Vectors/KAT_2_12_QILIN-512.txt"
CORPUS = ROOT / "oracles/hash-23/data/kat_512_subset.json"
RECORD = re.compile(r"Msg_Len = (\d+)\nMsg = ([0-9A-F]*)\nDst_Len = (\d+)\nDst = ([0-9A-F]+)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    args = parser.parse_args()
    run = args.run.resolve()
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    if (manifest["target"], manifest["algorithm"], manifest["parameter_set"]) != (
            "hash-23", "QILIN", "QILIN-512"):
        raise SystemExit("run is not a QILIN-512 hash-23 run")
    expected_source_sha = json.loads(CORPUS.read_text(encoding="utf-8"))["source_sha256"]
    if hashlib.sha256(KAT.read_bytes()).hexdigest() != expected_source_sha:
        raise SystemExit("submitted KAT source digest mismatch")

    libraries = {}
    for backend in ("reference", "optimized"):
        library = ctypes.CDLL(str(run / "build" / f"qilin512-{backend}.so"))
        function = library.CryptHash
        function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong,
                             ctypes.c_void_p]
        function.restype = ctypes.c_int
        libraries[backend] = (library, function)

    count = 0
    for match in RECORD.finditer(KAT.read_text(encoding="ascii")):
        bits = int(match[1])
        message = bytes.fromhex(match[2])
        digest = bytes.fromhex(match[4])
        if bits != count or int(match[3]) != 512 or len(message) != (bits + 7) // 8 or len(digest) != 64:
            raise SystemExit(f"malformed or out-of-order submitted KAT row {count}")
        input_buffer = ctypes.create_string_buffer(message if message else b"\x00")
        for backend, (_, function) in libraries.items():
            output = (ctypes.c_ubyte * 64)()
            code = function(512, input_buffer, bits, output)
            if code != 0 or bytes(output) != digest:
                raise SystemExit(f"{backend} mismatched submitted KAT row {count}: rc={code}")
        count += 1
    if count != 4097:
        raise SystemExit(f"expected 4097 submitted KAT rows, found {count}")
    print(f"QILIN-512: {count} submitted KAT rows matched in both backends ({count * 2} calls)")


if __name__ == "__main__":
    main()

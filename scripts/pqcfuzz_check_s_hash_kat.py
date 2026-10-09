"""Check a registered 512-bit dual-backend hash run against its archived KAT."""
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
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    target = manifest["target"]
    if (manifest["primitive"] != "hash" or manifest["api"] != "CryptHash"
            or not manifest["parameter_set"].endswith("512")):
        raise SystemExit("run is not a registered 512-bit CryptHash campaign")
    corpus = json.loads((ROOT / "oracles" / target / "data/kat_512_subset.json").read_text())
    source_root = ROOT / "third_party" / target / "source"
    kat = (source_root / corpus["source_path"]).resolve()
    if not kat.is_relative_to(source_root.resolve()):
        raise SystemExit("KAT path escapes registered target source")
    if hashlib.sha256(kat.read_bytes()).hexdigest() != corpus["source_sha256"]:
        raise SystemExit("submitted KAT file digest mismatch")
    prefix = manifest["parameter_set"].lower().replace("-", "").replace("_", "")
    libraries = {}
    for backend in ("reference", "optimized"):
        library = ctypes.CDLL(str(run / "build" / f"{prefix}-{backend}.so"))
        function = library.CryptHash
        function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong,
                             ctypes.c_void_p]
        function.restype = ctypes.c_int
        libraries[backend] = (library, function)

    count = 0
    for row in RECORD.finditer(kat.read_text(encoding="ascii")):
        bits, message_hex, digest_bits, digest_hex = row.groups()
        bits = int(bits)
        message = bytes.fromhex(message_hex)
        digest = bytes.fromhex(digest_hex)
        if (bits != count or int(digest_bits) != 512 or
                len(message) != (bits + 7) // 8 or len(digest) != 64):
            raise SystemExit(f"malformed or out-of-order KAT row {count}")
        input_buffer = ctypes.create_string_buffer(message if message else b"\x00")
        for backend, (_, function) in libraries.items():
            output = (ctypes.c_ubyte * 64)()
            code = function(512, input_buffer, bits, output)
            if code != 0 or bytes(output) != digest:
                raise SystemExit(f"{target} {backend} mismatched KAT row {count}: rc={code}")
        count += 1
    if count != 4097:
        raise SystemExit(f"expected 4097 KAT rows, found {count}")
    print(f"{target}: {count} submitted KAT rows matched in both backends ({count * 2} calls)")


if __name__ == "__main__":
    main()

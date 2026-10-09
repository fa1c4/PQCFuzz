"""Check a Litchi-XOF run's core and wrapper against every 1024-bit KAT row."""
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
    if (manifest["target"], manifest["parameter_set"], manifest["api"]) != (
            "hash-15", "Litchi-XOF", "CryptHash"):
        raise SystemExit("run is not the Litchi-XOF CryptHash campaign")
    corpus = json.loads((ROOT / "oracles/hash-15/data/kat_1024_subset.json").read_text())
    source = ROOT / "third_party/hash-15/source"
    kat = (source / corpus["source_path"]).resolve()
    if not kat.is_relative_to(source.resolve()):
        raise SystemExit("KAT path escapes source tree")
    if hashlib.sha256(kat.read_bytes()).hexdigest() != corpus["source_sha256"]:
        raise SystemExit("KAT source digest mismatch")
    library = ctypes.CDLL(str(run / "build/litchi_xof.so"))
    core = library.litchi_xof
    core.argtypes = [ctypes.c_void_p, ctypes.c_ulonglong,
                     ctypes.c_void_p, ctypes.c_ulonglong]
    core.restype = None
    wrapper = library.CryptHash
    wrapper.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong,
                        ctypes.c_void_p]
    wrapper.restype = ctypes.c_int
    count = 0
    for row in RECORD.finditer(kat.read_text(encoding="ascii")):
        bits, message_hex, digest_bits, digest_hex = row.groups()
        bits = int(bits)
        message = bytes.fromhex(message_hex)
        digest = bytes.fromhex(digest_hex)
        if (bits != count or int(digest_bits) != 1024 or
                len(message) != (bits + 7) // 8 or len(digest) != 128):
            raise SystemExit(f"malformed or out-of-order KAT row {count}")
        input_buffer = ctypes.create_string_buffer(message if message else b"\x00")
        core_output = (ctypes.c_ubyte * 128)()
        wrapper_output = (ctypes.c_ubyte * 128)()
        core(core_output, 1024, input_buffer, bits)
        code = wrapper(1024, input_buffer, bits, wrapper_output)
        if code != 0 or bytes(core_output) != digest or bytes(wrapper_output) != digest:
            raise SystemExit(f"core/wrapper mismatched submitted KAT row {count}: rc={code}")
        count += 1
    if count != 4097:
        raise SystemExit(f"expected 4097 KAT rows, found {count}")
    print(f"hash-15: {count} submitted 1024-bit KAT rows matched by core and wrapper ({count * 2} calls)")


if __name__ == "__main__":
    main()

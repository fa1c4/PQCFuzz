"""Invoke the selected source-pinned public CryptHash reference implementation."""
import ctypes
import json
import re
import sys
from pathlib import Path

TARGET = "hash-07"
_FUNCTIONS = {}


def invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}


def invoke(structured_input, source_root, profile):
    if not isinstance(structured_input, dict) or not isinstance(profile, dict):
        return invalid("input/profile must be objects")
    source = Path(source_root).resolve()
    if source.name != "source" or source.parent.parent.parent.name != TARGET or sys.byteorder != "little":
        return invalid("wrong run-local source, target or byte order")
    config = json.loads((source.parent / "package/data/secondary_instances.json").read_text())
    instance = profile.get("parameter_set")
    if instance not in config:
        return invalid("unknown parameter set")
    digest_bits = config[instance]["digest_bits"]
    if (profile.get("digest_bits") != digest_bits or
            structured_input.get("digest_bits") != digest_bits or
            structured_input.get("backend") != "reference"):
        return invalid("profile/output/backend mismatch")
    bits, raw = structured_input.get("message_bits"), structured_input.get("message_hex")
    if not isinstance(bits, int) or isinstance(bits, bool) or not 0 <= bits <= 8192:
        return invalid("invalid bit length")
    if not isinstance(raw, str) or re.fullmatch(r"[0-9a-f]*", raw) is None or len(raw) != 2 * ((bits + 7) // 8):
        return invalid("invalid message storage")
    message = bytes.fromhex(raw)
    if bits % 8 and message[-1] & ((1 << (8 - bits % 8)) - 1):
        return invalid("noncanonical trailing bits")
    library = source.parent / "build/hash-secondary.so"
    if not library.is_file():
        return invalid("run-local library missing")
    if instance not in _FUNCTIONS:
        function = ctypes.CDLL(str(library)).CryptHash
        function.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p)
        function.restype = ctypes.c_int
        _FUNCTIONS[instance] = function
    inbuf = ctypes.create_string_buffer(message if message else b"\x00")
    outlen = digest_bits // 8
    output = (ctypes.c_ubyte * (outlen + 16))(*([0xa5] * (outlen + 16)))
    code = _FUNCTIONS[instance](digest_bits, inbuf, bits, output)
    return {"reached": True, "status": "ok" if code == 0 else "api_error",
            "output": bytes(output[:outlen]).hex() if code == 0 else None,
            "output_length": outlen if code == 0 else 0, "return_code": code,
            "guard_modified": any(x != 0xa5 for x in output[outlen:]),
            "backend": "reference", "parameter_set": instance, "api": "CryptHash"}

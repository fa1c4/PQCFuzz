"""Invoke exact run-local submitted 512-bit CryptHash path."""
import ctypes
import re
import sys
from pathlib import Path

TARGET = "hash-24"
INSTANCE = "QSH-512"
_FUNCTIONS = {}

def _invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}

def invoke(structured_input, source_root, profile):
    if not isinstance(structured_input, dict) or not isinstance(profile, dict):
        return _invalid("input/profile must be objects")
    if profile.get("parameter_set") != INSTANCE or profile.get("digest_bits") != 512 or sys.byteorder != "little":
        return _invalid("wrong parameter set, output length, or byte order")
    backend = structured_input.get("backend")
    bits = structured_input.get("message_bits")
    message_hex = structured_input.get("message_hex")
    if backend not in ("reference", "optimized") or structured_input.get("digest_bits") != 512:
        return _invalid("backend/output mismatch")
    if not isinstance(bits, int) or isinstance(bits, bool) or not 0 <= bits <= 8192:
        return _invalid("invalid bit length")
    if not isinstance(message_hex, str) or re.fullmatch(r"[0-9a-f]*", message_hex) is None:
        return _invalid("invalid hex message")
    if len(message_hex) != 2 * ((bits + 7) // 8):
        return _invalid("message storage length differs from bit length")
    message = bytes.fromhex(message_hex)
    if bits % 8 and message[-1] & ((1 << (8 - bits % 8)) - 1):
        return _invalid("nonzero unused trailing bits")
    source = Path(source_root).resolve()
    if source.name != "source" or source.parent.parent.parent.name != TARGET:
        return _invalid("wrong run-local source identity")
    library = source.parent / "build" / ("hash512-" + backend + ".so")
    if not library.is_file():
        return _invalid("run-local library missing")
    if backend not in _FUNCTIONS:
        function = ctypes.CDLL(str(library)).CryptHash
        function.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p)
        function.restype = ctypes.c_int
        _FUNCTIONS[backend] = function
    input_buffer = ctypes.create_string_buffer(message if message else b"\x00")
    output = (ctypes.c_ubyte * 80)(*([0xa5] * 80))
    result = _FUNCTIONS[backend](512, input_buffer, bits, output)
    return {"reached": True, "status": "ok" if result == 0 else "api_error",
            "output": bytes(output[:64]).hex() if result == 0 else None,
            "output_length": 64 if result == 0 else 0, "return_code": result,
            "guard_modified": any(x != 0xa5 for x in output[64:]),
            "backend": backend, "parameter_set": INSTANCE, "api": "CryptHash"}

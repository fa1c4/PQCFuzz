"""Invoke run-local Litchi-XOF core or CryptHash with output canaries."""
import ctypes
import re
import sys
from pathlib import Path


_LIBRARY = None
_OUT_BITS = {512, 768, 1024}
_CANARY = 0xA5
_ALLOCATED = 144


def _invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}


def invoke(structured_input, source_root, profile):
    if not isinstance(structured_input, dict) or not isinstance(profile, dict):
        return _invalid("input/profile must be objects")
    if profile.get("parameter_set") != "Litchi-XOF" or sys.byteorder != "little":
        return _invalid("wrong parameter set or host byte order")
    backend = structured_input.get("backend")
    message_hex = structured_input.get("message_hex")
    message_bits = structured_input.get("message_bits")
    out_bits = structured_input.get("out_bits")
    if backend not in {"core", "wrapper"} or out_bits not in _OUT_BITS:
        return _invalid("unsupported backend or requested output length")
    if not isinstance(message_bits, int) or isinstance(message_bits, bool) or not 0 <= message_bits <= 8192:
        return _invalid("message bit length outside campaign domain")
    if not isinstance(message_hex, str) or re.fullmatch(r"[0-9a-f]*", message_hex) is None:
        return _invalid("message must be lowercase hex")
    if len(message_hex) != 2 * ((message_bits + 7) // 8):
        return _invalid("message storage length does not match bit length")
    message = bytes.fromhex(message_hex)
    if message_bits % 8 and message[-1] & ((1 << (8 - message_bits % 8)) - 1):
        return _invalid("unused storage bits must be zero")

    source = Path(source_root).resolve()
    library_path = source.parent / "build/litchi_xof.so"
    if source.name != "source" or not library_path.is_file():
        return _invalid("run-local Litchi-XOF library is missing")
    global _LIBRARY
    if _LIBRARY is None:
        _LIBRARY = ctypes.CDLL(str(library_path))
        _LIBRARY.litchi_xof.argtypes = [ctypes.c_void_p, ctypes.c_ulonglong,
                                       ctypes.c_void_p, ctypes.c_ulonglong]
        _LIBRARY.litchi_xof.restype = None
        _LIBRARY.CryptHash.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                      ctypes.c_ulonglong, ctypes.c_void_p]
        _LIBRARY.CryptHash.restype = ctypes.c_int
    input_buffer = ctypes.create_string_buffer(message if message else b"\x00")
    output = (ctypes.c_ubyte * _ALLOCATED)(*([_CANARY] * _ALLOCATED))
    if backend == "core":
        _LIBRARY.litchi_xof(output, out_bits, input_buffer, message_bits)
        code = 0
    else:
        code = _LIBRARY.CryptHash(out_bits, input_buffer, message_bits, output)
    requested = out_bits // 8
    suffix = bytes(output[requested:])
    first_changed = next((requested + i for i, value in enumerate(suffix)
                          if value != _CANARY), None)
    return {"reached": True, "status": "ok" if code == 0 else "api_error",
            "output": bytes(output[:requested]).hex() if code == 0 else None,
            "output_length": requested if code == 0 else 0,
            "guard_modified": first_changed is not None,
            "guard_first_changed_offset": first_changed,
            "guard_after_maximum_modified": any(value != _CANARY for value in output[128:]),
            "allocated_bytes": _ALLOCATED, "return_code": code, "backend": backend,
            "parameter_set": "Litchi-XOF", "api": "litchi_xof" if backend == "core" else "CryptHash"}

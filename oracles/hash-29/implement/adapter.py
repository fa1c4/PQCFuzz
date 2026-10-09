"""Invoke the run-local submitted XRH-2-512 CryptHash implementations."""
import ctypes
import re
import sys
from pathlib import Path


_LIBRARIES = {}
_BACKENDS = {"reference", "optimized"}


def _invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}


def invoke(structured_input, source_root, profile):
    if not isinstance(structured_input, dict) or not isinstance(profile, dict):
        return _invalid("input/profile must be objects")
    if profile.get("parameter_set") != "XRH-2-512" or sys.byteorder != "little":
        return _invalid("wrong parameter set or host byte order")
    backend = structured_input.get("backend")
    message_hex = structured_input.get("message_hex")
    message_bits = structured_input.get("message_bits")
    digest_bits = structured_input.get("digest_bits")
    if backend not in _BACKENDS or digest_bits != 512:
        return _invalid("unsupported backend or digest length")
    if not isinstance(message_bits, int) or isinstance(message_bits, bool) or not 0 <= message_bits <= 8192:
        return _invalid("message bit length outside campaign domain")
    if not isinstance(message_hex, str) or re.fullmatch(r"[0-9a-f]*", message_hex) is None:
        return _invalid("message must be lowercase hex")
    if len(message_hex) != 2 * ((message_bits + 7) // 8):
        return _invalid("message storage length does not match bit length")
    message = bytes.fromhex(message_hex)
    if message_bits % 8 and message[-1] & ((1 << (8 - message_bits % 8)) - 1):
        return _invalid("unused trailing storage bits must be zero for this campaign")

    source = Path(source_root).resolve()
    library = source.parent / "build" / ("xrh2512-" + backend + ".so")
    if source.name != "source" or not library.is_file():
        return _invalid("run-local XRH-2-512 library is missing")
    if backend not in _LIBRARIES:
        function = ctypes.CDLL(str(library)).CryptHash
        function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p]
        function.restype = ctypes.c_int
        _LIBRARIES[backend] = function
    input_buffer = ctypes.create_string_buffer(message if message else b"\x00")
    output_buffer = (ctypes.c_ubyte * 64)()
    result = _LIBRARIES[backend](512, input_buffer, message_bits, output_buffer)
    observation = {"reached": True, "status": "ok" if result == 0 else "api_error",
                   "output": bytes(output_buffer).hex() if result == 0 else None,
                   "output_length": 64 if result == 0 else 0,
                   "return_code": result, "backend": backend,
                   "parameter_set": "XRH-2-512", "api": "CryptHash"}
    return observation

"""Invoke exact run-local Pavelor CryptHash instance and output canary."""
import ctypes
import re
import sys
from pathlib import Path

_LIBRARIES = {}

def invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}

def invoke(structured_input, source_root, profile):
    if not isinstance(structured_input, dict) or not isinstance(profile, dict):
        return invalid("input/profile must be objects")
    instance, bits = profile.get("parameter_set"), profile.get("digest_bits")
    if instance not in ("Pavelor-512", "Pavelor-768", "Pavelor-1024") or \
            bits != int(instance.split("-")[-1]) or structured_input.get("digest_bits") != bits:
        return invalid("wrong instance or digest length")
    backend, length, message_hex = (structured_input.get("backend"),
                                     structured_input.get("message_bits"),
                                     structured_input.get("message_hex"))
    if backend not in ("reference", "optimized") or not isinstance(length, int) or \
            isinstance(length, bool) or not 0 <= length <= 8192 or \
            not isinstance(message_hex, str) or re.fullmatch(r"[0-9a-f]*", message_hex) is None:
        return invalid("invalid backend or message")
    if len(message_hex) != 2 * ((length + 7) // 8):
        return invalid("message storage length differs from bit length")
    message = bytes.fromhex(message_hex)
    if length % 8 and message[-1] & ((1 << (8 - length % 8)) - 1):
        return invalid("non-canonical unused trailing bits")
    source = Path(source_root).resolve()
    if source.name != "source" or source.parent.parent.parent.name != "hash-22" or sys.byteorder != "little":
        return invalid("wrong run-local source or host byte order")
    library_path = source.parent / "build" / f"{instance.lower().replace('-', '')}-{backend}.so"
    if not library_path.is_file():
        return invalid("run-local library missing")
    key = str(library_path)
    if key not in _LIBRARIES:
        library = ctypes.CDLL(key)
        library.CryptHash.argtypes = (ctypes.c_int, ctypes.c_void_p,
                                      ctypes.c_ulonglong, ctypes.c_void_p)
        library.CryptHash.restype = ctypes.c_int
        _LIBRARIES[key] = library
    input_buffer = ctypes.create_string_buffer(message if message else b"\x00")
    digest_bytes = bits // 8
    output = (ctypes.c_ubyte * (digest_bytes + 16))(*([0xa5] * (digest_bytes + 16)))
    code = _LIBRARIES[key].CryptHash(bits, input_buffer, length, output)
    return {"reached": True, "status": "ok" if code == 0 else "api_error",
            "output": bytes(output[:digest_bytes]).hex() if code == 0 else None,
            "output_length": digest_bytes if code == 0 else 0,
            "return_code": code, "guard_modified": any(value != 0xa5 for value in output[digest_bytes:]),
            "backend": backend, "parameter_set": instance, "api": "CryptHash"}

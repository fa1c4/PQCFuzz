"""Run-local submitted fixed-output CryptHash or Litchi core path."""
import ctypes
import re
import sys
from pathlib import Path


_LIBRARIES = {}


def _invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}


def invoke(structured_input, source_root, profile):
    if not isinstance(structured_input, dict) or not isinstance(profile, dict):
        return _invalid("input/profile must be objects")
    instance = profile.get("parameter_set")
    bits = profile.get("digest_bits")
    if not isinstance(instance, str) or not re.fullmatch(r"[A-Za-z0-9-]+", instance):
        return _invalid("invalid selected instance")
    if not isinstance(bits, int) or bits not in (256, 512, 768, 1024) or not instance.endswith("-" + str(bits)):
        return _invalid("selected instance and output length differ")
    if structured_input.get("digest_bits") != bits or sys.byteorder != "little":
        return _invalid("cross-instance digest length or host byte order")
    backend = structured_input.get("backend")
    is_litchi = instance.startswith("Litchi-")
    allowed = ("core", "wrapper") if is_litchi else ("reference", "optimized")
    if backend not in allowed:
        return _invalid("unsupported submitted path")
    message_hex = structured_input.get("message_hex")
    message_bits = structured_input.get("message_bits")
    if not isinstance(message_bits, int) or isinstance(message_bits, bool) or not 0 <= message_bits <= 8192:
        return _invalid("message bit length outside campaign domain")
    if not isinstance(message_hex, str) or re.fullmatch(r"[0-9a-f]*", message_hex) is None:
        return _invalid("message must be lowercase hex")
    if len(message_hex) != 2 * ((message_bits + 7) // 8):
        return _invalid("message storage length differs from bit length")
    message = bytes.fromhex(message_hex)
    if message_bits % 8 and message[-1] & ((1 << (8 - message_bits % 8)) - 1):
        return _invalid("nonzero unused trailing bits")
    source = Path(source_root).resolve()
    target = source.parent.parent.parent.name
    family = {"hash-03": "C-Hash", "hash-15": "Litchi", "hash-16": "LLH",
              "hash-23": "QILIN", "hash-28": "XRH-1", "hash-29": "XRH-2", "hash-34": "WChain"}.get(target)
    if family is None or not instance.startswith(family + "-") or source.name != "source":
        return _invalid("instance and source identity differ")
    prefix = re.sub(r"[^a-z0-9]", "", instance.lower())
    library_path = source.parent / "build" / f"{prefix}-{'reference' if is_litchi else backend}.so"
    if not library_path.is_file():
        return _invalid("run-local submitted library missing")
    key = str(library_path)
    if key not in _LIBRARIES:
        library = ctypes.CDLL(key)
        library.CryptHash.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                      ctypes.c_ulonglong, ctypes.c_void_p]
        library.CryptHash.restype = ctypes.c_int
        if is_litchi:
            core = getattr(library, instance.lower().replace("-", "_"))
            core.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong]
            core.restype = None
        _LIBRARIES[key] = library
    library = _LIBRARIES[key]
    input_buffer = ctypes.create_string_buffer(message if message else b"\x00")
    length = bits // 8
    output_buffer = (ctypes.c_ubyte * (length + 16))(*([0xa5] * (length + 16)))
    if is_litchi and backend == "core":
        getattr(library, instance.lower().replace("-", "_"))(output_buffer, input_buffer, message_bits)
        code = 0
    else:
        code = library.CryptHash(bits, input_buffer, message_bits, output_buffer)
    return {"reached": True, "status": "ok" if code == 0 else "api_error",
            "output": bytes(output_buffer[:length]).hex() if code == 0 else None,
            "output_length": length if code == 0 else 0, "return_code": code,
            "guard_modified": any(value != 0xa5 for value in output_buffer[length:]),
            "backend": backend, "parameter_set": instance,
            "api": instance.lower().replace("-", "_") if is_litchi and backend == "core" else "CryptHash"}

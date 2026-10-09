"""Derive both submitted KEX roles on one indexed public transcript."""
import ctypes
import json
from pathlib import Path

TARGET = "kex-01"
LIBRARIES = {}

def invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}

def record(path, offsets, index):
    with path.open("rb") as stream:
        stream.seek(offsets[index])
        block = stream.read(offsets[index + 1] - offsets[index])
    row = {}
    for line in block.splitlines():
        if b" = " in line:
            key, value = line.split(b" = ", 1)
            row[key.decode("ascii")] = value.decode("ascii").strip()
    if int(row.get("Count", -1)) != index:
        raise ValueError("KAT record index mismatch")
    return row

def buffer(row, key):
    raw = bytes.fromhex(row[key])
    if len(raw) != int(row[key + "_Len"]):
        raise ValueError("KAT field length mismatch: " + key)
    return ctypes.create_string_buffer(raw if raw else b"\x00"), len(raw)

def invoke(structured_input, source_root, profile):
    if not isinstance(structured_input, dict) or not isinstance(profile, dict):
        return invalid("input/profile must be objects")
    source = Path(source_root).resolve()
    if source.name != "source" or source.parent.parent.parent.name != TARGET:
        return invalid("wrong run-local target")
    package = source.parent / "package"
    config = json.loads((package / "data/instances.json").read_text())
    instance = profile.get("parameter_set")
    if instance not in config or structured_input.get("instance") != instance or \
            structured_input.get("operation") != "derive_roles":
        return invalid("wrong instance or operation")
    index = structured_input.get("record_index")
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < 10:
        return invalid("invalid record index")
    offsets_path = source.parent / "build" / f"{instance}-offsets.json"
    lib_path = source.parent / "build" / f"{instance}.so"
    if not offsets_path.is_file() or not lib_path.is_file():
        return invalid("run-local build missing")
    cfg = config[instance]
    row = record(source / cfg["kat"], json.loads(offsets_path.read_text()), index)
    passes = cfg["passes"]
    if int(row["Pass_Num"]) != passes:
        return invalid("pass count mismatch")
    if instance not in LIBRARIES:
        LIBRARIES[instance] = ctypes.CDLL(str(lib_path))
    lib = LIBRARIES[instance]
    lib.kex_get_passes_num.restype = ctypes.c_ulonglong
    lib.kex_get_ss_len_bytes.restype = ctypes.c_ulonglong
    expected_length = int(row["SS_Len"])
    if lib.kex_get_passes_num() != passes or lib.kex_get_ss_len_bytes() != expected_length:
        return invalid("submitted API length/pass getter mismatch")
    args = (ctypes.c_void_p, ctypes.c_ulonglong) * 4 + \
           (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong))
    outputs = {}
    codes = {}
    guards = {}
    for role, fields in (("a", ("SKa", "PKb", "M2", "Pass1_Sta" if passes == 2 else "Pass3_Sta")),
                         ("b", ("SKb", "PKa", "M1" if passes == 2 else "M3", "Pass2_Stb"))):
        pairs = [buffer(row, field) for field in fields]
        fn = getattr(lib, "kex_derive_ss_" + role)
        fn.argtypes = args
        fn.restype = ctypes.c_int
        result = (ctypes.c_ubyte * (expected_length + 16))(*([0xa5] * (expected_length + 16)))
        length = ctypes.c_ulonglong(expected_length)
        code = fn(*(part for pair in pairs for part in pair), result, ctypes.byref(length))
        outputs[role] = bytes(result[:expected_length]).hex() if code == 0 and length.value == expected_length else None
        codes[role] = code
        guards[role] = any(value != 0xa5 for value in result[expected_length:])
    success = all(codes[role] == 0 and outputs[role] is not None for role in ("a", "b"))
    return {"reached": True, "status": "ok" if success else "api_error",
            "output": outputs["a"], "peer_output": outputs["b"],
            "output_length": expected_length if success else 0,
            "return_code_a": codes["a"], "return_code_b": codes["b"],
            "guard_modified": any(guards.values()), "parameter_set": instance,
            "api": "kex_derive_ss_a+b", "passes": passes}

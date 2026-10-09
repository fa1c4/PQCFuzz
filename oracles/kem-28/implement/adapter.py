"""Call actual submitted API on an indexed public KAT record."""
import ctypes
import json
from pathlib import Path

TARGET = "kem-28"
PRIMITIVE = "kem"
LIBRARIES = {}

def invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}

def record(path, offsets, index):
    with path.open("rb") as stream:
        stream.seek(offsets[index])
        block = stream.read(offsets[index + 1] - offsets[index])
    values = {}
    for line in block.splitlines():
        if b" = " in line:
            key, value = line.split(b" = ", 1)
            values[key.decode("ascii")] = value.decode("ascii")
    if int(values.get("Count", -1)) != index:
        raise ValueError("KAT record index mismatch")
    return values

def buffer(value):
    raw = bytes.fromhex(value)
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
            structured_input.get("operation") != ("verify" if PRIMITIVE == "signature" else "decapsulate"):
        return invalid("wrong instance or operation")
    index = structured_input.get("record_index")
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < 10:
        return invalid("invalid record index")
    path = source / config[instance]["kat"]
    offsets_path = source.parent / "build" / f"{instance}-offsets.json"
    lib_path = source.parent / "build" / f"{instance}.so"
    if not offsets_path.is_file() or not lib_path.is_file():
        return invalid("run-local build missing")
    offsets = json.loads(offsets_path.read_text())
    row = record(path, offsets, index)
    if instance not in LIBRARIES:
        LIBRARIES[instance] = ctypes.CDLL(str(lib_path))
    lib = LIBRARIES[instance]
    if PRIMITIVE == "signature":
        pk, pklen = buffer(row["PK"])
        sn, snlen = buffer(row["Sn"])
        message, mlen = buffer(row["M"])
        if pklen != int(row["PK_Len"]) or snlen != int(row["Sn_Len"]) or \
                mlen != int(row["M_Len"]):
            return invalid("KAT length mismatch")
        lib.sig_get_pk_len_bytes.restype = ctypes.c_ulonglong
        lib.sig_get_sn_len_bytes.restype = ctypes.c_ulonglong
        maximum_snlen = lib.sig_get_sn_len_bytes()
        variable_snlen = config[instance].get("variable_signature_length", False)
        if pklen != lib.sig_get_pk_len_bytes() or snlen > maximum_snlen or \
                (not variable_snlen and snlen != maximum_snlen):
            return invalid("submitted length getter mismatch")
        fn = lib.sig_verify
        fn.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                       ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_ulonglong)
        fn.restype = ctypes.c_int
        code = fn(pk, pklen, sn, snlen, message, mlen)
        return {"reached": True, "status": "ok" if code == 0 else "reject",
                "output": "accepted" if code == 0 else "rejected", "output_length": 1,
                "return_code": code, "parameter_set": instance, "api": "sig_verify"}
    sk, sklen = buffer(row["SK"])
    ct, ctlen = buffer(row["CT"])
    expected_len = int(row["SS_Len"])
    if sklen != int(row["SK_Len"]) or ctlen != int(row["CT_Len"]):
        return invalid("KAT length mismatch")
    for name, length in (("kem_get_sk_len_bytes", sklen), ("kem_get_ct_len_bytes", ctlen),
                         ("kem_get_ss_len_bytes", expected_len)):
        fn = getattr(lib, name)
        fn.restype = ctypes.c_ulonglong
        if fn() != length:
            return invalid("submitted length getter mismatch: " + name)
    fn = lib.kem_dec
    fn.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                   ctypes.c_ulonglong, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong))
    fn.restype = ctypes.c_int
    output = (ctypes.c_ubyte * (expected_len + 16))(*([0xa5] * (expected_len + 16)))
    result_len = ctypes.c_ulonglong(expected_len)
    code = fn(sk, sklen, ct, ctlen, output, ctypes.byref(result_len))
    return {"reached": True, "status": "ok" if code == 0 else "api_error",
            "output": bytes(output[:expected_len]).hex() if code == 0 else None,
            "output_length": result_len.value if code == 0 else 0,
            "guard_modified": any(x != 0xa5 for x in output[expected_len:]),
            "return_code": code, "parameter_set": instance, "api": "kem_dec"}

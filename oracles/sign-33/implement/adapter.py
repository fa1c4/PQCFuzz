"""Call actual submitted API on an indexed public KAT record."""
import ctypes
import hashlib
import json
from pathlib import Path

TARGET = "sign-33"
PRIMITIVE = "signature"
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
    operation = structured_input.get("operation")
    allowed = ("verify", "sign_roundtrip") if PRIMITIVE == "signature" else ("decapsulate",)
    if instance not in config or structured_input.get("instance") != instance or operation not in allowed:
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
    if operation == "sign_roundtrip":
        seed = bytes.fromhex(row["Seed"])
        pk, pklen = buffer(row["PK"])
        sk, sklen = buffer(row["SK"])
        message, mlen = buffer(row["M"])
        if len(seed) != int(row["Seed_Len"]) or not mlen or \
                pklen != int(row["PK_Len"]) or sklen != int(row["SK_Len"]) or \
                mlen != int(row["M_Len"]):
            return invalid("submitted sign key/message length mismatch")
        for name, size in (("pk", pklen), ("sk", sklen), ("sn", int(row["Sn_Len"]))):
            getter = getattr(lib, f"sig_get_{name}_len_bytes")
            getter.restype = ctypes.c_ulonglong
            if getter() != size:
                return invalid("submitted sign getter mismatch: " + name)
        entropy = ctypes.create_string_buffer(seed)
        lib.init_randombytes.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong)
        lib.init_randombytes(entropy, len(seed))
        snlen = int(row["Sn_Len"])
        signature = (ctypes.c_ubyte * (snlen + 16))(*([0xa5] * (snlen + 16)))
        returned_len = ctypes.c_ulonglong(snlen)
        lib.sig_sign.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                                 ctypes.c_ulonglong, ctypes.c_void_p,
                                 ctypes.POINTER(ctypes.c_ulonglong))
        lib.sig_sign.restype = ctypes.c_int
        sign_code = lib.sig_sign(sk, sklen, message, mlen, signature,
                                 ctypes.byref(returned_len))
        if sign_code != 0 or returned_len.value != snlen:
            return {"reached": True, "status": "api_error", "output": None,
                    "output_length": returned_len.value, "sign_code": sign_code,
                    "api": "sig_sign+sig_verify"}
        lib.sig_verify.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                                   ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_ulonglong)
        lib.sig_verify.restype = ctypes.c_int
        verify_code = lib.sig_verify(pk, pklen, signature, snlen, message, mlen)
        return {"reached": True, "status": "ok" if verify_code == 0 else "reject",
                "output": "accepted" if verify_code == 0 else "rejected",
                "output_length": returned_len.value,
                "guard_modified": any(x != 0xa5 for x in signature[snlen:]),
                "sign_code": sign_code, "verify_code": verify_code,
                "signature_sha256": hashlib.sha256(bytes(signature[:snlen])).hexdigest(),
                "seed_sha256": hashlib.sha256(seed).hexdigest(),
                "parameter_set": instance, "api": "sig_sign+sig_verify"}
    if PRIMITIVE == "signature":
        pk, pklen = buffer(row["PK"])
        sn, snlen = buffer(row["Sn"])
        message, mlen = buffer(row["M"])
        flip = structured_input.get("message_flip_bit", 0)
        if flip not in (0, 1) or isinstance(flip, bool):
            return invalid("unsupported message mutation")
        if flip:
            if mlen == 0:
                return invalid("cannot flip empty message")
            changed = bytearray(bytes.fromhex(row["M"]))
            changed[0] ^= 1
            message = ctypes.create_string_buffer(bytes(changed))
        if pklen != int(row["PK_Len"]) or snlen != int(row["Sn_Len"]) or \
                mlen != int(row["M_Len"]):
            return invalid("KAT length mismatch")
        lib.sig_get_pk_len_bytes.restype = ctypes.c_ulonglong
        lib.sig_get_sn_len_bytes.restype = ctypes.c_ulonglong
        if pklen != lib.sig_get_pk_len_bytes() or snlen != lib.sig_get_sn_len_bytes():
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

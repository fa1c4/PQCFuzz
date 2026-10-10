"""Run-local adapter for one submitted A-tier public API and parameter set."""
import ctypes
import hashlib
import json
from pathlib import Path


LIBRARIES = {}


def invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}


def load_row(path, offsets, index):
    with path.open("rb") as stream:
        stream.seek(offsets[index])
        block = stream.read(offsets[index + 1] - offsets[index])
    row = {}
    for line in block.splitlines():
        if b" = " in line:
            key, value = line.split(b" = ", 1)
            row[key.decode("ascii")] = value.decode("ascii")
    if int(row.get("Count", -1)) != index:
        raise ValueError("KAT index mismatch")
    return row


def buffer(raw):
    return ctypes.create_string_buffer(raw if raw else b"\x00")


def sized(capacity):
    return (ctypes.c_ubyte * (capacity + 16))(*([0xa5] * (capacity + 16)))


def guard_ok(value, capacity):
    return all(x == 0xa5 for x in value[capacity:])


def seed_rng(lib, row):
    seed = bytes.fromhex(row["Seed"])
    if len(seed) != int(row["Seed_Len"]):
        raise ValueError("KAT seed length mismatch")
    context = ctypes.c_char.in_dll(lib, "drng_algorithm")
    call = lib.init_random_number
    call.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong)
    call.restype = ctypes.c_int
    return call(ctypes.addressof(context), buffer(seed), len(seed)), hashlib.sha256(seed).hexdigest()


def invoke(structured_input, source_root, profile):
    if not isinstance(structured_input, dict) or not isinstance(profile, dict):
        return invalid("structured input/profile required")
    source = Path(source_root).resolve()
    target = source.parent.parent.parent.name
    primitive = "signature" if target.startswith("sign-") else "kem"
    if source.name != "source" or not target.startswith(("sign-", "kem-")):
        return invalid("wrong run-local source")
    package = source.parent / "package"
    configs = json.loads((package / "data/instances.json").read_text())
    instance, api = profile.get("parameter_set"), profile.get("api")
    index = structured_input.get("record_index")
    if (instance not in configs or structured_input.get("instance") != instance or
            structured_input.get("operation") != api or
            not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < 10):
        return invalid("wrong instance, API or record")
    if api not in (("sig_get_pk_len_bytes", "sig_get_sk_len_bytes", "sig_get_sn_len_bytes",
                    "sig_keygen", "sig_sign") if primitive == "signature" else
                   ("kem_get_pk_len_bytes", "kem_get_sk_len_bytes", "kem_get_ss_len_bytes",
                    "kem_get_ct_len_bytes", "kem_keygen", "kem_enc")):
        return invalid("unsupported API")
    cfg = configs[instance]
    kat = source / cfg["kat"]
    offsets_file = source.parent / "build" / f"{instance}-offsets.json"
    library = source.parent / "build" / f"{instance}.so"
    if not kat.is_file() or not offsets_file.is_file() or not library.is_file():
        return invalid("run-local KAT or build missing")
    row = load_row(kat, json.loads(offsets_file.read_text()), index)
    lib = LIBRARIES.setdefault(instance, ctypes.CDLL(str(library)))
    ull, ptr = ctypes.c_ulonglong, ctypes.c_void_p
    if "_get_" in api:
        fn = getattr(lib, api)
        fn.argtypes = ()
        fn.restype = ull
        value = fn()
        return {"reached": True, "status": "ok", "output": value,
                "output_length": 8, "api": api, "parameter_set": instance,
                "record_index": index, "called": [api]}

    seed_code, seed_sha = seed_rng(lib, row)
    if seed_code != 0:
        return invalid("submitted DRNG initialization failed")
    called = []
    keygen = getattr(lib, "sig_keygen" if primitive == "signature" else "kem_keygen")
    keygen.argtypes = (ptr, ctypes.POINTER(ull), ptr, ctypes.POINTER(ull))
    keygen.restype = ctypes.c_int

    def lengths(names):
        values = {}
        for name in names:
            fn = getattr(lib, ("sig_" if primitive == "signature" else "kem_") +
                         "get_" + name + "_len_bytes")
            fn.argtypes = ()
            fn.restype = ull
            values[name] = fn()
            if not 0 < values[name] < 100000000:
                raise ValueError("unreasonable getter")
        return values

    names = ("pk", "sk", "sn") if primitive == "signature" else ("pk", "sk", "ss", "ct")
    limits = lengths(names)
    if api.endswith("keygen"):
        pk, sk = sized(limits["pk"]), sized(limits["sk"])
        pklen, sklen = ull(limits["pk"]), ull(limits["sk"])
        key_code = keygen(pk, ctypes.byref(pklen), sk, ctypes.byref(sklen))
        called.append(api)
        if (key_code != 0 or pklen.value != limits["pk"] or
                sklen.value != limits["sk"] or not guard_ok(pk, limits["pk"]) or
                not guard_ok(sk, limits["sk"])):
            return {"reached": True, "status": "api_error", "output": False,
                    "output_length": 1, "api": api, "parameter_set": instance,
                    "record_index": index, "called": called, "keygen_code": key_code,
                    "pk_length": pklen.value, "sk_length": sklen.value}
    else:
        pkraw, skraw = bytes.fromhex(row["PK"]), bytes.fromhex(row["SK"])
        if (len(pkraw) != int(row["PK_Len"]) or len(skraw) != int(row["SK_Len"]) or
                len(pkraw) != limits["pk"] or len(skraw) != limits["sk"]):
            return invalid("submitted key lengths mismatch getters")
        pk, sk = buffer(pkraw), buffer(skraw)
        pklen, sklen = ull(len(pkraw)), ull(len(skraw))

    if primitive == "signature":
        message = bytes.fromhex(row["M"])
        if len(message) != int(row["M_Len"]):
            return invalid("submitted message length mismatch")
        sign = lib.sig_sign
        sign.argtypes = (ptr, ull, ptr, ull, ptr, ctypes.POINTER(ull))
        sign.restype = ctypes.c_int
        verify = lib.sig_verify
        verify.argtypes = (ptr, ull, ptr, ull, ptr, ull)
        verify.restype = ctypes.c_int
        signature = sized(limits["sn"])
        snlen = ull(limits["sn"])
        sign_code = sign(sk, sklen.value, buffer(message), len(message), signature,
                         ctypes.byref(snlen))
        called.append("sig_sign")
        verify_code = None
        if sign_code == 0 and 0 < snlen.value <= limits["sn"]:
            verify_code = verify(pk, pklen.value, signature, snlen.value,
                                 buffer(message), len(message))
            called.append("sig_verify")
        good = (sign_code == 0 and verify_code == 0 and
                0 < snlen.value <= limits["sn"] and guard_ok(signature, limits["sn"]))
        detail = {"sign_code": sign_code, "verify_code": verify_code,
                  "signature_length": snlen.value, "guard_ok": guard_ok(signature, limits["sn"])}
    else:
        enc = lib.kem_enc
        enc.argtypes = (ptr, ull, ptr, ctypes.POINTER(ull), ptr, ctypes.POINTER(ull))
        enc.restype = ctypes.c_int
        dec = lib.kem_dec
        dec.argtypes = (ptr, ull, ptr, ull, ptr, ctypes.POINTER(ull))
        dec.restype = ctypes.c_int
        ss, ct, ss2 = sized(limits["ss"]), sized(limits["ct"]), sized(limits["ss"])
        sslen, ctlen, ss2len = ull(limits["ss"]), ull(limits["ct"]), ull(limits["ss"])
        enc_code = enc(pk, pklen.value, ss, ctypes.byref(sslen), ct, ctypes.byref(ctlen))
        called.append("kem_enc")
        dec_code = None
        if (enc_code == 0 and sslen.value <= limits["ss"] and
                ctlen.value <= limits["ct"]):
            dec_code = dec(sk, sklen.value, ct, ctlen.value, ss2, ctypes.byref(ss2len))
            called.append("kem_dec")
        good = (enc_code == 0 and dec_code == 0 and
                sslen.value == ss2len.value == limits["ss"] and
                ctlen.value == limits["ct"] and
                bytes(ss[:sslen.value]) == bytes(ss2[:ss2len.value]) and
                all((guard_ok(ss, limits["ss"]), guard_ok(ct, limits["ct"]),
                     guard_ok(ss2, limits["ss"]))))
        detail = {"enc_code": enc_code, "dec_code": dec_code,
                  "ss_length": sslen.value, "ct_length": ctlen.value,
                  "dec_ss_length": ss2len.value,
                  "guard_ok": all((guard_ok(ss, limits["ss"]), guard_ok(ct, limits["ct"]),
                                   guard_ok(ss2, limits["ss"])))}
    return {"reached": api in called, "status": "ok" if good else "api_error",
            "output": good, "output_length": 1, "api": api,
            "parameter_set": instance, "record_index": index,
            "seed_sha256": seed_sha, "called": called, **detail}

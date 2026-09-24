"""Independent NTRU-HPS/HRSS model lane.

The model uses only Python integers:

* little-endian bit codecs for S3 and Rq0/Sq written from the specification
  packing order (not the target's pack3.c/packq.c),
* an O(n^2) cyclic convolution in Z[x]/(x^n-1) (not the target NTT),
* centered reduction, the DPKE decrypt and the membership predicates,
* HPS and HRSS Lift transliterations of the specification,
* SHA3-256 via hashlib for the implicit-rejection formulas.

It is used by tests/ntru_model_test.py to validate the pinned reference
decrypt/fail classification and to kill deliberately faulted model mutants.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = REPO_ROOT / "src" / "config" / "scheme_profiles" / "ntru.json"


class NtruModelError(ValueError):
    """Raised when a codec or decode precondition fails."""


@dataclass(frozen=True)
class NtruProfile:
    algorithm: str
    variant: str
    n: int
    q: int
    logq: int
    b3: int
    bq: int
    pk_len: int
    sk_len: int
    ct_len: int
    ss_len: int
    weight: int
    pack_trinary_bytes: int
    prf_key_bytes: int
    tail_unused_bits: int
    sample_fg_bytes: int
    sample_rm_bytes: int

    @property
    def sk_fp_off(self) -> int:
        return self.b3

    @property
    def sk_hq_off(self) -> int:
        return 2 * self.b3

    @property
    def sk_prf_off(self) -> int:
        return 2 * self.b3 + self.bq


def load_profiles() -> dict[str, NtruProfile]:
    payload = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profiles: dict[str, NtruProfile] = {}
    for entry in payload.get("parameter_sets", []):
        profile = NtruProfile(
            algorithm=entry["algorithm"],
            variant=entry["variant"],
            n=entry["n"],
            q=entry["q"],
            logq=entry["logq"],
            b3=entry["b3"],
            bq=entry["bq"],
            pk_len=entry["pk_len"],
            sk_len=entry["sk_len"],
            ct_len=entry["ct_len"],
            ss_len=entry["ss_len"],
            weight=entry["weight"],
            pack_trinary_bytes=entry["pack_trinary_bytes"],
            prf_key_bytes=entry["prf_key_bytes"],
            tail_unused_bits=entry["tail_unused_bits"],
            sample_fg_bytes=entry["sample_fg_bytes"],
            sample_rm_bytes=entry["sample_rm_bytes"],
        )
        profiles[profile.algorithm] = profile
    return profiles


# ------------------------------------------------------------------- codecs


def decode_s3(payload: bytes, profile: NtruProfile) -> list[int]:
    """S3: five base-3 digits per byte, coefficient 5i as least significant."""
    if len(payload) < profile.pack_trinary_bytes:
        raise NtruModelError("truncated S3 payload")
    coefficients = [0] * profile.n
    index = 0
    for group in range((profile.n - 1) // 5):
        value = payload[group]
        for j in range(5):
            coefficients[5 * group + j] = value % 3
            value //= 3
        index = 5 * (group + 1)
    if index < profile.n - 1:
        value = payload[(profile.n - 1) // 5]
        while index < profile.n - 1:
            coefficients[index] = value % 3
            value //= 3
            index += 1
    return coefficients


def encode_s3(coefficients: list[int], profile: NtruProfile) -> bytes:
    if len(coefficients) != profile.n:
        raise NtruModelError("wrong S3 coefficient count")
    out = bytearray(profile.pack_trinary_bytes)
    group = 0
    while group * 5 < profile.n - 1:
        value = 0
        place = 1
        for j in range(5):
            index = group * 5 + j
            if index >= profile.n - 1:
                break
            trit = coefficients[index]
            if trit not in (0, 1, 2):
                raise NtruModelError("S3 coefficient outside {0,1,2}")
            value += trit * place
            place *= 3
        out[group] = value & 0xFF
        group += 1
    return bytes(out)


def decode_rq0(payload: bytes, profile: NtruProfile, *, reconstruct_last: bool = True) -> list[int]:
    """Rq0: n-1 little-endian logq-bit coefficients.

    reconstruct_last=True restores coefficient n-1 so the sum is 0 mod q
    (poly_Rq_sum_zero_frombytes); False leaves it zero (poly_Sq_frombytes).
    """
    if len(payload) < profile.bq:
        raise NtruModelError("truncated Rq0 payload")
    coefficients = [0] * profile.n
    buffer = 0
    bits = 0
    byte_index = 0
    mask = (1 << profile.logq) - 1
    total = 0
    for i in range(profile.n - 1):
        while bits < profile.logq:
            buffer |= payload[byte_index] << bits
            byte_index += 1
            bits += 8
        value = buffer & mask
        buffer >>= profile.logq
        bits -= profile.logq
        coefficients[i] = value
        total += value
    if reconstruct_last:
        coefficients[profile.n - 1] = (profile.q - total) % profile.q
    return coefficients


def encode_rq0(coefficients: list[int], profile: NtruProfile) -> bytes:
    if len(coefficients) != profile.n:
        raise NtruModelError("wrong Rq0 coefficient count")
    out = bytearray(profile.bq)
    buffer = 0
    bits = 0
    byte_index = 0
    for i in range(profile.n - 1):
        value = coefficients[i]
        if value < 0 or value >= profile.q:
            raise NtruModelError("Rq0 coefficient outside [0,q)")
        buffer |= value << bits
        bits += profile.logq
        while bits >= 8:
            out[byte_index] = buffer & 0xFF
            byte_index += 1
            buffer >>= 8
            bits -= 8
    if bits > 0:
        out[byte_index] = buffer & 0xFF
    return bytes(out)


def decode_sk(sk: bytes, profile: NtruProfile) -> tuple[list[int], list[int], list[int], bytes]:
    if len(sk) != profile.sk_len:
        raise NtruModelError("secret key length is not the profile length")
    f = decode_s3(sk[: profile.b3], profile)
    fp = decode_s3(sk[profile.b3 : 2 * profile.b3], profile)
    hq = decode_rq0(sk[profile.sk_hq_off : profile.sk_hq_off + profile.bq], profile, reconstruct_last=False)
    prf = sk[profile.sk_prf_off : profile.sk_prf_off + profile.prf_key_bytes]
    return f, fp, hq, prf


def decode_pk(pk: bytes, profile: NtruProfile) -> list[int]:
    if len(pk) != profile.pk_len:
        raise NtruModelError("public key length is not the profile length")
    return decode_rq0(pk, profile)


def decode_ct(ct: bytes, profile: NtruProfile) -> list[int]:
    if len(ct) != profile.ct_len:
        raise NtruModelError("ciphertext length is not the profile length")
    return decode_rq0(ct, profile)


# -------------------------------------------------------------- ring arithmetic


def cyclic_mul(a: list[int], b: list[int], q: int | None = None) -> list[int]:
    """Product in Z[x]/(x^n-1)."""
    n = len(a)
    if len(b) != n:
        raise NtruModelError("cyclic product dimension mismatch")
    out = [0] * n
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            if bj == 0:
                continue
            out[(i + j) % n] += ai * bj
    if q is not None:
        out = [value % q for value in out]
    return out


def mod3_phi(coefficients: list[int]) -> list[int]:
    last = coefficients[-1]
    return [(value + 2 * last) % 3 for value in coefficients]


def modq_phi(coefficients: list[int], q: int) -> list[int]:
    last = coefficients[-1]
    return [(value - last) % q for value in coefficients]


def rq_to_s3(coefficients: list[int], profile: NtruProfile) -> list[int]:
    values = []
    for value in coefficients:
        value %= profile.q
        if value >= profile.q // 2:
            value += 1 if profile.logq % 2 == 1 else 2
        values.append(value)
    return mod3_phi(values)


def z3_to_zq(trits: list[int], q: int) -> list[int]:
    return [0 if t == 0 else (1 if t == 1 else q - 1) for t in trits]


def trinary_zq_to_z3(values: list[int], profile: NtruProfile) -> list[int]:
    out = []
    for value in values:
        value %= profile.q
        centered = value - profile.q if value >= profile.q // 2 else value
        out.append(centered % 3)
    return out


def lift_hps(trits: list[int], profile: NtruProfile) -> list[int]:
    return z3_to_zq(trits, profile.q)


def lift_hrss(trits: list[int], profile: NtruProfile) -> list[int]:
    n = profile.n
    q = profile.q
    t = 3 - (n % 3)
    b = [0] * n
    b[0] = trits[0] * (2 - t) + trits[1] * 0 + trits[2] * t
    b[1] = trits[1] * (2 - t) + trits[2] * 0
    b[2] = trits[2] * (2 - t)
    zj = 0
    for i in range(3, n):
        b[0] += trits[i] * (zj + 2 * t)
        b[1] += trits[i] * (zj + t)
        b[2] += trits[i] * zj
        zj = (zj + t) % 3
    b[1] += trits[0] * (zj + t)
    b[2] += trits[0] * zj
    b[2] += trits[1] * (zj + t)
    for i in range(3, n):
        b[i] = b[i - 3] + 2 * (trits[i] + trits[i - 1] + trits[i - 2])
    # Finish reduction mod Phi by subtracting Phi * b[n-1], then Z3 -> Zq.
    b = [((value & 0xFFFF) + 2 * (b[n - 1] & 0xFFFF)) % 3 for value in b]
    b = z3_to_zq(b, q)
    r = [0] * n
    r[0] = (-b[0]) % q
    for i in range(n - 1):
        r[i + 1] = (b[i] - b[i + 1]) % q
    return r


def lift(trits: list[int], profile: NtruProfile, *, use_hps_lift: bool = False) -> list[int]:
    if profile.variant == "HPS" or use_hps_lift:
        return lift_hps(trits, profile)
    return lift_hrss(trits, profile)


# ----------------------------------------------------------- decaps / membership


def check_ciphertext_padding(ct: bytes, profile: NtruProfile) -> bool:
    if profile.tail_unused_bits == 0:
        return False
    mask = ((1 << profile.tail_unused_bits) - 1) << (8 - profile.tail_unused_bits)
    return (ct[profile.ct_len - 1] & mask) != 0


def check_r(coefficients: list[int], profile: NtruProfile) -> bool:
    for c in coefficients:
        c &= 0xFFFF
        if (c + 1) & (profile.q - 4):
            return False
        if (c + 2) & 4:
            return False
    return (coefficients[-1] & 0xFFFF) == 0


def check_m(coefficients: list[int], profile: NtruProfile) -> bool:
    if profile.variant != "HPS":
        return False
    ones = sum(c & 1 for c in coefficients)
    twos = sum(2 for c in coefficients if c & 2)
    return ones == twos // 2 and twos == profile.weight


def dpke_decrypt(
    profile: NtruProfile,
    sk: bytes,
    ct: bytes,
    *,
    use_hps_lift: bool = False,
    skip_padding_check: bool = False,
    skip_r_check: bool = False,
    wrong_weight: bool = False,
) -> dict:
    f, fp, hq, prf = decode_sk(sk, profile)
    c = decode_ct(ct, profile)
    fq = z3_to_zq(f, profile.q)
    cf = cyclic_mul(c, fq, q=profile.q)
    mf = rq_to_s3(cf, profile)
    m = mod3_phi(cyclic_mul(mf, fp))
    m_coeffs = [value % 3 for value in m]

    fail_padding = False if skip_padding_check else check_ciphertext_padding(ct, profile)
    if profile.variant != "HPS":
        fail_m = False
    elif wrong_weight:
        ones = sum(value & 1 for value in m_coeffs)
        twos = sum(2 for value in m_coeffs if value & 2)
        fail_m = not (ones == twos // 2 and twos >= profile.weight - 2)
    else:
        fail_m = not check_m(m_coeffs, profile)

    liftm = lift(m_coeffs, profile, use_hps_lift=use_hps_lift)
    b = [(c[i] - liftm[i]) % profile.q for i in range(profile.n)]
    hq_values = [value % profile.q for value in hq]
    r_raw = cyclic_mul(b, hq_values, q=profile.q)
    r_raw = modq_phi(r_raw, profile.q)
    r_fail = False if skip_r_check else not check_r(r_raw, profile)
    r = trinary_zq_to_z3(r_raw, profile)

    packed_rm = encode_s3(r, profile) + encode_s3(m_coeffs, profile)
    fail = fail_padding or fail_m or r_fail
    return {
        "r": r,
        "m": m_coeffs,
        "packed_rm": packed_rm,
        "fail": fail,
        "fail_padding": fail_padding,
        "fail_m": fail_m,
        "fail_r": r_fail,
        "prf": prf,
    }


def fallback_secret(prf: bytes, ct: bytes, *, hash_name: str = "sha3_256", off_by_one: bool = False) -> bytes:
    material = prf
    if off_by_one:
        material = prf[1:] + bytes([0])
    if hash_name == "shake256":
        return hashlib.shake_256(material + ct).digest(32)
    return hashlib.sha3_256(material + ct).digest()


def model_decaps(
    profile: NtruProfile,
    sk: bytes,
    ct: bytes,
    *,
    swallow_fail: bool = False,
    zero_on_fail: bool = False,
    prf_off_by_one: bool = False,
    fallback_hash: str = "sha3_256",
) -> bytes:
    decoded = dpke_decrypt(profile, sk, ct)
    valid = hashlib.sha3_256(decoded["packed_rm"]).digest()
    if not decoded["fail"]:
        return valid
    if swallow_fail:
        return valid
    if zero_on_fail:
        return bytes(32)
    return fallback_secret(decoded["prf"], ct, hash_name=fallback_hash, off_by_one=prf_off_by_one)


def model_valid_secret(profile: NtruProfile, sk: bytes, ct: bytes) -> bytes:
    decoded = dpke_decrypt(profile, sk, ct)
    return hashlib.sha3_256(decoded["packed_rm"]).digest()


# ------------------------------------------------------------- mutant catalogue


def _mutant(name: str):
    def wrap(profile: NtruProfile, sk: bytes, ct: bytes) -> bytes:
        if name == "prf_off_by_one":
            return model_decaps(profile, sk, ct, prf_off_by_one=True)
        if name == "shake256_fallback":
            return model_decaps(profile, sk, ct, fallback_hash="shake256")
        if name == "zero_secret_on_fail":
            return model_decaps(profile, sk, ct, zero_on_fail=True)
        if name == "swallow_fail":
            return model_decaps(profile, sk, ct, swallow_fail=True)
        raise KeyError(name)

    return wrap


MUTANTS: dict[str, Callable] = {
    name: _mutant(name) for name in ("prf_off_by_one", "shake256_fallback", "zero_secret_on_fail", "swallow_fail")
}


def wrong_hps_weight_mutant(profile: NtruProfile, m: list[int]) -> bool:
    """HPS mutant that ignores the equal +1/-1 count requirement."""
    twos = sum(2 for value in m if value & 2)
    return twos == profile.weight


def hrss_hps_lift_mutant(profile: NtruProfile, sk: bytes, ct: bytes) -> bytes:
    decoded = dpke_decrypt(profile, sk, ct, use_hps_lift=True)
    return hashlib.sha3_256(decoded["packed_rm"]).digest()

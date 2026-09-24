"""Independent Falcon model lane.

This module is deliberately independent from the target implementation:

* SHAKE256 comes from Python's hashlib.
* HashToPoint uses rejection sampling (specification Algorithm 3), not the
  target's constant-time squeeze.
* The negacyclic product is an integer O(n^2) convolution, not the target NTT.
* The norm is computed with Python arbitrary-precision integers.

It is used by tests/falcon_model_test.py to validate the pinned reference
codec/HashToPoint/key-equation byte-for-byte and to kill deliberately faulted
model mutants (ignored norm, accepted negative zero, ignored padding bits,
little-endian HashToPoint, modulo-reduced public key coefficients,
sig_max_len-as-exact, always-true verify).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = REPO_ROOT / "src" / "config" / "scheme_profiles" / "falcon.json"

Q = 12289
FIVE_Q = 5 * Q
CENTERED_HALF = (Q - 1) // 2  # 6144


class FalconModelError(ValueError):
    """Raised when a codec or verification precondition fails."""


@dataclass(frozen=True)
class FalconProfile:
    algorithm: str
    format: str
    sig_type: str
    logn: int
    n: int
    q: int
    pk_len: int
    sk_len: int
    sig_max_len: int
    padded_len: int
    ct_len: int
    salt_len: int
    norm_bound: int
    compressed_coefficient_limit: int
    pk_header: int
    sig_header: int
    sk_header: int
    ct_header: int
    fg_bits: int

    @property
    def sig_payload_off(self) -> int:
        return 1 + self.salt_len


def load_profiles() -> dict[str, FalconProfile]:
    payload = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profiles: dict[str, FalconProfile] = {}
    for entry in payload.get("parameter_sets", []):
        profile = FalconProfile(
            algorithm=entry["algorithm"],
            format=entry["format"],
            sig_type=entry["sig_type"],
            logn=entry["logn"],
            n=entry["n"],
            q=Q,
            pk_len=entry["pk_len"],
            sk_len=entry["sk_len"],
            sig_max_len=entry["sig_max_len"],
            padded_len=entry["padded_len"],
            ct_len=entry["ct_len"],
            salt_len=entry["salt_len"],
            norm_bound=entry["norm_bound"],
            compressed_coefficient_limit=entry["compressed_coefficient_limit"],
            pk_header=entry["pk_header"],
            sig_header=entry["sig_header"],
            sk_header=entry["sk_header"],
            ct_header=entry["ct_header"],
            fg_bits=entry["fg_bits"],
        )
        profiles[profile.algorithm] = profile
    return profiles


# --------------------------------------------------------------- SHAKE / HashToPoint


def shake256_stream(seed: bytes, block: int = 1 << 16) -> Callable[[int], bytes]:
    hasher = hashlib.shake_256(seed)
    state = {"done": 0}

    def take(count: int) -> bytes:
        state["done"] += count
        return hasher.digest(state["done"])[state["done"] - count : state["done"]]

    return take


def hash_to_point_rejection(stream: Callable[[int], bytes], n: int) -> list[int]:
    """Falcon spec Algorithm 3: big-endian 16-bit t, keep t < 5*q, output t mod q."""
    coefficients: list[int] = []
    while len(coefficients) < n:
        chunk = stream(2 * n)
        if len(chunk) % 2 != 0:
            raise FalconModelError("SHAKE stream returned an odd byte count")
        for offset in range(0, len(chunk), 2):
            t = (chunk[offset] << 8) | chunk[offset + 1]
            if t < FIVE_Q:
                coefficients.append(t % Q)
                if len(coefficients) == n:
                    break
    return coefficients


def hash_to_point(salt: bytes, message: bytes, n: int) -> list[int]:
    return hash_to_point_rejection(shake256_stream(salt + message), n)


def hash_to_point_little_endian(salt: bytes, message: bytes, n: int) -> list[int]:
    """Faulty variant used by the mutant catalogue."""
    stream = shake256_stream(salt + message)
    coefficients: list[int] = []
    while len(coefficients) < n:
        chunk = stream(2 * n)
        for offset in range(0, len(chunk), 2):
            t = (chunk[offset + 1] << 8) | chunk[offset]
            if t < FIVE_Q:
                coefficients.append(t % Q)
                if len(coefficients) == n:
                    break
    return coefficients


# ------------------------------------------------------------------- bit codecs


def decode_compressed(
    payload: bytes,
    n: int,
    *,
    limit: int = 2047,
    allow_negative_zero: bool = False,
    check_trailing_bits: bool = True,
) -> tuple[list[int], int]:
    """Transliteration of the pinned reference comp_decode() semantics."""
    acc = 0
    acc_len = 0
    v = 0
    coefficients: list[int] = []
    for _ in range(n):
        if v >= len(payload):
            raise FalconModelError("truncated compressed payload")
        acc = ((acc << 8) | payload[v]) & 0xFFFFFFFF
        v += 1
        b = (acc >> acc_len) & 0xFFFFFFFF
        s = b & 128
        m = b & 127
        while True:
            if acc_len == 0:
                if v >= len(payload):
                    raise FalconModelError("unterminated compressed unary terminator")
                acc = ((acc << 8) | payload[v]) & 0xFFFFFFFF
                v += 1
                acc_len = 8
            acc_len -= 1
            if (acc >> acc_len) & 1:
                break
            m += 128
            if m > limit:
                raise FalconModelError("compressed coefficient above the pinned limit")
        if s and m == 0 and not allow_negative_zero:
            raise FalconModelError("negative zero is forbidden by the compressed codec")
        coefficients.append(-m if s else m)
    if check_trailing_bits and (acc & ((1 << acc_len) - 1)) != 0:
        raise FalconModelError("non-zero trailing bits in the last compressed payload byte")
    return coefficients, v


def compressed_metadata(payload: bytes, n: int) -> dict:
    """Bit offsets and trailing-bit count for the compressed payload.

    Mirrors the target decoder's accumulator bookkeeping so tests can craft
    negative-zero, terminator-clear and padding-bit fixtures without a fixed
    coefficient offset table.
    """
    acc = 0
    acc_len = 0
    v = 0
    sign_offsets: list[tuple[int, int]] = []
    term_offsets: list[tuple[int, int]] = []
    for _ in range(n):
        if v >= len(payload):
            raise FalconModelError("truncated compressed payload")
        acc = ((acc << 8) | payload[v]) & 0xFFFFFFFF
        v += 1
        sign_acc_pos = acc_len + 7
        sign_offsets.append((v - 1 - (sign_acc_pos >> 3), sign_acc_pos & 7))
        b = (acc >> acc_len) & 0xFFFFFFFF
        s = b & 128
        m = b & 127
        while True:
            if acc_len == 0:
                if v >= len(payload):
                    raise FalconModelError("unterminated compressed unary terminator")
                acc = ((acc << 8) | payload[v]) & 0xFFFFFFFF
                v += 1
                acc_len = 8
            acc_len -= 1
            term_acc_pos = acc_len
            if (acc >> acc_len) & 1:
                term_offsets.append((v - 1 - (term_acc_pos >> 3), term_acc_pos & 7))
                break
            m += 128
            if m > 2047:
                raise FalconModelError("compressed coefficient above the pinned limit")
        if s and m == 0:
            raise FalconModelError("negative zero is forbidden by the compressed codec")
    if acc & ((1 << acc_len) - 1):
        raise FalconModelError("non-zero trailing bits in the last compressed payload byte")
    return {
        "consumed": v,
        "trailing_bits": acc_len,
        "sign_offsets": sign_offsets,
        "term_offsets": term_offsets,
    }


def encode_compressed(coefficients: Iterable[int], limit: int = 2047) -> bytes:
    out = bytearray()
    acc = 0
    acc_len = 0
    for value in coefficients:
        if value < -limit or value > limit:
            raise FalconModelError("compressed coefficient outside the pinned encoding limit")
        t = value
        acc <<= 1
        if t < 0:
            t = -t
            acc |= 1
        w = t
        acc <<= 7
        acc |= w & 127
        w >>= 7
        acc_len += 8
        acc <<= w + 1
        acc |= 1
        acc_len += w + 1
        while acc_len >= 8:
            acc_len -= 8
            out.append((acc >> acc_len) & 0xFF)
            acc &= (1 << acc_len) - 1 if acc_len else 0
    if acc_len > 0:
        out.append((acc << (8 - acc_len)) & 0xFF)
    return bytes(out)


def decode_ct(payload: bytes, n: int) -> tuple[list[int], int]:
    bits = 12
    in_len = (n * bits + 7) // 8
    if in_len > len(payload):
        raise FalconModelError("truncated CT payload")
    mask1 = (1 << bits) - 1
    mask2 = 1 << (bits - 1)
    acc = 0
    acc_len = 0
    v = 0
    coefficients: list[int] = []
    while len(coefficients) < n:
        acc = (acc << 8) | payload[v]
        v += 1
        acc_len += 8
        while acc_len >= bits and len(coefficients) < n:
            acc_len -= bits
            w = (acc >> acc_len) & mask1
            if w & mask2:
                w -= 1 << bits
            if w == -mask2:
                raise FalconModelError("the minimum negative CT coefficient is forbidden")
            coefficients.append(w)
    if acc & ((1 << acc_len) - 1):
        raise FalconModelError("non-zero trailing bits in the last CT payload byte")
    return coefficients, v


def encode_ct(coefficients: Iterable[int]) -> bytes:
    bits = 12
    maxv = (1 << (bits - 1)) - 1
    out = bytearray()
    acc = 0
    acc_len = 0
    for value in coefficients:
        if value < -maxv or value > maxv:
            raise FalconModelError("CT coefficient outside the signed 12-bit range")
        acc = (acc << bits) | (value & ((1 << bits) - 1))
        acc_len += bits
        while acc_len >= 8:
            acc_len -= 8
            out.append((acc >> acc_len) & 0xFF)
    if acc_len > 0:
        out.append((acc << (8 - acc_len)) & 0xFF)
    return bytes(out)


def decode_pk(payload: bytes, n: int, *, reduce_mod_q: bool = False) -> list[int]:
    in_len = (n * 14 + 7) // 8
    if in_len > len(payload):
        raise FalconModelError("truncated public key payload")
    acc = 0
    acc_len = 0
    v = 0
    coefficients: list[int] = []
    while len(coefficients) < n:
        acc = (acc << 8) | payload[v]
        v += 1
        acc_len += 8
        if acc_len >= 14:
            acc_len -= 14
            w = (acc >> acc_len) & 0x3FFF
            if w >= Q:
                if not reduce_mod_q:
                    raise FalconModelError("public key coefficient is not smaller than q")
                w %= Q
            coefficients.append(w)
    if acc & ((1 << acc_len) - 1):
        raise FalconModelError("non-zero trailing bits in the last public key byte")
    return coefficients


def encode_pk(coefficients: Iterable[int]) -> bytes:
    out = bytearray()
    acc = 0
    acc_len = 0
    for value in coefficients:
        if value < 0 or value >= Q:
            raise FalconModelError("public key coefficient is not smaller than q")
        acc = (acc << 14) | value
        acc_len += 14
        while acc_len >= 8:
            acc_len -= 8
            out.append((acc >> acc_len) & 0xFF)
    if acc_len > 0:
        out.append((acc << (8 - acc_len)) & 0xFF)
    return bytes(out)


def decode_sk(secret_key: bytes, profile: FalconProfile) -> tuple[list[int], list[int], list[int]]:
    if not secret_key or secret_key[0] != profile.sk_header:
        raise FalconModelError("secret key header does not match the profile")
    payload = secret_key[1:]
    if len(payload) != profile.sk_len - 1:
        raise FalconModelError("secret key length is not the exact profile length")
    f, offset = _decode_trim_i8(payload, 0, profile.n, profile.fg_bits)
    g, offset = _decode_trim_i8(payload, offset, profile.n, profile.fg_bits)
    F, offset = _decode_trim_i8(payload, offset, profile.n, 8)
    if offset != len(payload):
        raise FalconModelError("secret key trailing bytes are not consumed")
    return f, g, F


def _decode_trim_i8(payload: bytes, offset: int, n: int, bits: int) -> tuple[list[int], int]:
    in_len = (n * bits + 7) // 8
    if offset + in_len > len(payload):
        raise FalconModelError("truncated trim_i8 payload")
    mask1 = (1 << bits) - 1
    mask2 = 1 << (bits - 1)
    acc = 0
    acc_len = 0
    v = offset
    values: list[int] = []
    while len(values) < n:
        acc = (acc << 8) | payload[v]
        v += 1
        acc_len += 8
        while acc_len >= bits and len(values) < n:
            acc_len -= bits
            w = (acc >> acc_len) & mask1
            if w & mask2:
                w -= 1 << bits
            if w == -mask2:
                raise FalconModelError("forbidden minimum negative trim_i8 value")
            values.append(w)
    if acc & ((1 << acc_len) - 1):
        raise FalconModelError("non-zero trailing bits in the last trim_i8 byte")
    return values, v


# -------------------------------------------------------------- ring arithmetic


def centered_mod_q(value: int, q: int = Q) -> int:
    value %= q
    if value > q // 2:
        value -= q
    return value


def negacyclic_mul(a: list[int], b: list[int], q: int | None = None) -> list[int]:
    n = len(a)
    if len(b) != n:
        raise FalconModelError("negacyclic product dimension mismatch")
    out = [0] * n
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            if bj == 0:
                continue
            k = i + j
            product = ai * bj
            if k < n:
                out[k] += product
            else:
                out[k - n] -= product
    if q is not None:
        out = [value % q for value in out]
    return out


def model_key_equation(f, g, F, G, q: int = Q) -> bool:
    if len(f) != len(g) or len(f) != len(F) or len(f) != len(G):
        return False
    left = negacyclic_mul(f, G)  # fG
    right = negacyclic_mul(g, F)  # gF
    difference = [a - b for a, b in zip(left, right)]
    # The NTRU equation fG - gF = q holds over the integers (mod x^n+1).
    if difference[0] != q:
        return False
    return all(value == 0 for value in difference[1:])


def norm_predicate(norm: int, bound: int) -> bool:
    """Acceptance uses <= B; Python integers cannot wrap."""
    return norm <= bound


def model_public_key_relation(f, g, h, q: int = Q) -> bool:
    product = negacyclic_mul(f, h, q=q)
    g_reduced = [value % q for value in g]
    return product == g_reduced


# ------------------------------------------------------------------ verification


@dataclass
class ModelVerifyResult:
    accepted: bool
    codec_ok: bool
    norm: int
    norm_bound: int
    s1: list[int]
    s2: list[int]
    reason: str = ""


def parse_signature(
    profile: FalconProfile,
    signature: bytes,
    *,
    allow_negative_zero: bool = False,
    check_trailing_bits: bool = True,
    padded_accepted: bool = True,
) -> tuple[bytes, list[int], bool]:
    if len(signature) < profile.sig_payload_off:
        raise FalconModelError("signature shorter than header plus salt")
    header = signature[0]
    expected = profile.ct_header if profile.format == "ct" else profile.sig_header
    if header != expected:
        raise FalconModelError("signature header does not match the profile")
    salt = signature[1 : 1 + profile.salt_len]
    payload = signature[profile.sig_payload_off :]
    if profile.format == "ct":
        if len(signature) != profile.ct_len:
            raise FalconModelError("CT signature length is not the exact profile length")
        coefficients, _ = decode_ct(payload, profile.n)
        return salt, coefficients, False
    if profile.format == "padded" and len(signature) != profile.padded_len:
        raise FalconModelError("padded signature length is not the exact profile length")
    coefficients, consumed = decode_compressed(
        payload,
        profile.n,
        limit=profile.compressed_coefficient_limit,
        allow_negative_zero=allow_negative_zero,
        check_trailing_bits=check_trailing_bits,
    )
    end = profile.sig_payload_off + consumed
    if end == len(signature):
        return salt, coefficients, False
    if not padded_accepted or len(signature) != profile.padded_len:
        raise FalconModelError("unconsumed trailing bytes are not a legal padded form")
    if any(byte != 0 for byte in signature[end:]):
        raise FalconModelError("non-zero byte inside the padded region")
    return salt, coefficients, True


def model_verify(
    profile: FalconProfile,
    public_key: bytes,
    message: bytes,
    signature: bytes,
    *,
    check_norm: bool = True,
    allow_negative_zero: bool = False,
    check_trailing_bits: bool = True,
    little_endian_hash: bool = False,
    reduce_pk_mod_q: bool = False,
    padded_accepted: bool = True,
    always_accept: bool = False,
) -> ModelVerifyResult:
    if always_accept:
        return ModelVerifyResult(True, True, 0, profile.norm_bound, [], [], "always_accept mutant")
    if len(public_key) != profile.pk_len:
        return ModelVerifyResult(False, False, 0, profile.norm_bound, [], [], "public key length mismatch")
    if public_key[0] != profile.pk_header:
        return ModelVerifyResult(False, False, 0, profile.norm_bound, [], [], "public key header mismatch")
    try:
        h = decode_pk(public_key[1:], profile.n, reduce_mod_q=reduce_pk_mod_q)
    except FalconModelError as exc:
        return ModelVerifyResult(False, False, 0, profile.norm_bound, [], [], str(exc))
    try:
        salt, s2, _ = parse_signature(
            profile,
            signature,
            allow_negative_zero=allow_negative_zero,
            check_trailing_bits=check_trailing_bits,
            padded_accepted=padded_accepted,
        )
    except FalconModelError as exc:
        return ModelVerifyResult(False, False, 0, profile.norm_bound, [], [], str(exc))

    if little_endian_hash:
        c = hash_to_point_little_endian(salt, message, profile.n)
    else:
        c = hash_to_point(salt, message, profile.n)
    s2_times_h = negacyclic_mul(s2, h, q=profile.q)
    s1 = [centered_mod_q(ci - sh, profile.q) for ci, sh in zip(c, s2_times_h)]
    norm = sum(value * value for value in s1) + sum(value * value for value in s2)
    accepted = True
    reason = ""
    if check_norm and norm > profile.norm_bound:
        accepted = False
        reason = "norm above the profile bound"
    return ModelVerifyResult(accepted, True, norm, profile.norm_bound, s1, s2, reason)


# ------------------------------------------------------------- mutant catalogue


def _mutant(name: str):
    def wrap(profile, public_key, message, signature):
        if name == "ignore_norm":
            return model_verify(profile, public_key, message, signature, check_norm=False).accepted
        if name == "accept_negative_zero":
            return model_verify(profile, public_key, message, signature, allow_negative_zero=True).accepted
        if name == "ignore_padding_bits":
            return model_verify(profile, public_key, message, signature, check_trailing_bits=False).accepted
        if name == "little_endian_hash_to_point":
            return model_verify(profile, public_key, message, signature, little_endian_hash=True).accepted
        if name == "pk_mod_q_reduce":
            return model_verify(profile, public_key, message, signature, reduce_pk_mod_q=True).accepted
        if name == "sig_max_len_exact":
            if len(signature) != profile.sig_max_len:
                return False
            return model_verify(profile, public_key, message, signature).accepted
        if name == "always_true":
            return True
        raise KeyError(name)

    return wrap


MUTANTS: dict[str, Callable] = {name: _mutant(name) for name in (
    "ignore_norm",
    "accept_negative_zero",
    "ignore_padding_bits",
    "little_endian_hash_to_point",
    "pk_mod_q_reduce",
    "sig_max_len_exact",
    "always_true",
)}


def mutant_is_caught(name: str, profile: FalconProfile, mutant_result: bool, model_result: bool) -> bool:
    """A mutant is caught when the model rejects but the faulty implementation accepts."""
    return (not model_result) and mutant_result

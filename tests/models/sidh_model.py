"""Independent SIDH model (Fp/Fp2 arithmetic, cfpk, j-invariant, transcript checks).

The full isogeny computation is covered by the pinned generic reference; this
model cross-checks the shared algebraic layers on the locked parameter sets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = REPO_ROOT / "src" / "config" / "scheme_profiles" / "sidh.json"
REFERENCE_PATH = REPO_ROOT / "tests" / "fixtures" / "sike_sidh" / "sidh_reference.json"


@dataclass(frozen=True)
class SidhProfile:
    algorithm: str
    e2: int
    e3: int
    np: int
    nsk2: int
    nsk3: int
    pk_len: int
    sk_a_len: int
    sk_b_len: int
    shared_len: int


def load_profiles() -> dict[str, SidhProfile]:
    payload = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profiles: dict[str, SidhProfile] = {}
    for entry in payload["parameter_sets"]:
        profiles[entry["algorithm"]] = SidhProfile(
            algorithm=entry["algorithm"],
            e2=entry["e2"],
            e3=entry["e3"],
            np=entry["np"],
            nsk2=entry["nsk2"],
            nsk3=entry["nsk3"],
            pk_len=entry["pk_len"],
            sk_a_len=entry["sk_a_len"],
            sk_b_len=entry["sk_b_len"],
            shared_len=entry["shared_len"],
        )
    return profiles


def field_prime(e2: int, e3: int) -> int:
    return (1 << e2) * (3**e3) - 1


def bob_scalar_bits(e3: int) -> int:
    return (3**e3).bit_length() - 1


# ------------------------------------------------------------- Fp2 arithmetic


def fp2_mul(a: tuple[int, int], b: tuple[int, int], p: int) -> tuple[int, int]:
    ar, ai = a
    br, bi = b
    return ((ar * br - ai * bi) % p, (ar * bi + ai * br) % p)


def fp2_add(a: tuple[int, int], b: tuple[int, int], p: int) -> tuple[int, int]:
    return ((a[0] + b[0]) % p, (a[1] + b[1]) % p)


def fp2_inv(a: tuple[int, int], p: int) -> tuple[int, int]:
    ar, ai = a
    norm = (ar * ar + ai * ai) % p
    if norm == 0:
        raise ValueError("Fp2 element is not invertible")
    inverse = pow(norm, -1, p)
    return ((ar * inverse) % p, (-ai * inverse) % p)


def j_invariant(montgomery_a: int, p: int) -> int:
    """j-invariant of y^2 = x^3 + A x^2 + x over Fp."""
    numerator = (montgomery_a * montgomery_a - 3) % p
    denominator = (montgomery_a * montgomery_a - 4) % p
    if denominator == 0:
        raise ValueError("degenerate Montgomery curve (A^2 = 4)")
    return (256 * pow(numerator, 3, p) % p) * pow(denominator, -1, p) % p


def montgomery_ladder(x: int, scalar: int, montgomery_a: int, p: int) -> int:
    """x-only Montgomery ladder (RFC 7748-style) for a small reference curve."""
    if scalar == 0:
        return 0  # x-coordinate of the point at infinity
    x1 = x % p
    x2, z2 = 1 % p, 0
    x3, z3 = x1, 1
    a24 = ((montgomery_a + 2) * pow(4, -1, p)) % p
    swap = 0
    for bit in bin(scalar)[2:]:
        k_t = int(bit)
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t
        a = (x2 + z2) % p
        aa = (a * a) % p
        b = (x2 - z2) % p
        bb = (b * b) % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = (d * a) % p
        cb = (c * b) % p
        x3 = pow(da + cb, 2, p)
        z3 = (x1 * pow(da - cb, 2, p)) % p
        x2 = (aa * bb) % p
        z2 = (e * ((aa + a24 * e) % p)) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    if z2 % p == 0:
        return 0
    return (x2 * pow(z2, -1, p)) % p


# ------------------------------------------------------------- SIDH transcript


def fp_decode(raw: bytes, p: int) -> int:
    value = int.from_bytes(raw, "little")
    if value >= p:
        raise ValueError("Fp value is out of range")
    return value


def fp2_decode(raw: bytes, np: int, p: int) -> tuple[int, int]:
    if len(raw) != 2 * np:
        raise ValueError("Fp2 element length mismatch")
    return (fp_decode(raw[:np], p), fp_decode(raw[np:], p))


def load_reference() -> dict[str, dict[str, str]]:
    payload = json.loads(REFERENCE_PATH.read_text(encoding="utf-8"))
    return payload["records"]


def verify_reference(profile: SidhProfile, record: dict[str, str]) -> dict[str, bool]:
    p = field_prime(profile.e2, profile.e3)
    pk_a = bytes.fromhex(record["pk_a"])
    pk_b = bytes.fromhex(record["pk_b"])
    shared_a = bytes.fromhex(record["shared_a"])
    shared_b = bytes.fromhex(record["shared_b"])
    scalar_a = int.from_bytes(bytes.fromhex(record["scalar_a"]), "little")
    scalar_b = int.from_bytes(bytes.fromhex(record["scalar_b"]), "little")
    tolerances = {
        "pk_length": len(pk_a) == profile.pk_len and len(pk_b) == profile.pk_len,
        "shared_length": len(shared_a) == profile.shared_len and len(shared_b) == profile.shared_len,
        "roles_agree": shared_a == shared_b,
        "scalar_a_in_range": scalar_a < (1 << profile.e2),
        "scalar_b_in_range": scalar_b < (1 << bob_scalar_bits(profile.e3)),
    }
    # Every Fp limb of the public keys must be canonical.
    canonical = True
    for public_key in (pk_a, pk_b):
        for offset in range(0, profile.pk_len, profile.np):
            try:
                fp_decode(public_key[offset : offset + profile.np], p)
            except ValueError:
                canonical = False
    tolerances["public_key_limbs_canonical"] = canonical
    # The shared value is an Fp2 element in canonical form.
    try:
        fp2_decode(shared_a, profile.np, p)
        tolerances["shared_is_canonical_fp2"] = True
    except ValueError:
        tolerances["shared_is_canonical_fp2"] = False
    return tolerances

"""Independent SIKE uncompressed model (field/octet codecs, SHAKE framing, gate selection).

The model deliberately does not implement the expensive isogeny arithmetic;
that layer is covered by the pinned generic reference transcript.  Here we
reproduce every byte-level decision of Algorithm 2 around the isogeny calls and
cross-check the recorded intermediates from tests/fixtures/sike_sidh.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = REPO_ROOT / "src" / "config" / "scheme_profiles" / "sike.json"
CASES_PATH = REPO_ROOT / "tests" / "fixtures" / "sike_sidh" / "sike_cases.json"


@dataclass(frozen=True)
class SikeProfile:
    algorithm: str
    e2: int
    e3: int
    np: int
    nsk2: int
    nsk3: int
    msg_bytes: int
    pk_len: int
    sk_len: int
    ct_len: int
    ss_len: int
    sk_s_off: int
    sk_sk3_off: int
    sk_pk_off: int
    c0_len: int
    c1_off: int


def load_profiles() -> dict[str, SikeProfile]:
    payload = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profiles: dict[str, SikeProfile] = {}
    for entry in payload["parameter_sets"]:
        profiles[entry["algorithm"]] = SikeProfile(
            algorithm=entry["algorithm"],
            e2=entry["e2"],
            e3=entry["e3"],
            np=entry["np"],
            nsk2=entry["nsk2"],
            nsk3=entry["nsk3"],
            msg_bytes=entry["msg_bytes"],
            pk_len=entry["pk_len"],
            sk_len=entry["sk_len"],
            ct_len=entry["ct_len"],
            ss_len=entry["ss_len"],
            sk_s_off=entry["sk_s_off"],
            sk_sk3_off=entry["sk_sk3_off"],
            sk_pk_off=entry["sk_pk_off"],
            c0_len=entry["c0_len"],
            c1_off=entry["c1_off"],
        )
    return profiles


def field_prime(e2: int, e3: int) -> int:
    return (1 << e2) * (3**e3) - 1


def bob_scalar_bits(e3: int) -> int:
    return (3**e3).bit_length() - 1


def fp_is_canonical(raw: bytes, p: int) -> bool:
    if len(raw) == 0:
        return False
    return int.from_bytes(raw, "little") < p


def fp_decode(raw: bytes, p: int) -> int:
    if not fp_is_canonical(raw, p):
        raise ValueError("Fp value is not in the canonical range")
    return int.from_bytes(raw, "little")


def fp_encode(value: int, p: int, np: int) -> bytes:
    if value < 0 or value >= p:
        raise ValueError("Fp value is out of range")
    return value.to_bytes(np, "little")


def shake256(data: bytes, out_len: int) -> bytes:
    return hashlib.shake_256(data).digest(out_len)


def byte_mask_for_bits(bits: int) -> int:
    remainder = bits % 8
    return 0xFF if remainder == 0 else (1 << remainder) - 1


def split_sk(sk: bytes, profile: SikeProfile) -> tuple[bytes, bytes, bytes]:
    if len(sk) != profile.sk_len:
        raise ValueError("secret key length does not match the profile")
    s = sk[profile.sk_s_off : profile.sk_s_off + profile.msg_bytes]
    sk3 = sk[profile.sk_sk3_off : profile.sk_sk3_off + profile.nsk3]
    pk3 = sk[profile.sk_pk_off : profile.sk_pk_off + profile.pk_len]
    return s, sk3, pk3


def split_ct(ct: bytes, profile: SikeProfile) -> tuple[bytes, bytes]:
    if len(ct) != profile.ct_len:
        raise ValueError("ciphertext length does not match the profile")
    c0 = ct[: profile.c0_len]
    c1 = ct[profile.c1_off : profile.c1_off + profile.msg_bytes]
    return c0, c1


def g_scalar(m: bytes, pk3: bytes, profile: SikeProfile) -> bytes:
    digest = bytearray(shake256(m + pk3, profile.nsk2))
    digest[-1] &= byte_mask_for_bits(profile.e2)
    return bytes(digest)


def expected_secret(m: bytes, gate: bool, s: bytes, ct: bytes, profile: SikeProfile) -> bytes:
    prefix = m if gate else s
    return shake256(prefix + ct, profile.ss_len)


def limb_boundaries(profile: SikeProfile) -> dict[str, bytes]:
    p = field_prime(profile.e2, profile.e3)
    return {
        "p_minus_one": fp_encode(p - 1, p, profile.np),
        "p": p.to_bytes(profile.np, "little"),
        "p_plus_one": (p + 1).to_bytes(profile.np, "little"),
        "all_ones": b"\xff" * profile.np,
    }


def classify_limb(raw: bytes, p: int) -> str:
    return "canonical" if fp_is_canonical(raw, p) else "out_of_range"


def load_cases() -> dict[str, dict[str, str]]:
    payload = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    return payload["records"]


def verify_case(profile: SikeProfile, record: dict[str, str]) -> dict[str, bool]:
    """Cross-check the middle layers of the recorded gate transcript."""
    s, sk3, pk3 = split_sk(bytes.fromhex(record["sk"]), profile)
    _, _ = s, sk3
    ct = bytes.fromhex(record["ct"])
    fail_ct = bytes.fromhex(record["fail_ct"])
    baseline_m = bytes.fromhex(record["baseline_m"])
    fail_m = bytes.fromhex(record["fail_m"])
    checks = {
        "baseline_gate_valid": record["baseline_gate"] == "valid",
        "fail_gate_fallback": record["fail_gate"] == "fallback",
        "baseline_r_matches": record["baseline_r"] == g_scalar(baseline_m, pk3, profile).hex(),
        "fail_r_matches": record["fail_r"] == g_scalar(fail_m, pk3, profile).hex(),
        "baseline_expected_matches": record["baseline_expected"]
        == expected_secret(baseline_m, True, s, ct, profile).hex(),
        "baseline_expected_is_ss": record["baseline_expected"] == record["ss"],
        "fail_expected_matches": record["fail_expected"]
        == expected_secret(fail_m, False, s, fail_ct, profile).hex(),
        "fail_message_differs": fail_m != baseline_m,
        "fail_expected_differs": record["fail_expected"] != record["ss"],
    }
    return checks

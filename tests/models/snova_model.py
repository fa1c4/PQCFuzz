"""Independent SNOVA round-2 wire/model lane.

This module is not a cryptographic implementation and never claims EUF-CMA,
sUF or quantum security.  It independently models the parts of SNOVA that the
PQCFuzz oracles need to separate target behavior from format/encoding
mutants: GF16 arithmetic, the nibble codecs, the AES-CTR and indexed-SHAKE
public expansions, the round-2 T/F/P/ABQ relations, the l^2+l term public map,
the target hash and a GF16 Gaussian solver.

Slow lanes (full 11-parameter coverage) are exercised by
tests/snova_model_test.py with tiny fixtures, while the small (24,5,4) profile
is differentially checked against the pinned reference adapter.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = REPO_ROOT / "src" / "config" / "scheme_profiles" / "snova.json"

# The pinned round-2 source calls gen_ABQ("SNOVA_ABQ") with an underscore; the
# round-2 PDF prose and the implementation plan write "SNOVA ABQ" with a space.
# The pinned source/KAT is authoritative for this model.
FIXED_ABQ_SEED = b"SNOVA_ABQ"
SHAKE_RATE = 168


class SnovaModelError(ValueError):
    """Raised when a wire object violates the locked SNOVA profile."""


# ---------------------------------------------------------------------------
# GF16 arithmetic: x^4 + x + 1, addition is XOR.
# ---------------------------------------------------------------------------
def gf16_mul(a: int, b: int) -> int:
    a &= 0xF
    b &= 0xF
    result = 0
    for _ in range(4):
        if b & 1:
            result ^= a
        carry = a & 0x8
        a = (a << 1) & 0xF
        if carry:
            a ^= 0x3
        b >>= 1
    return result


def integer_mod16_mul(a: int, b: int) -> int:
    """Deliberately wrong mutant: integer multiplication modulo 16."""
    return (a * b) % 16


GF16_MUL_TABLE: Tuple[Tuple[int, ...], ...] = tuple(
    tuple(gf16_mul(a, b) for b in range(16)) for a in range(16)
)


def gf16_inv(a: int) -> int:
    a &= 0xF
    if a == 0:
        raise SnovaModelError("zero has no multiplicative inverse in GF16")
    for candidate in range(1, 16):
        if gf16_mul(a, candidate) == 1:
            return candidate
    raise SnovaModelError("GF16 inverse table is inconsistent")


def gf16_add(a: int, b: int) -> int:
    return (a ^ b) & 0xF


# ---------------------------------------------------------------------------
# Wire codecs.
# ---------------------------------------------------------------------------
def pack_nibbles(values: Sequence[int]) -> bytes:
    out = bytearray()
    for index in range(0, len(values) - 1, 2):
        out.append((values[index] & 0xF) | ((values[index + 1] & 0xF) << 4))
    if len(values) % 2 == 1:
        out.append(values[-1] & 0xF)
    return bytes(out)


def unpack_nibbles(data: bytes, count: int) -> List[int]:
    if count < 0:
        raise SnovaModelError("nibble count must be non-negative")
    if (count + 1) // 2 > len(data):
        raise SnovaModelError("nibble stream is shorter than the requested count")
    out: List[int] = []
    for index in range(count):
        byte = data[index // 2]
        out.append(byte & 0xF if index % 2 == 0 else (byte >> 4) & 0xF)
    return out


def pack_nibbles_cut_in_half(values: Sequence[int]) -> bytes:
    """The ESK packing used by convert_GF16s_to_bytes_merger_in_half."""
    count = len(values)
    half = (count + 1) // 2
    out = bytearray((count + 1) // 2)
    for index in range(count // 2):
        out[index] = (values[index] & 0xF) | ((values[index + half] & 0xF) << 4)
    if count % 2 == 1:
        out[count // 2] = values[half - 1] & 0xF
    return bytes(out)


def unpack_nibbles_cut_in_half(data: bytes, count: int) -> List[int]:
    """Inverse of pack_nibbles_cut_in_half (convert_bytes_to_GF16s_cut_in_half)."""
    half = (count + 1) // 2
    if half > len(data):
        raise SnovaModelError("cut-in-half stream is shorter than the requested count")
    out = [0] * count
    for index in range(half):
        out[index] = data[index] & 0xF
    for index in range(count // 2):
        out[index + half] = (data[index] >> 4) & 0xF
    return out


def signature_padding_mask(profile: "SnovaProfile", target_hash: bytes) -> bytes:
    """Mask the unused high nibble of the last hash byte when the count is odd."""
    if len(target_hash) != profile.hash_bytes:
        raise SnovaModelError("target hash length does not match the profile")
    if profile.hash_nibbles % 2 == 1:
        return target_hash[:-1] + bytes([target_hash[-1] & 0x0F])
    return target_hash


# ---------------------------------------------------------------------------
# Profile.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SnovaProfile:
    algorithm: str
    v: int
    o: int
    l: int
    backend: str
    pk_expand_shake: bool
    fixed_abq: bool
    pk_len: int
    sig_len: int
    signature_data_bytes: int
    salt_bytes: int
    public_seed_bytes: int
    private_seed_bytes: int
    n_matrices: int
    m_matrices: int
    sq_rank: int
    alpha_terms: int
    hash_nibbles: int
    hash_bytes: int
    ssk_len: int
    esk_len: int
    category: int
    security_level: int

    @property
    def is_seed_format(self) -> bool:
        return self.ssk_len == 48


def load_profiles(path: Optional[Path] = None) -> Dict[str, SnovaProfile]:
    payload = json.loads(Path(path or PROFILE_PATH).read_text(encoding="utf-8"))
    if payload.get("family") != "SNOVA" or payload.get("primitive_type") != "sig":
        raise SnovaModelError("scheme profile is not the SNOVA signature family")
    profiles: Dict[str, SnovaProfile] = {}
    for entry in payload["parameter_sets"]:
        sk_variants = entry.get("sk_len_variants") or [entry["sk_len"]]
        profiles[entry["algorithm"]] = SnovaProfile(
            algorithm=entry["algorithm"],
            v=entry["snova_v"],
            o=entry["snova_o"],
            l=entry["snova_l"],
            backend=entry["backend"],
            pk_expand_shake=bool(entry["pk_expand_shake"]),
            fixed_abq=bool(entry["fixed_abq"]),
            pk_len=entry["pk_len"],
            sig_len=entry["sig_max_len"],
            signature_data_bytes=entry["signature_data_bytes"],
            salt_bytes=entry["salt_bytes"],
            public_seed_bytes=entry["public_seed_bytes"],
            private_seed_bytes=entry["private_seed_bytes"],
            n_matrices=entry["n_matrices"],
            m_matrices=entry["m_matrix"],
            sq_rank=entry["sq_rank"],
            alpha_terms=entry["alpha_terms"],
            hash_nibbles=entry["hash_nibbles"],
            hash_bytes=entry["hash_bytes"],
            ssk_len=entry["sk_len"],
            esk_len=max(sk_variants),
            category=entry["category"],
            security_level=entry["security_level"],
        )
    return profiles


# ---------------------------------------------------------------------------
# Matrix helpers (l x l flat lists).
# ---------------------------------------------------------------------------
def zeros_matrix(l: int) -> List[int]:
    return [0] * (l * l)


def identity_matrix(l: int) -> List[int]:
    out = zeros_matrix(l)
    for i in range(l):
        out[i * l + i] = 1
    return out


def mat_add(a: Sequence[int], b: Sequence[int]) -> List[int]:
    return [x ^ y for x, y in zip(a, b)]


def mat_scale(a: Sequence[int], scalar: int, l: int) -> List[int]:
    return [gf16_mul(value, scalar) for value in a]


def mat_mul(a: Sequence[int], b: Sequence[int], l: int) -> List[int]:
    out = [0] * (l * l)
    for i in range(l):
        for j in range(l):
            acc = 0
            for k in range(l):
                acc ^= gf16_mul(a[i * l + k], b[k * l + j])
            out[i * l + j] = acc
    return out


def mat_transpose(a: Sequence[int], l: int) -> List[int]:
    return [a[j * l + i] for i in range(l) for j in range(l)]


def mat_det(a: Sequence[int], l: int) -> int:
    # In characteristic 2 every permutation sign is +1, so the determinant is
    # the permanent: sum over all permutations without sign corrections.
    rows = [list(a[i * l : (i + 1) * l]) for i in range(l)]
    det = 0
    for perm in _permutations(list(range(l))):
        term = 1
        for i in range(l):
            term = gf16_mul(term, rows[i][perm[i]])
        det ^= term
    return det


def _permutations(items: List[int]) -> Iterable[List[int]]:
    if len(items) <= 1:
        yield list(items)
        return
    for index, value in enumerate(items):
        rest = items[:index] + items[index + 1 :]
        for tail in _permutations(rest):
            yield [value] + tail


def _permutation_sign(perm: Sequence[int]) -> int:
    inversions = 0
    for i in range(len(perm)):
        for j in range(i + 1, len(perm)):
            if perm[i] > perm[j]:
                inversions += 1
    return inversions % 2


def be_the_s_matrix(l: int) -> List[int]:
    out = [((8 - (i + j)) & 0xF) for i in range(l) for j in range(l)]
    if l == 5:
        out[4 * l + 4] = 9
    return out


def s_matrices(l: int) -> List[List[int]]:
    matrices = [identity_matrix(l), be_the_s_matrix(l)]
    for _ in range(2, l):
        matrices.append(mat_mul(matrices[-1], matrices[1], l))
    return matrices


def be_invertible_by_add_a_s(matrix: Sequence[int], s: Sequence[int], l: int) -> List[int]:
    # The reference adds a*S cumulatively (source = source + a*S each step), so
    # the model must accumulate too.
    out = list(matrix)
    if mat_det(out, l) == 0:
        for scalar in range(1, 16):
            out = mat_add(out, mat_scale(s, scalar, l))
            if mat_det(out, l) != 0:
                return out
    return out


def gen_a_fqs(coeffs: Sequence[int], l: int, s_mats: Sequence[Sequence[int]]) -> List[int]:
    """gen_a_FqS: c0*I + sum_{i=1}^{l-2} c_i*S_i + adj(c_{l-1})*S_{l-1}."""
    if len(coeffs) != l:
        raise SnovaModelError("gen_a_FqS expects exactly l coefficients")
    out = mat_scale(identity_matrix(l), coeffs[0], l)
    for index in range(1, l - 1):
        out = mat_add(out, mat_scale(s_mats[index], coeffs[index], l))
    last = coeffs[l - 1]
    if last == 0:
        adjusted = 15 if coeffs[0] == 0 else (16 - coeffs[0]) & 0xF
    else:
        adjusted = last
    out = mat_add(out, mat_scale(s_mats[l - 1], adjusted, l))
    return out


# ---------------------------------------------------------------------------
# AES-128 (encryption only) for the AES public expansion backend.
# ---------------------------------------------------------------------------
def _build_aes_tables() -> Tuple[List[int], List[int]]:
    sbox = [0] * 256
    inv_sbox = [0] * 256
    for value in range(256):
        inverse = _gf256_inverse(value)
        transformed = inverse
        for shift in (1, 2, 3, 4):
            transformed ^= _rotl8(inverse, shift)
        sbox[value] = transformed ^ 0x63
    for value, mapped in enumerate(sbox):
        inv_sbox[mapped] = value
    return sbox, inv_sbox


def _gf256_inverse(value: int) -> int:
    if value == 0:
        return 0
    for candidate in range(1, 256):
        if _gf256_mul(value, candidate) == 1:
            return candidate
    raise SnovaModelError("GF(2^8) inverse lookup failed")


def _gf256_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return result


def _rotl8(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


AES_SBOX, AES_INV_SBOX = _build_aes_tables()
AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def aes128_expand_key(key: bytes) -> List[List[int]]:
    if len(key) != 16:
        raise SnovaModelError("AES-128 expects a 16-byte key")
    words = [list(key[4 * i : 4 * i + 4]) for i in range(4)]
    for round_index in range(1, 11):
        previous = words[-1]
        temp = list(previous[1:] + previous[:1])
        temp = [AES_SBOX[byte] for byte in temp]
        temp[0] ^= AES_RCON[round_index - 1]
        base = words[-4]
        words.append([base[i] ^ temp[i] for i in range(4)])
        for _ in range(3):
            previous = words[-1]
            base = words[-4]
            words.append([base[i] ^ previous[i] for i in range(4)])
    return [sum(words[4 * r : 4 * r + 4], []) for r in range(11)]


def _aes_add_round_key(state: List[int], round_key: Sequence[int]) -> List[int]:
    return [state[i] ^ round_key[i] for i in range(16)]


def _aes_sub_bytes(state: List[int]) -> List[int]:
    return [AES_SBOX[byte] for byte in state]


def _aes_shift_rows(state: List[int]) -> List[int]:
    out = list(state)
    for row in range(4):
        values = [state[row + 4 * col] for col in range(4)]
        values = values[row:] + values[:row]
        for col in range(4):
            out[row + 4 * col] = values[col]
    return out


def _aes_mix_columns(state: List[int]) -> List[int]:
    out = [0] * 16
    for col in range(4):
        a = state[4 * col : 4 * col + 4]
        out[4 * col + 0] = _gf256_mul(a[0], 2) ^ _gf256_mul(a[1], 3) ^ a[2] ^ a[3]
        out[4 * col + 1] = a[0] ^ _gf256_mul(a[1], 2) ^ _gf256_mul(a[2], 3) ^ a[3]
        out[4 * col + 2] = a[0] ^ a[1] ^ _gf256_mul(a[2], 2) ^ _gf256_mul(a[3], 3)
        out[4 * col + 3] = _gf256_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf256_mul(a[3], 2)
    return out


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise SnovaModelError("AES block must be 16 bytes")
    schedule = aes128_expand_key(key)
    state = _aes_add_round_key(list(block), schedule[0])
    for round_index in range(1, 10):
        state = _aes_sub_bytes(state)
        state = _aes_shift_rows(state)
        state = _aes_mix_columns(state)
        state = _aes_add_round_key(state, schedule[round_index])
    state = _aes_sub_bytes(state)
    state = _aes_shift_rows(state)
    state = _aes_add_round_key(state, schedule[10])
    return bytes(state)


def aes128_ctr_stream(key: bytes, out_len: int) -> bytes:
    """Zero-IV AES-128-CTR with a big-endian 128-bit counter starting at 0.

    This matches the pinned oqs aes_c.c aes_ctr wrapper used by SNOVA's
    AES_128_CTR.
    """
    out = bytearray()
    counter = 0
    while len(out) < out_len:
        block = counter.to_bytes(16, "big")
        out.extend(aes128_encrypt_block(key, block))
        counter += 1
    return bytes(out[:out_len])


# ---------------------------------------------------------------------------
# Public-key expansion.
# ---------------------------------------------------------------------------
def snova_shake_stream(seed: bytes, out_len: int) -> bytes:
    """Indexed SHAKE128-CTR expansion: block_i = SHAKE128(seed || LE64(i))."""
    out = bytearray()
    block_index = 0
    while len(out) < out_len:
        hasher = hashlib.shake_128()
        hasher.update(seed)
        hasher.update(block_index.to_bytes(8, "little"))
        block = hasher.digest(SHAKE_RATE)
        out.extend(block)
        block_index += 1
    return bytes(out[:out_len])


def continuous_shake128_stream(seed: bytes, out_len: int) -> bytes:
    """Deliberately wrong mutant: plain continuous SHAKE128(seed)."""
    return hashlib.shake_128(seed).digest(out_len)


def bytes_prng_public(profile: SnovaProfile) -> int:
    l = profile.l
    m = profile.m_matrices
    n = profile.n_matrices
    sq = profile.sq_rank
    alpha = profile.alpha_terms
    nibbles = sq * (2 * m * alpha + m * (n * n - m * m)) + l * 2 * m * alpha
    return (nibbles + 1) // 2


def pk_expand(profile: SnovaProfile, public_seed: bytes) -> bytes:
    if len(public_seed) != profile.public_seed_bytes:
        raise SnovaModelError("public seed length does not match the profile")
    if profile.pk_expand_shake:
        return snova_shake_stream(public_seed, bytes_prng_public(profile))
    return aes128_ctr_stream(public_seed, bytes_prng_public(profile))


def _fixed_abq_blocks(profile: SnovaProfile) -> Dict[str, List[List[List[int]]]]:
    """SHAKE256("SNOVA ABQ") A/B/Q repair used when FIXED_ABQ is active."""
    l = profile.l
    m = profile.m_matrices
    sq = profile.sq_rank
    alpha = profile.alpha_terms
    total_bytes = m * alpha * (sq + l)
    stream = hashlib.shake_256(FIXED_ABQ_SEED).digest(total_bytes)
    ab_entries = unpack_nibbles(stream, 2 * m * alpha * sq)
    q_offset_bytes = alpha * sq
    q_count = 2 * m * alpha * l
    q_stream = stream[q_offset_bytes : q_offset_bytes + (q_count + 1) // 2]
    q_coeffs = unpack_nibbles(q_stream, q_count)
    s_mats = s_matrices(l)

    a_blocks: List[List[int]] = []
    b_blocks: List[List[int]] = []
    for pi in range(m):
        for index in range(alpha):
            slot = (pi * alpha + index) * sq
            a_blocks.append(be_invertible_by_add_a_s(ab_entries[slot : slot + sq], s_mats[1], l))
    for pi in range(m):
        for index in range(alpha):
            slot = ((m + pi) * alpha + index) * sq
            b_blocks.append(be_invertible_by_add_a_s(ab_entries[slot : slot + sq], s_mats[1], l))

    q1: List[List[int]] = []
    q2: List[List[int]] = []
    cursor = 0
    for _ in range(m * alpha):
        q1.append(gen_a_fqs(q_coeffs[cursor : cursor + l], l, s_mats))
        cursor += l
    for _ in range(m * alpha):
        q2.append(gen_a_fqs(q_coeffs[cursor : cursor + l], l, s_mats))
        cursor += l
    return {"A": a_blocks, "B": b_blocks, "Q1": q1, "Q2": q2}


def gen_a_b_q_p(profile: SnovaProfile, public_seed: bytes) -> Dict[str, List[List[List[int]]]]:
    """Decode A,B,Q1,Q2 and P11,P12,P21 from the pinned expansion stream."""
    l = profile.l
    m = profile.m_matrices
    v = profile.v
    o = profile.o
    sq = profile.sq_rank
    alpha = profile.alpha_terms
    n = profile.n_matrices

    if profile.fixed_abq:
        fixed = _fixed_abq_blocks(profile)
        a_blocks, b_blocks = fixed["A"], fixed["B"]
        q1, q2 = fixed["Q1"], fixed["Q2"]
        expanded = pk_expand(profile, public_seed)
    else:
        a_blocks = []
        b_blocks = []
        q1 = []
        q2 = []
        expanded = pk_expand(profile, public_seed)

    struct_nibbles = sq * (2 * m * alpha + m * (n * n - m * m))
    stream_nibbles = unpack_nibbles(expanded, struct_nibbles)
    s_mats = s_matrices(l)

    p11: List[List[int]] = []
    p12: List[List[int]] = []
    p21: List[List[int]] = []
    cursor = 0
    for _ in range(m * v * v):
        p11.append(stream_nibbles[cursor : cursor + sq])
        cursor += sq
    for _ in range(m * v * o):
        p12.append(stream_nibbles[cursor : cursor + sq])
        cursor += sq
    for _ in range(m * o * v):
        p21.append(stream_nibbles[cursor : cursor + sq])
        cursor += sq
    for pi in range(m):
        for index in range(alpha):
            block = stream_nibbles[cursor : cursor + sq]
            cursor += sq
            if not profile.fixed_abq:
                a_blocks.append(be_invertible_by_add_a_s(block, s_mats[1], l))
    for pi in range(m):
        for index in range(alpha):
            block = stream_nibbles[cursor : cursor + sq]
            cursor += sq
            if not profile.fixed_abq:
                b_blocks.append(be_invertible_by_add_a_s(block, s_mats[1], l))

    if not profile.fixed_abq:
        q_tail_nibbles = 2 * m * alpha * l
        tail_offset_bytes = bytes_prng_public(profile) - (q_tail_nibbles + 1) // 2
        tail = expanded[tail_offset_bytes:]
        q_coeffs = unpack_nibbles(tail, q_tail_nibbles)
        q_cursor = 0
        for _ in range(m * alpha):
            q1.append(gen_a_fqs(q_coeffs[q_cursor : q_cursor + l], l, s_mats))
            q_cursor += l
        for _ in range(m * alpha):
            q2.append(gen_a_fqs(q_coeffs[q_cursor : q_cursor + l], l, s_mats))
            q_cursor += l
    return {"P11": p11, "P12": p12, "P21": p21, "A": a_blocks, "B": b_blocks, "Q1": q1, "Q2": q2}


def gen_t12(profile: SnovaProfile, private_seed: bytes) -> List[List[List[int]]]:
    if len(private_seed) != profile.private_seed_bytes:
        raise SnovaModelError("private seed length does not match the profile")
    nibbles_count = profile.v * profile.o * profile.l
    stream = hashlib.shake_256(private_seed).digest((nibbles_count + 1) // 2)
    coefficients = unpack_nibbles(stream, nibbles_count)
    s_mats = s_matrices(profile.l)
    matrices: List[List[int]] = []
    cursor = 0
    for _ in range(profile.v):
        for _ in range(profile.o):
            matrices.append(gen_a_fqs(coefficients[cursor : cursor + profile.l], profile.l, s_mats))
            cursor += profile.l
    return matrices


def gen_f(profile: SnovaProfile, p: Dict[str, List[List[int]]], t12: List[List[int]]) -> Dict[str, List[List[int]]]:
    l = profile.l
    v = profile.v
    o = profile.o
    f11 = list(p["P11"])
    f12 = list(p["P12"])
    f21 = list(p["P21"])
    for i in range(profile.m_matrices):
        for j in range(v):
            for k in range(o):
                total = f12[(i * v + j) * o + k]
                for index in range(v):
                    total = mat_add(total, mat_mul(p["P11"][(i * v + j) * v + index], t12[index * o + k], l))
                f12[(i * v + j) * o + k] = total
    for i in range(profile.m_matrices):
        for j in range(o):
            for k in range(v):
                total = f21[(i * o + j) * v + k]
                for index in range(v):
                    total = mat_add(total, mat_mul(t12[index * o + j], p["P11"][(i * v + index) * v + k], l))
                f21[(i * o + j) * v + k] = total
    return {"F11": f11, "F12": f12, "F21": f21}


def gen_p22(
    profile: SnovaProfile,
    t12: List[List[int]],
    p21: List[List[int]],
    f12: List[List[int]],
) -> List[int]:
    l = profile.l
    v = profile.v
    o = profile.o
    out: List[int] = []
    for i in range(profile.m_matrices):
        for j in range(o):
            for k in range(o):
                total = zeros_matrix(l)
                for index in range(v):
                    term1 = mat_mul(t12[index * o + j], f12[(i * v + index) * o + k], l)
                    term2 = mat_mul(p21[(i * o + j) * v + index], t12[index * o + k], l)
                    total = mat_add(total, mat_add(term1, term2))
                out.extend(total)
    return out


def model_public_key(profile: SnovaProfile, public_seed: bytes, private_seed: bytes) -> bytes:
    p = gen_a_b_q_p(profile, public_seed)
    t12 = gen_t12(profile, private_seed)
    f = gen_f(profile, p, t12)
    p22 = gen_p22(profile, t12, p["P21"], f["F12"])
    return public_seed + pack_nibbles(p22)


def model_private_algebra(profile: SnovaProfile, public_seed: bytes, private_seed: bytes):
    """Return the P/T/F key material used by the alignment oracle."""
    p = gen_a_b_q_p(profile, public_seed)
    t12 = gen_t12(profile, private_seed)
    f = gen_f(profile, p, t12)
    return p, t12, f


# ---------------------------------------------------------------------------
# Signature decoding and the l^2+l public map.
# ---------------------------------------------------------------------------
def decode_signature(profile: SnovaProfile, signature: bytes) -> Tuple[List[List[int]], bytes]:
    if len(signature) != profile.sig_len:
        raise SnovaModelError("signature length does not match the profile")
    data = signature[: profile.signature_data_bytes]
    salt = signature[profile.signature_data_bytes : profile.signature_data_bytes + profile.salt_bytes]
    nibbles = unpack_nibbles(data, profile.n_matrices * profile.sq_rank)
    matrices = [nibbles[i * profile.sq_rank : (i + 1) * profile.sq_rank] for i in range(profile.n_matrices)]
    return matrices, salt


def decode_public_key(profile: SnovaProfile, public_key: bytes) -> Tuple[bytes, List[List[int]]]:
    if len(public_key) != profile.pk_len:
        raise SnovaModelError("public key length does not match the profile")
    seed = public_key[: profile.public_seed_bytes]
    nibbles = unpack_nibbles(public_key[profile.public_seed_bytes :], profile.m_matrices * profile.o * profile.o * profile.sq_rank)
    matrices = [
        nibbles[i * profile.sq_rank : (i + 1) * profile.sq_rank]
        for i in range(profile.m_matrices * profile.o * profile.o)
    ]
    return seed, matrices


def target_hash(profile: SnovaProfile, public_seed: bytes, digest: bytes, salt: bytes) -> bytes:
    stream = hashlib.shake_256(public_seed + digest + salt).digest(profile.hash_bytes)
    return stream


def message_digest(message: bytes) -> bytes:
    return hashlib.shake_256(message).digest(64)


def _assemble_p(profile: SnovaProfile, p: Dict[str, List[List[int]]], p22: List[List[int]]) -> List[List[int]]:
    """Assemble the m x n x n block matrix in the pinned struct order."""
    l = profile.l
    v = profile.v
    o = profile.o
    n = profile.n_matrices
    blocks: List[List[int]] = [zeros_matrix(l) for _ in range(profile.m_matrices * n * n)]
    for mi in range(profile.m_matrices):
        for ni in range(v):
            for nj in range(v):
                blocks[(mi * n + ni) * n + nj] = p["P11"][(mi * v + ni) * v + nj]
            for nj in range(o):
                blocks[(mi * n + ni) * n + (v + nj)] = p["P12"][(mi * v + ni) * o + nj]
        for ni in range(o):
            for nj in range(v):
                blocks[(mi * n + v + ni) * n + nj] = p["P21"][(mi * o + ni) * v + nj]
            for nj in range(o):
                blocks[(mi * n + v + ni) * n + (v + nj)] = p22[(mi * o + ni) * o + nj]
    return blocks


def _assemble_f(profile: SnovaProfile, f: Dict[str, List[List[int]]]) -> List[List[int]]:
    l = profile.l
    v = profile.v
    o = profile.o
    n = profile.n_matrices
    blocks: List[List[int]] = [zeros_matrix(l) for _ in range(profile.m_matrices * n * n)]
    for mi in range(profile.m_matrices):
        for ni in range(v):
            for nj in range(v):
                blocks[(mi * n + ni) * n + nj] = f["F11"][(mi * v + ni) * v + nj]
            for nj in range(o):
                blocks[(mi * n + ni) * n + (v + nj)] = f["F12"][(mi * v + ni) * o + nj]
        for ni in range(o):
            for nj in range(v):
                blocks[(mi * n + v + ni) * n + nj] = f["F21"][(mi * o + ni) * v + nj]
            # F22 is identically zero by the round-2 key relation.
    return blocks


def direct_map(
    profile: SnovaProfile,
    p_blocks: List[List[int]],
    abq: Dict[str, List[List[int]]],
    u_matrices: Sequence[Sequence[int]],
) -> bytes:
    """Ptilde(U) = sum_{alpha} A_l (U^T Q1 P[(i+alpha)%m] Q2 U) B_l."""
    l = profile.l
    m = profile.m_matrices
    n = profile.n_matrices
    alpha_count = profile.alpha_terms
    out = [0] * (m * profile.sq_rank)
    for mi in range(m):
        for alpha in range(alpha_count):
            mi_prime = (mi + alpha) % m
            a_block = abq["A"][mi * alpha_count + alpha]
            b_block = abq["B"][mi * alpha_count + alpha]
            q1 = abq["Q1"][mi * alpha_count + alpha]
            q2 = abq["Q2"][mi * alpha_count + alpha]
            for ni in range(n):
                left = mat_mul(a_block, mat_mul(mat_transpose(u_matrices[ni], l), q1, l), l)
                total = zeros_matrix(l)
                for nj in range(n):
                    right = mat_mul(mat_mul(q2, u_matrices[nj], l), b_block, l)
                    total = mat_add(total, mat_mul(p_blocks[(mi_prime * n + ni) * n + nj], right, l))
                out[mi * profile.sq_rank : (mi + 1) * profile.sq_rank] = mat_add(
                    out[mi * profile.sq_rank : (mi + 1) * profile.sq_rank], mat_mul(left, total, l)
                )
    return pack_nibbles(out)


def model_verify(
    profile: SnovaProfile,
    public_key: bytes,
    message: bytes,
    signature: bytes,
    *,
    check_padding: bool = True,
) -> bool:
    """Independent accept/reject decision for the locked profile.

    This models the cryptographic equation and the wire encoding; it does not
    model the target's API-length wrapper.
    """
    seed, p22 = decode_public_key(profile, public_key)
    u_matrices, salt = decode_signature(profile, signature)
    abq = gen_a_b_q_p(profile, seed)
    p_blocks = _assemble_p(profile, abq, p22)
    digest = message_digest(message)
    expected = signature_padding_mask(profile, target_hash(profile, seed, digest, salt))
    computed = direct_map(profile, p_blocks, abq, u_matrices)
    return computed == expected


def model_private_map(
    profile: SnovaProfile,
    f_blocks: List[List[int]],
    abq: Dict[str, List[List[int]]],
    x_matrices: Sequence[Sequence[int]],
) -> bytes:
    """Ftilde(X) using the private F block matrix (F22 = 0)."""
    return direct_map(profile, f_blocks, abq, x_matrices)


def transform_x_to_u(profile: SnovaProfile, t12: List[List[int]], x_matrices: Sequence[Sequence[int]]) -> List[List[int]]:
    l = profile.l
    v = profile.v
    o = profile.o
    u = []
    for index in range(v):
        value = list(x_matrices[index])
        for i in range(o):
            value = mat_add(value, mat_mul(t12[index * o + i], x_matrices[v + i], l))
        u.append(value)
    for index in range(o):
        u.append(list(x_matrices[v + index]))
    return u


def transform_u_to_x(profile: SnovaProfile, t12: List[List[int]], u_matrices: Sequence[Sequence[int]]) -> List[List[int]]:
    """T^{-1} = T in characteristic 2."""
    return transform_x_to_u(profile, t12, u_matrices)


# ---------------------------------------------------------------------------
# GF16 Gaussian elimination with independent verification.
# ---------------------------------------------------------------------------
def gauss_solve_gf16(
    matrix: Sequence[Sequence[int]],
    rhs: Sequence[int],
    *,
    allow_row_swap: bool = True,
    verify_solution: bool = True,
) -> Optional[List[int]]:
    """Solve matrix * x = rhs over GF16 or return None for a singular system."""
    size = len(matrix)
    if len(rhs) != size or any(len(row) != size for row in matrix):
        raise SnovaModelError("Gaussian system must be square")
    aug = [list(matrix[i]) + [rhs[i]] for i in range(size)]
    for col in range(size):
        if aug[col][col] == 0 and allow_row_swap:
            for row in range(col + 1, size):
                if aug[row][col] != 0:
                    aug[col], aug[row] = aug[row], aug[col]
                    break
        if aug[col][col] == 0:
            return None
        pivot_inverse = gf16_inv(aug[col][col])
        aug[col] = [gf16_mul(value, pivot_inverse) for value in aug[col]]
        for row in range(size):
            if row == col or aug[row][col] == 0:
                continue
            factor = aug[row][col]
            aug[row] = [aug[row][k] ^ gf16_mul(aug[col][k], factor) for k in range(size + 1)]
    solution = [aug[i][size] for i in range(size)]
    if verify_solution:
        for row in range(size):
            acc = 0
            for col in range(size):
                acc ^= gf16_mul(matrix[row][col], solution[col])
            if acc != rhs[row]:
                return None
    return solution


def gauss_solve_without_row_swap(matrix: Sequence[Sequence[int]], rhs: Sequence[int]) -> Optional[List[int]]:
    """Deliberately wrong mutant: fails on a zero pivot that needs a row swap."""
    return gauss_solve_gf16(matrix, rhs, allow_row_swap=False)


def gauss_retry_loop(
    systems: Sequence[Tuple[Sequence[Sequence[int]], Sequence[int]]],
    *,
    max_attempts: int = 8,
) -> Tuple[Optional[List[int]], int]:
    """Bounded retry: singular systems are discarded and the vinegar changes."""
    attempts = 0
    for matrix, rhs in systems:
        if attempts >= max_attempts:
            break
        attempts += 1
        solution = gauss_solve_gf16(matrix, rhs)
        if solution is not None:
            return solution, attempts
    return None, attempts


# ---------------------------------------------------------------------------
# Deterministic mutant catalogue used by the model tests.
# ---------------------------------------------------------------------------
MUTANTS = (
    "gf16_as_integer_mod16",
    "signature_length_floor",
    "dropped_salt",
    "dropped_spublic",
    "only_l_squared_terms",
    "fixed_i_prime",
    "p12_p21_swap",
    "missing_transpose",
    "indexed_shake_as_continuous",
    "counter_not_incrementing",
    "gauss_without_row_swap",
    "gauss_solution_unverified",
)


def expected_signature_length(v: int, o: int, l: int) -> int:
    return ((v + o) * l * l + 1) // 2 + 16


def expected_signature_length_floor(v: int, o: int, l: int) -> int:
    return ((v + o) * l * l) // 2 + 16


__all__ = [
    "AES_SBOX",
    "FIXED_ABQ_SEED",
    "GF16_MUL_TABLE",
    "MUTANTS",
    "SnovaModelError",
    "SnovaProfile",
    "aes128_ctr_stream",
    "aes128_encrypt_block",
    "be_invertible_by_add_a_s",
    "continuous_shake128_stream",
    "decode_public_key",
    "decode_signature",
    "direct_map",
    "expected_signature_length",
    "expected_signature_length_floor",
    "gauss_retry_loop",
    "gauss_solve_gf16",
    "gauss_solve_without_row_swap",
    "gen_a_b_q_p",
    "gen_a_fqs",
    "gen_f",
    "gen_p22",
    "gen_t12",
    "gf16_add",
    "gf16_inv",
    "gf16_mul",
    "integer_mod16_mul",
    "load_profiles",
    "mat_add",
    "mat_det",
    "mat_mul",
    "mat_transpose",
    "message_digest",
    "model_private_algebra",
    "model_private_map",
    "model_public_key",
    "model_verify",
    "pack_nibbles",
    "pack_nibbles_cut_in_half",
    "s_matrices",
    "signature_padding_mask",
    "snova_shake_stream",
    "target_hash",
    "transform_u_to_x",
    "transform_x_to_u",
    "unpack_nibbles",
    "unpack_nibbles_cut_in_half",
]

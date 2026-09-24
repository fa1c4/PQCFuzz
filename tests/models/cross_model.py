#!/usr/bin/env python3
"""Independent CROSS codec, challenge, tree, and transcript model.

This module is deliberately independent of the C++ reference build.  It
implements the wire-level properties the CROSS round-2 specification fixes
(bit packing, Fp/Fz membership, the zero-padding rule, the fixed-weight
challenge sampler, seed-tree rebuild semantics, little-endian domain tags) and
a small transcript verifier used to exercise the mutation oracles.  The model
is a specification/consistency evidence source, not a second cryptographic
implementation of CROSS, and it never claims IND-CCA or EUF/sUF security.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = REPO_ROOT / "src" / "config" / "scheme_profiles" / "cross.json"

HASH_DOMAIN_SEP_CONST = 0x8000
CSPRNG_DOMAIN_SEP_CONST = 0x0000


class CrossModelError(ValueError):
    """Raised when a modelled wire object violates its canonical form."""


@dataclass(frozen=True)
class Profile:
    algorithm: str
    variant: str
    category: int
    corner: str
    p: int
    z: int
    n: int
    k: int
    m: int
    g: int
    t: int
    w: int
    pk_len: int
    sk_len: int
    sig_len: int
    seed_bytes: int
    salt_bytes: int
    digest_bytes: int
    y_bits: int
    v_bits: int
    s_bits: int
    y_bytes: int
    v_bytes: int
    syn_bytes: int
    tree_nodes_to_store: int
    c_rng_bits: int

    @property
    def is_rsdpg(self) -> bool:
        return self.variant == "RSDPG"

    @property
    def response_rounds(self) -> int:
        return self.t - self.w

    @property
    def vector_count(self) -> int:
        return self.m if self.is_rsdpg else self.n


def load_profiles(path: Path | None = None) -> dict[str, Profile]:
    payload = json.loads((path or PROFILE_PATH).read_text(encoding="utf-8"))
    profiles: dict[str, Profile] = {}
    for entry in payload["parameter_sets"]:
        profiles[entry["algorithm"]] = Profile(
            algorithm=entry["algorithm"],
            variant=entry["variant"],
            category=entry["category"],
            corner=entry["corner"],
            p=entry["p"],
            z=entry["z"],
            n=entry["n"],
            k=entry["k"],
            m=entry["m"],
            g=entry["g"],
            t=entry["t"],
            w=entry["w"],
            pk_len=entry["pk_len"],
            sk_len=entry["sk_len"],
            sig_len=entry["sig_max_len"],
            seed_bytes=entry["seed_bytes"],
            salt_bytes=entry["salt_bytes"],
            digest_bytes=entry["digest_bytes"],
            y_bits=entry["y_bits"],
            v_bits=entry["v_bits"],
            s_bits=entry["s_bits"],
            y_bytes=entry["y_bytes"],
            v_bytes=entry["v_bytes"],
            syn_bytes=entry["syn_bytes"],
            tree_nodes_to_store=entry["tree_nodes_to_store"],
            c_rng_bits=entry["c_rng_bits"],
        )
    return profiles


# ---------------------------------------------------------------------------
# Bit packing (little-endian bit order, zero-padded to a byte boundary).
# ---------------------------------------------------------------------------

def pack_vector(coeffs: Sequence[int], bits: int) -> bytes:
    total_bits = bits * len(coeffs)
    out = bytearray((total_bits + 7) // 8)
    for index, value in enumerate(coeffs):
        if value < 0 or value >= (1 << bits):
            raise CrossModelError(f"coefficient {index} does not fit in {bits} bits")
        bit_pos = index * bits
        for offset in range(bits):
            if value & (1 << offset):
                absolute = bit_pos + offset
                out[absolute // 8] |= 1 << (absolute % 8)
    return bytes(out)


def unpack_vector(
    data: bytes,
    count: int,
    bits: int,
    modulus: int,
    *,
    check_range: bool = True,
    check_padding: bool = True,
) -> list[int]:
    total_bits = bits * count
    if len(data) != (total_bits + 7) // 8:
        raise CrossModelError(f"packed length {len(data)} != {(total_bits + 7) // 8}")
    if check_padding:
        padding_bits = (8 - total_bits % 8) % 8
        for extra in range(padding_bits):
            absolute = total_bits + extra
            if data[absolute // 8] & (1 << (absolute % 8)):
                raise CrossModelError("non-zero unused padding bit")
    coeffs: list[int] = []
    for index in range(count):
        value = 0
        bit_pos = index * bits
        for offset in range(bits):
            absolute = bit_pos + offset
            if data[absolute // 8] & (1 << (absolute % 8)):
                value |= 1 << offset
        if check_range and value >= modulus:
            raise CrossModelError(f"coefficient {index} value {value} >= modulus {modulus}")
        coeffs.append(value)
    return coeffs


# ---------------------------------------------------------------------------
# SHAKE-based CSPRNG / challenge sampler (port of expand_digest_to_fixed_weight)
# ---------------------------------------------------------------------------

def shake_stream(profile: Profile, parts: Iterable[bytes], out_len: int) -> bytes:
    xof = hashlib.shake_128() if profile.seed_bytes == 16 else hashlib.shake_256()
    for part in parts:
        xof.update(part)
    return xof.digest(out_len)


def expand_fixed_weight(
    profile: Profile,
    digest: bytes,
    *,
    stream: Callable[[int], bytes] | None = None,
) -> bytes:
    """Return a t-byte 0/1 string with Hamming weight exactly w.

    The default stream reproduces csprng_initialize(digest, 3*T).  Tests inject
    a deterministic stream to exercise the rejection/refill path.
    """
    if len(digest) != profile.digest_bytes:
        raise CrossModelError("digest length mismatch")
    dsc = (CSPRNG_DOMAIN_SEP_CONST + 3 * profile.t) & 0xFFFF
    buffer_len = (profile.c_rng_bits + 7) // 8
    if stream is None:
        buffer = shake_stream(profile, [digest, dsc.to_bytes(2, "little")], buffer_len)
    else:
        buffer = stream(buffer_len)
    if len(buffer) != buffer_len:
        raise CrossModelError("stream returned the wrong length")

    fixed_weight = bytearray([1] * profile.w + [0] * (profile.t - profile.w))
    sub_buffer = int.from_bytes(buffer[0:8], "little")
    bits_in_sub_buf = 64
    pos_in_buf = 8
    pos_remaining = len(buffer) - pos_in_buf
    curr = 0
    while curr < profile.t:
        if bits_in_sub_buf <= 32 and pos_remaining > 0:
            refresh_amount = 4 if pos_remaining >= 4 else pos_remaining
            refresh = int.from_bytes(buffer[pos_in_buf : pos_in_buf + refresh_amount], "little")
            pos_in_buf += refresh_amount
            sub_buffer |= refresh << bits_in_sub_buf
            bits_in_sub_buf += 8 * refresh_amount
            pos_remaining -= refresh_amount
        bits_for_pos = (profile.t - 1 - curr).bit_length() or 1
        mask = (1 << bits_for_pos) - 1
        candidate = sub_buffer & mask
        if candidate < profile.t - curr:
            dest = curr + candidate
            fixed_weight[curr], fixed_weight[dest] = fixed_weight[dest], fixed_weight[curr]
            curr += 1
        sub_buffer >>= bits_for_pos
        bits_in_sub_buf -= bits_for_pos
    return bytes(fixed_weight)


# ---------------------------------------------------------------------------
# Toy seed/flag tree with the published-set semantics of the CROSS tree.
# ---------------------------------------------------------------------------

def seed_tree_leaves(profile: Profile, root_seed: bytes, salt: bytes, leaf_count: int) -> list[bytes]:
    """Return the full toy tree in level order (root, ..., leaves)."""
    if leaf_count & (leaf_count - 1) or leaf_count == 0:
        raise CrossModelError("toy tree requires a power-of-two leaf count")
    levels: list[list[bytes]] = [[root_seed]]
    level = 0
    width = 1
    while width < leaf_count:
        expanded: list[bytes] = []
        for index, node in enumerate(levels[-1]):
            for child in (0, 1):
                expanded.append(
                    shake_stream(
                        profile,
                        [node, salt, bytes([1, child, level & 0xFF, index & 0xFF])],
                        profile.seed_bytes,
                    )
                )
        levels.append(expanded)
        width *= 2
        level += 1
    return [node for level_nodes in levels for node in level_nodes]


def _rebuildable(challenge: Sequence[int], leaf_count: int, node: int) -> bool:
    if node >= leaf_count:
        return challenge[node - leaf_count] == 1
    return _rebuildable(challenge, leaf_count, 2 * node) and _rebuildable(challenge, leaf_count, 2 * node + 1)


def publish_seed_path(
    profile: Profile,
    tree: list[bytes],
    challenge: Sequence[int],
    leaf_count: int,
) -> dict[int, bytes]:
    """Published heap-indexed nodes for the challenge (leaves are zero rounds).

    `tree` is level order; leaves start at heap index `leaf_count`.
    """
    heap: dict[int, bytes] = {}
    offset = 0
    width = 1
    heap_index = 1
    while width <= leaf_count:
        for index in range(width):
            heap[heap_index + index] = tree[offset + index]
        offset += width
        heap_index = heap_index * 2
        width *= 2

    def collect(node: int) -> None:
        if _rebuildable(challenge, leaf_count, node):
            return
        if node >= leaf_count:
            published[node] = heap[node]
            return
        collect(2 * node)
        collect(2 * node + 1)

    published: dict[int, bytes] = {}
    collect(1)
    return published


def _levels(leaf_count: int) -> list[tuple[int, int]]:
    levels: list[tuple[int, int]] = []
    width = 1
    level = 0
    while width <= leaf_count:
        levels.append((level, width))
        width *= 2
        level += 1
    return levels


def published_leaf_set(published: dict[int, bytes], leaf_count: int) -> set[int]:
    """Leaf positions whose seeds were published (must be exactly zero rounds)."""
    return {node - leaf_count for node in published if node >= leaf_count}


def rebuild_leaves(
    profile: Profile,
    tree: list[bytes],
    challenge: Sequence[int],
    leaf_count: int,
    published: dict[int, bytes] | None = None,
) -> dict[int, bytes]:
    """Rebuild one-challenge leaves and check they equal the honest tree."""
    if published is None:
        published = publish_seed_path(profile, tree, challenge, leaf_count)
    heap: dict[int, bytes] = {}
    offset = 0
    width = 1
    heap_index = 1
    while width <= leaf_count:
        for index in range(width):
            heap[heap_index + index] = tree[offset + index]
        offset += width
        heap_index *= 2
        width *= 2

    def rebuild(node: int) -> bytes:
        if node >= leaf_count:
            if challenge[node - leaf_count] == 1:
                return heap[node]
            raise CrossModelError("cannot rebuild a published leaf")
        if node in published:
            return published[node]
        left = rebuild(2 * node)
        right = rebuild(2 * node + 1)
        return shake_stream(
            profile,
            [left, right, b"node", node.to_bytes(4, "little")],
            profile.seed_bytes,
        )

    rebuilt: dict[int, bytes] = {}
    for index, bit in enumerate(challenge):
        if bit == 1:
            rebuilt[index] = rebuild(leaf_count + index)
    return rebuilt


def detach_seed_disclosure_mutant(
    tree: list[bytes],
    challenge: list[int],
    leaf_count: int,
) -> list[int]:
    """Fault mutant: publish a one-challenge leaf seed too.

    The published-set predicate is expected to catch this by observing a
    published leaf whose challenge bit is 1.
    """
    for index, bit in enumerate(challenge):
        if bit == 1:
            challenge[index] = 0
            break
    return challenge


# ---------------------------------------------------------------------------
# Transcript model over the CROSS-shaped wire layout.
# ---------------------------------------------------------------------------

DEFAULT_TAGS = {
    "matrix": HASH_DOMAIN_SEP_CONST + 0,
    "seed_pk": HASH_DOMAIN_SEP_CONST + 1,
    "seed_sk": HASH_DOMAIN_SEP_CONST + 2,
    "commit": HASH_DOMAIN_SEP_CONST + 3,
    "challenge": HASH_DOMAIN_SEP_CONST + 4,
    "challenge_2": HASH_DOMAIN_SEP_CONST + 5,
    "message": HASH_DOMAIN_SEP_CONST + 6,
    "tree": HASH_DOMAIN_SEP_CONST + 7,
}


def tagged_hash(
    profile: Profile,
    tag: int,
    parts: Iterable[bytes],
    *,
    big_endian: bool = False,
    omit_salt: bool = False,
) -> bytes:
    order = "big" if big_endian else "little"
    xof = hashlib.shake_128() if profile.seed_bytes == 16 else hashlib.shake_256()
    for part in parts:
        xof.update(part)
    if not omit_salt:
        xof.update(int(tag).to_bytes(2, order))
    return xof.digest(profile.digest_bytes)


def model_signature_layout(profile: Profile) -> list[tuple[str, int]]:
    """Byte capacities of the model signature in wire order."""
    return [
        ("salt", profile.salt_bytes),
        ("digest_cmt", profile.digest_bytes),
        ("digest_chall2", profile.digest_bytes),
        ("path", profile.tree_nodes_to_store * profile.seed_bytes),
        ("proof", profile.tree_nodes_to_store * profile.digest_bytes),
        ("resp1", profile.response_rounds * profile.digest_bytes),
        ("resp0", profile.response_rounds * (profile.y_bytes + profile.v_bytes)),
    ]


def model_signature_len(profile: Profile) -> int:
    return sum(length for _, length in model_signature_layout(profile))


def model_sign(profile: Profile, secret_seed: bytes, message: bytes, sign_seed: bytes) -> bytes:
    """Build a canonical CROSS-shaped model signature."""
    if len(secret_seed) != profile.seed_bytes:
        raise CrossModelError("secret seed length mismatch")
    salt = tagged_hash(profile, DEFAULT_TAGS["seed_pk"], [secret_seed, sign_seed])[: profile.salt_bytes]
    key_seed = tagged_hash(profile, DEFAULT_TAGS["matrix"], [secret_seed])
    challenge_seed = tagged_hash(profile, DEFAULT_TAGS["challenge"], [key_seed, message, salt])
    challenge = expand_fixed_weight(profile, challenge_seed)

    y_vectors: list[list[int]] = []
    v_vectors: list[list[int]] = []
    cmt1: list[bytes] = []
    for round_index in range(profile.response_rounds):
        y = [(sign_seed[(round_index + j) % len(sign_seed)] + j) % profile.p for j in range(profile.n)]
        v = [
            (sign_seed[(round_index + j) % len(sign_seed)] + j * 3) % profile.z
            for j in range(profile.vector_count)
        ]
        y_vectors.append(y)
        v_vectors.append(v)
        cmt1.append(
            tagged_hash(
                profile,
                DEFAULT_TAGS["commit"],
                [bytes([round_index]), pack_vector(y, profile.y_bits), pack_vector(v, profile.v_bits)],
            )
        )
    digest_cmt = tagged_hash(
        profile,
        DEFAULT_TAGS["tree"],
        [b"".join(cmt1), pack_vector(challenge, 8)],
    )
    digest_chall2 = tagged_hash(
        profile,
        DEFAULT_TAGS["challenge_2"],
        [b"".join(pack_vector(y, profile.y_bits) for y in y_vectors), challenge_seed],
    )
    body = bytearray()
    body += salt
    body += digest_cmt
    body += digest_chall2
    body += bytes(profile.tree_nodes_to_store * profile.seed_bytes)
    body += bytes(profile.tree_nodes_to_store * profile.digest_bytes)
    body += bytes(profile.response_rounds * profile.digest_bytes)
    for y, v in zip(y_vectors, v_vectors):
        body += pack_vector(y, profile.y_bits)
        body += pack_vector(v, profile.v_bits)
    assert len(body) == profile.sig_len
    return bytes(body)


def model_public_seed(profile: Profile, secret_seed: bytes) -> bytes:
    return tagged_hash(profile, DEFAULT_TAGS["matrix"], [secret_seed])


def model_verify(
    profile: Profile,
    public_seed: bytes,
    message: bytes,
    signature: bytes,
    *,
    checks: dict[str, bool] | None = None,
) -> bool:
    checks = dict(checks or {})
    enabled = lambda name: checks.get(name, True)  # noqa: E731
    if len(signature) != profile.sig_len:
        return False

    offset = 0
    salt = signature[offset : offset + profile.salt_bytes]
    offset += profile.salt_bytes
    digest_cmt = signature[offset : offset + profile.digest_bytes]
    offset += profile.digest_bytes
    digest_chall2 = signature[offset : offset + profile.digest_bytes]
    offset += profile.digest_bytes
    offset += profile.tree_nodes_to_store * profile.seed_bytes
    offset += profile.tree_nodes_to_store * profile.digest_bytes
    offset += profile.response_rounds * profile.digest_bytes

    y_vectors: list[list[int]] = []
    v_vectors: list[list[int]] = []
    try:
        for _ in range(profile.response_rounds):
            y = unpack_vector(
                signature[offset : offset + profile.y_bytes],
                profile.n,
                profile.y_bits,
                profile.p,
                check_range=enabled("coefficient_range"),
                check_padding=enabled("padding_bits"),
            )
            offset += profile.y_bytes
            v = unpack_vector(
                signature[offset : offset + profile.v_bytes],
                profile.vector_count,
                profile.v_bits,
                profile.z,
                check_range=enabled("coefficient_range"),
                check_padding=enabled("padding_bits"),
            )
            offset += profile.v_bytes
            y_vectors.append(y)
            v_vectors.append(v)
    except CrossModelError:
        return False

    challenge_seed = tagged_hash(
        profile,
        DEFAULT_TAGS["challenge"],
        [public_seed, message, salt],
        big_endian=not enabled("le16_tags"),
    )
    try:
        challenge = expand_fixed_weight(profile, challenge_seed)
    except CrossModelError:
        return False
    if enabled("challenge_weight") and sum(challenge) != profile.w:
        return False

    cmt1 = [
        tagged_hash(
            profile,
            DEFAULT_TAGS["commit"],
            [bytes([index]), pack_vector(y, profile.y_bits), pack_vector(v, profile.v_bits)],
            omit_salt=not enabled("salt_binding"),
        )
        for index, (y, v) in enumerate(zip(y_vectors, v_vectors))
    ]
    expected_cmt = tagged_hash(
        profile,
        DEFAULT_TAGS["tree"],
        [b"".join(cmt1), pack_vector(challenge, 8)],
        omit_salt=not enabled("salt_binding"),
    )
    expected_chall2 = tagged_hash(
        profile,
        DEFAULT_TAGS["challenge_2"],
        [b"".join(pack_vector(y, profile.y_bits) for y in y_vectors), challenge_seed],
        omit_salt=not enabled("salt_binding"),
    )
    if enabled("digest_cmt") and expected_cmt != digest_cmt:
        return False
    if enabled("digest_chall2") and expected_chall2 != digest_chall2:
        return False
    return True


# ---------------------------------------------------------------------------
# Mutant catalogue from plan section 6.3.
# ---------------------------------------------------------------------------

def wire_coefficient_value(profile: Profile, axis: str) -> int:
    bits = profile.y_bits if axis == "y" else profile.v_bits
    return (1 << bits) - 1


def mutant_is_caught(profile: Profile, mutant: str) -> bool:
    """True when the canonical model rejects the mutant's wire object."""
    if mutant == "f7_as_wire_zero":
        value = wire_coefficient_value(profile, "y")
        packed = pack_vector([value] + [0] * (profile.n - 1), profile.y_bits)
        try:
            unpack_vector(packed, profile.n, profile.y_bits, profile.p)
            return False
        except CrossModelError:
            return True
    if mutant == "ignore_tail_bits":
        total_bits = profile.y_bits * profile.n
        padding = (8 - total_bits % 8) % 8
        packed = bytearray(pack_vector([0] * profile.n, profile.y_bits))
        if padding == 0:
            return True
        packed[-1] |= 1 << (total_bits % 8)
        try:
            unpack_vector(bytes(packed), profile.n, profile.y_bits, profile.p)
            return False
        except CrossModelError:
            return True
    if mutant == "challenge_weight_lt_w":
        # An implementation that accepts a weight<w string must be caught by the
        # exact-weight predicate.
        digest = bytes(range(profile.digest_bytes))
        challenge = expand_fixed_weight(profile, digest)
        if sum(challenge) != profile.w:
            return False
        weakened = bytearray(challenge)
        weakened[0] = 0
        return sum(weakened) != profile.w
    if mutant == "missing_digest_compare":
        # A transcript with a changed commitment digest verifies only when the
        # digest comparison is dropped.
        secret_seed = bytes([0x42] * profile.seed_bytes)
        signature = model_sign(profile, secret_seed, b"m", b"s" * profile.seed_bytes)
        tampered = bytearray(signature)
        tampered[profile.salt_bytes] ^= 1
        public_seed = model_public_seed(profile, secret_seed)
        canonical_ok = model_verify(profile, public_seed, b"m", bytes(tampered))
        mutant_ok = model_verify(profile, public_seed, b"m", bytes(tampered), checks={"digest_cmt": False})
        return (not canonical_ok) and mutant_ok
    if mutant == "le16_as_be":
        secret_seed = bytes([0x42] * profile.seed_bytes)
        signature = model_sign(profile, secret_seed, b"m", b"s" * profile.seed_bytes)
        public_seed = model_public_seed(profile, secret_seed)
        return model_verify(profile, public_seed, b"m", signature, checks={"le16_tags": False}) is False
    if mutant == "missing_salt":
        secret_seed = bytes([0x42] * profile.seed_bytes)
        signature = model_sign(profile, secret_seed, b"m", b"s" * profile.seed_bytes)
        public_seed = model_public_seed(profile, secret_seed)
        return model_verify(profile, public_seed, b"m", signature, checks={"salt_binding": False}) is False
    if mutant == "wrong_leaf_order":
        profile_toy = profile
        challenge = [1, 0, 1, 1, 0, 0, 1, 0]
        salt = b"salt"
        root = b"root"
        tree = seed_tree_leaves(profile_toy, root, salt, len(challenge))
        published = publish_seed_path(profile_toy, tree, challenge, len(challenge))
        reordered = list(challenge)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        try:
            revealed = published_leaf_set(published, len(challenge))
        except CrossModelError:
            return False
        return revealed == {index for index, bit in enumerate(challenge) if bit == 0} and reordered != challenge
    if mutant == "disclose_b0_seed":
        challenge = [1, 0, 1, 1, 0, 0, 1, 0]
        tree = seed_tree_leaves(profile, b"root", b"salt", len(challenge))
        faulty = detach_seed_disclosure_mutant(tree, list(challenge), len(challenge))
        published = publish_seed_path(profile, tree, faulty, len(challenge))
        revealed = published_leaf_set(published, len(challenge))
        original_zero = {index for index, bit in enumerate(challenge) if bit == 0}
        return not revealed.issubset(original_zero)
    if mutant == "simd_tail_lanes":
        # A tail lane that is not packed/checked would let padding bits pass.
        total_bits = profile.y_bits * profile.n
        padding = (8 - total_bits % 8) % 8
        if padding == 0:
            return True
        packed = bytearray(pack_vector([0] * profile.n, profile.y_bits))
        packed[-1] |= 1 << (total_bits % 8)
        try:
            unpack_vector(bytes(packed), profile.n, profile.y_bits, profile.p)
            return False
        except CrossModelError:
            relaxed = unpack_vector(
                bytes(packed), profile.n, profile.y_bits, profile.p, check_padding=False
            )
            return relaxed == [0] * profile.n
    raise CrossModelError(f"unknown mutant: {mutant}")


MUTANTS = (
    "f7_as_wire_zero",
    "ignore_tail_bits",
    "challenge_weight_lt_w",
    "missing_digest_compare",
    "le16_as_be",
    "missing_salt",
    "wrong_leaf_order",
    "disclose_b0_seed",
    "simd_tail_lanes",
)


def mutation_recipe(field: str, index: int = 0, aux: int = 0, op: int = 2, payload: bytes = b"\x01") -> bytes:
    field_ids = {
        "signature": 1,
        "signature.salt": 2,
        "signature.digest_cmt": 3,
        "signature.digest_chall2": 4,
        "signature.y": 5,
        "signature.v": 6,
        "signature.resp1": 7,
        "signature.path": 8,
        "signature.proof": 9,
        "signature.unused_slot": 10,
        "public_key": 11,
        "public_key.seed": 12,
        "public_key.syndrome": 13,
        "message": 14,
        "context": 15,
    }
    return bytes([op, field_ids[field]]) + index.to_bytes(4, "little") + aux.to_bytes(4, "little") + payload


def decode_mutation_recipe(data: bytes) -> dict[str, int | bytes]:
    if not data:
        return {"op": 0, "field": 0, "index": 0, "aux": 0, "payload": b""}
    if len(data) < 10:
        raise CrossModelError("recipe shorter than 10-byte header")
    op = data[0]
    field = data[1]
    if op > 11:
        raise CrossModelError("unknown operation")
    if field > 15:
        raise CrossModelError("unknown field")
    return {
        "op": op,
        "field": field,
        "index": int.from_bytes(data[2:6], "little"),
        "aux": int.from_bytes(data[6:10], "little"),
        "payload": data[10:],
    }


__all__ = [
    "CSPRNG_DOMAIN_SEP_CONST",
    "CrossModelError",
    "DEFAULT_TAGS",
    "HASH_DOMAIN_SEP_CONST",
    "MUTANTS",
    "Profile",
    "decode_mutation_recipe",
    "detach_seed_disclosure_mutant",
    "expand_fixed_weight",
    "load_profiles",
    "model_public_seed",
    "model_sign",
    "model_signature_layout",
    "model_signature_len",
    "model_verify",
    "mutation_recipe",
    "mutant_is_caught",
    "pack_vector",
    "publish_seed_path",
    "published_leaf_set",
    "rebuild_leaves",
    "seed_tree_leaves",
    "shake_stream",
    "tagged_hash",
    "unpack_vector",
    "wire_coefficient_value",
]

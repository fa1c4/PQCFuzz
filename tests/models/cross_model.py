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
# Exact CROSS seed tree / Merkle tree (port of the pinned round-2
# seedtree.c and merkle.c, including the truncated non-power-of-two topology).
# ---------------------------------------------------------------------------

def _clog2(value: int) -> int:
    if value < 1:
        raise CrossModelError("clog2 requires a positive value")
    return max((value - 1).bit_length(), 1)


def _l_child(node: int) -> int:
    return 2 * node + 1


def _r_child(node: int) -> int:
    return 2 * node + 2


def _parent(node: int) -> int:
    return (node - 1) // 2 if node % 2 else (node - 2) // 2


@dataclass(frozen=True)
class TreeLayout:
    depth: int
    offsets: list[int]
    nodes_per_level: list[int]
    leaves_per_level: list[int]
    start_indices: list[int]  # deepest leaf group first
    consecutive_leaves: list[int]
    level_start: list[int]

    @property
    def total_nodes(self) -> int:
        return sum(self.nodes_per_level)


def tree_offsets_and_nodes(t: int) -> tuple[list[int], list[int]]:
    """Port of Additional_Implementations/.../compute_derived_parameters.py."""
    depth = _clog2(t)
    missing = [2 ** (index - 1) for index in range(1, depth + 1)]
    missing.insert(0, 0)
    remaining = t - 2 ** (depth - 1)
    level = 1
    while remaining > 0:
        inner_depth = 0
        found = False
        while not found:
            if remaining <= 2**inner_depth:
                for index in range(inner_depth, 0, -1):
                    missing[level + index] -= 2 ** (index - 1)
                remaining -= (2 ** _clog2(remaining)) // 2
                missing[level] -= 1
                level += 1
                found = True
            else:
                inner_depth += 1
    offsets = list(missing)
    for index in range(depth, -1, -1):
        for prior in range(index):
            offsets[index] -= offsets[prior]
    nodes_per_level = [2**index - missing[index] for index in range(depth + 1)]
    return offsets, nodes_per_level


def tree_leaves(t: int, offsets: list[int]) -> tuple[list[int], list[int], list[int]]:
    """Port of tree_leaves: leaf count per level plus ordered groups."""
    depth = _clog2(t)
    leaves_per_level = [0] * (depth + 1)
    start_index_per_level = [0] * (depth + 1)
    remaining = t
    level = 0
    root_node = 0
    left_child = _l_child(root_node) - offsets[level]
    while remaining > 0:
        inner_depth = 1
        subtree_found = False
        while not subtree_found:
            if remaining <= 2**inner_depth:
                for _ in range((2 ** _clog2(remaining)) // 2):
                    if remaining == 1:
                        leaves_per_level[level] += 1
                        if start_index_per_level[level] == 0:
                            start_index_per_level[level] = root_node
                    else:
                        leaves_per_level[level + inner_depth] += 1
                        if start_index_per_level[level + inner_depth] == 0:
                            start_index_per_level[level + inner_depth] = left_child
                root_node = _r_child(root_node) - offsets[level]
                left_child = _l_child(root_node) - offsets[level]
                level += 1
                remaining -= (2 ** _clog2(remaining)) // 2
                subtree_found = True
            else:
                left_child = _l_child(left_child) - offsets[level + inner_depth]
                inner_depth += 1
    consecutive = [count for count in leaves_per_level if count != 0]
    starts = [index for index in start_index_per_level if index != 0]
    return leaves_per_level, starts[::-1], consecutive[::-1]


def tree_layout(t: int) -> TreeLayout:
    depth = _clog2(t)
    offsets, nodes_per_level = tree_offsets_and_nodes(t)
    leaves_per_level, start_indices, consecutive = tree_leaves(t, offsets)
    level_start = [0] * (depth + 1)
    running = 0
    for index, count in enumerate(nodes_per_level):
        level_start[index] = running
        running += count
    if running != 2 * t - 1:
        raise CrossModelError(f"derived tree for t={t} has {running} nodes, expected {2 * t - 1}")
    if sum(leaves_per_level) != t:
        raise CrossModelError(f"derived tree for t={t} has {sum(leaves_per_level)} leaves")
    return TreeLayout(
        depth=depth,
        offsets=offsets,
        nodes_per_level=nodes_per_level,
        leaves_per_level=leaves_per_level,
        start_indices=start_indices,
        consecutive_leaves=consecutive,
        level_start=level_start,
    )


def _domain_tag(dsc: int) -> bytes:
    return (dsc & 0xFFFF).to_bytes(2, "little")


def gen_seed_tree(profile: Profile, root_seed: bytes, salt: bytes, layout: TreeLayout | None = None) -> bytes:
    """SHAKE expansion of the full linearized seed tree (seedtree.c)."""
    if len(root_seed) != profile.seed_bytes or len(salt) != profile.salt_bytes:
        raise CrossModelError("seed tree root/salt length mismatch")
    layout = layout or tree_layout(profile.t)
    seed_len = profile.seed_bytes
    tree = bytearray(layout.total_nodes * seed_len)
    tree[0:seed_len] = root_seed
    for level in range(layout.depth):
        internal = layout.nodes_per_level[level] - layout.leaves_per_level[level]
        for node_in_level in range(internal):
            father = layout.level_start[level] + node_in_level
            left_child = 2 * father + 1 - layout.offsets[level]
            dsc = (CSPRNG_DOMAIN_SEP_CONST + father) & 0xFFFF
            children = shake_stream(
                profile,
                [bytes(tree[father * seed_len : (father + 1) * seed_len]), salt, _domain_tag(dsc)],
                2 * seed_len,
            )
            tree[left_child * seed_len : (left_child + 2) * seed_len] = children
    return bytes(tree)


def seed_leaves(profile: Profile, tree: bytes, layout: TreeLayout | None = None) -> list[bytes]:
    """Extract the t round seeds in round order (seedtree.c seed_leaves)."""
    layout = layout or tree_layout(profile.t)
    seed_len = profile.seed_bytes
    if len(tree) != layout.total_nodes * seed_len:
        raise CrossModelError("seed tree length mismatch")
    leaves: list[bytes] = []
    for group, count in enumerate(layout.consecutive_leaves):
        for index in range(count):
            offset = (layout.start_indices[group] + index) * seed_len
            leaves.append(tree[offset : offset + seed_len])
    return leaves


def compute_seeds_to_publish(layout: TreeLayout, indices_to_publish: Sequence[int]) -> bytearray:
    """Port of compute_seeds_to_publish (flag-tree over the truncated topology)."""
    if len(indices_to_publish) != sum(layout.consecutive_leaves):
        raise CrossModelError("challenge length does not match the tree leaf count")
    flags = bytearray(layout.total_nodes)
    ordered = list(indices_to_publish)
    counter = 0
    for group, count in enumerate(layout.consecutive_leaves):
        for index in range(count):
            flags[layout.start_indices[group] + index] = 1 if ordered[counter] else 0
            counter += 1
    start_node = layout.start_indices[0]
    for level in range(layout.depth, 0, -1):
        for index in range(layout.nodes_per_level[level] - 2, -1, -2):
            current = start_node + index
            parent = _parent(current) + (layout.offsets[level - 1] >> 1)
            flags[parent] = 1 if (flags[current] == 1 and flags[current + 1] == 1) else 0
        start_node -= layout.nodes_per_level[level - 1]
    return flags


def seed_path(
    profile: Profile,
    tree: bytes,
    indices_to_publish: Sequence[int],
    layout: TreeLayout | None = None,
) -> tuple[bytes, int]:
    """Published seed nodes for one challenge (seedtree.c seed_path)."""
    layout = layout or tree_layout(profile.t)
    flags = compute_seeds_to_publish(layout, indices_to_publish)
    seed_len = profile.seed_bytes
    if len(tree) != layout.total_nodes * seed_len:
        raise CrossModelError("seed tree length mismatch")
    published = bytearray()
    start_node = 1
    for level in range(1, layout.depth + 1):
        for node_in_level in range(layout.nodes_per_level[level]):
            current = start_node + node_in_level
            father = _parent(current) + (layout.offsets[level - 1] >> 1)
            if flags[current] == 1 and flags[father] == 0:
                published.extend(tree[current * seed_len : (current + 1) * seed_len])
        start_node += layout.nodes_per_level[level]
    return bytes(published), len(published) // seed_len


def rebuild_tree(
    profile: Profile,
    indices_to_publish: Sequence[int],
    stored_seeds: bytes,
    salt: bytes,
    layout: TreeLayout | None = None,
) -> tuple[bytes, bool]:
    """Rebuild the published seeds and check the zero-padding contract."""
    layout = layout or tree_layout(profile.t)
    flags = compute_seeds_to_publish(layout, indices_to_publish)
    seed_len = profile.seed_bytes
    tree = bytearray(layout.total_nodes * seed_len)
    nodes_used = 0
    start_node = 1
    for level in range(1, layout.depth + 1):
        for node_in_level in range(layout.nodes_per_level[level]):
            current = start_node + node_in_level
            father = _parent(current) + (layout.offsets[level - 1] >> 1)
            left_child = 2 * current + 1 - layout.offsets[level]
            if flags[current] == 1 and flags[father] == 0:
                tree[current * seed_len : (current + 1) * seed_len] = stored_seeds[
                    nodes_used * seed_len : (nodes_used + 1) * seed_len
                ]
                nodes_used += 1
            if flags[current] == 1 and node_in_level < layout.nodes_per_level[level] - layout.leaves_per_level[level]:
                dsc = (CSPRNG_DOMAIN_SEP_CONST + current) & 0xFFFF
                children = shake_stream(
                    profile,
                    [bytes(tree[current * seed_len : (current + 1) * seed_len]), salt, _domain_tag(dsc)],
                    2 * seed_len,
                )
                tree[left_child * seed_len : (left_child + 2) * seed_len] = children
        start_node += layout.nodes_per_level[level]
    expected_bytes = profile.tree_nodes_to_store * seed_len
    padding = stored_seeds[nodes_used * seed_len :]
    padding_ok = len(stored_seeds) == expected_bytes and all(byte == 0 for byte in padding)
    return bytes(tree), padding_ok


def _merkle_place(layout: TreeLayout, tree: list[bytes | None], leaves: Sequence[bytes]) -> None:
    if len(leaves) != sum(layout.consecutive_leaves):
        raise CrossModelError("commitment count does not match the tree leaf count")
    counter = 0
    for group, count in enumerate(layout.consecutive_leaves):
        for index in range(count):
            tree[layout.start_indices[group] + index] = leaves[counter]
            counter += 1


def _merkle_hash(profile: Profile, left: bytes, right: bytes) -> bytes:
    return shake_stream(
        profile,
        [left, right, _domain_tag(HASH_DOMAIN_SEP_CONST)],
        profile.digest_bytes,
    )


def merkle_tree_root(
    profile: Profile,
    leaves: Sequence[bytes],
    layout: TreeLayout | None = None,
) -> tuple[bytes, list[bytes]]:
    """Bottom-up Merkle root over the CROSS truncated tree (merkle.c)."""
    layout = layout or tree_layout(profile.t)
    tree: list[bytes | None] = [None] * layout.total_nodes
    _merkle_place(layout, tree, leaves)
    start_node = layout.start_indices[0]
    for level in range(layout.depth, 0, -1):
        for index in range(layout.nodes_per_level[level] - 2, -1, -2):
            current = start_node + index
            parent = _parent(current) + (layout.offsets[level - 1] >> 1)
            left = tree[current]
            right = tree[current + 1]
            if left is None or right is None:
                raise CrossModelError("merkle tree is missing a child node")
            tree[parent] = _merkle_hash(profile, left, right)
        start_node -= layout.nodes_per_level[level - 1]
    root = tree[0]
    if root is None:
        raise CrossModelError("merkle tree root was not computed")
    return root, [node if node is not None else b"" for node in tree]


def merkle_tree_proof(
    profile: Profile,
    tree: Sequence[bytes],
    leaves_to_reveal: Sequence[int],
    layout: TreeLayout | None = None,
) -> tuple[bytes, int]:
    """Port of tree_proof (sibling digests for the hidden leaves)."""
    layout = layout or tree_layout(profile.t)
    flags = bytearray(layout.total_nodes)
    ordered = list(leaves_to_reveal)
    counter = 0
    for group, count in enumerate(layout.consecutive_leaves):
        for index in range(count):
            if ordered[counter] == 0:
                flags[layout.start_indices[group] + index] = 1
            counter += 1
    proof = bytearray()
    start_node = layout.start_indices[0]
    published = 0
    for level in range(layout.depth, 0, -1):
        for index in range(layout.nodes_per_level[level] - 2, -1, -2):
            current = start_node + index
            parent = _parent(current) + (layout.offsets[level - 1] >> 1)
            flags[parent] = 1 if (flags[current] == 1 or flags[current + 1] == 1) else 0
            if flags[current] == 0 and flags[current + 1] == 1:
                proof.extend(tree[current])
                published += 1
            if flags[current] == 1 and flags[current + 1] == 0:
                proof.extend(tree[current + 1])
                published += 1
        start_node -= layout.nodes_per_level[level - 1]
    return bytes(proof), published


def recompute_merkle_root(
    profile: Profile,
    leaves: Sequence[bytes],
    proof: bytes,
    leaves_to_reveal: Sequence[int],
    layout: TreeLayout | None = None,
) -> tuple[bytes, bool]:
    """Port of recompute_root including the zero-padding check."""
    layout = layout or tree_layout(profile.t)
    digest_len = profile.digest_bytes
    tree: list[bytes | None] = [None] * layout.total_nodes
    _merkle_place(layout, tree, leaves)
    flags = bytearray(layout.total_nodes)
    ordered = list(leaves_to_reveal)
    counter = 0
    for group, count in enumerate(layout.consecutive_leaves):
        for index in range(count):
            if ordered[counter] == 0:
                flags[layout.start_indices[group] + index] = 1
            counter += 1
    published = 0
    start_node = layout.start_indices[0]
    for level in range(layout.depth, 0, -1):
        for index in range(layout.nodes_per_level[level] - 2, -1, -2):
            current = start_node + index
            parent = _parent(current) + (layout.offsets[level - 1] >> 1)
            if flags[current] == 0 and flags[current + 1] == 0:
                continue
            if flags[current] == 1:
                left = tree[current]
            else:
                left = proof[published * digest_len : (published + 1) * digest_len]
                published += 1
            if flags[current + 1] == 1:
                right = tree[current + 1]
            else:
                right = proof[published * digest_len : (published + 1) * digest_len]
                published += 1
            if left is None or right is None:
                raise CrossModelError("merkle recompute is missing a child digest")
            tree[parent] = _merkle_hash(profile, left, right)
            flags[parent] = 1
        start_node -= layout.nodes_per_level[level - 1]
    root = tree[0]
    if root is None:
        raise CrossModelError("merkle root was not recomputed")
    expected_bytes = profile.tree_nodes_to_store * digest_len
    padding = proof[published * digest_len :]
    padding_ok = len(proof) == expected_bytes and all(byte == 0 for byte in padding)
    return root, padding_ok


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

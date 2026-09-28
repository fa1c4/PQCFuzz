#!/usr/bin/env python3
"""CROSS model tests: codec, challenge, tree, transcript, and reference diff."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tests.models import cross_model as model  # noqa: E402

PROFILES = model.load_profiles()
ALGORITHMS = sorted(PROFILES)


def test_profile_matrix_layout_and_skip_assert_note() -> None:
    assert len(PROFILES) == 18
    for profile in PROFILES.values():
        assert model.model_signature_len(profile) == profile.sig_len
        assert profile.seed_bytes in (16, 24, 32)
        assert profile.category in (1, 3, 5)
        assert profile.corner in ("FAST", "BALANCED", "SMALL")
        assert profile.t > profile.w
        assert profile.y_bytes == (profile.y_bits * profile.n + 7) // 8
        if profile.is_rsdpg:
            assert profile.v_bytes == (profile.v_bits * profile.m + 7) // 8
            assert profile.syn_bytes == (profile.s_bits * (profile.n - profile.k) + 7) // 8
        else:
            assert profile.v_bytes == (profile.v_bits * profile.n + 7) // 8


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_pack_unpack_roundtrip_and_canonicality(algorithm: str) -> None:
    profile = PROFILES[algorithm]
    coeffs = [(index * 5 + 1) % profile.p for index in range(profile.n)]
    packed = model.pack_vector(coeffs, profile.y_bits)
    assert model.unpack_vector(packed, profile.n, profile.y_bits, profile.p) == coeffs

    # Out-of-range wire coefficient must be rejected.
    bad = bytearray(packed)
    bad[-1] |= 0xFF
    with pytest.raises(model.CrossModelError):
        model.unpack_vector(bytes(bad), profile.n, profile.y_bits, profile.p)

    # Non-zero unused padding bit must be rejected.
    total_bits = profile.y_bits * profile.n
    padding = (8 - total_bits % 8) % 8
    if padding:
        padded = bytearray(model.pack_vector([0] * profile.n, profile.y_bits))
        padded[-1] |= 1 << (total_bits % 8)
        with pytest.raises(model.CrossModelError):
            model.unpack_vector(bytes(padded), profile.n, profile.y_bits, profile.p)
        # A decoder that ignores padding accepts it: that is the modelled bug.
        relaxed = model.unpack_vector(
            bytes(padded), profile.n, profile.y_bits, profile.p, check_padding=False
        )
        assert relaxed == [0] * profile.n

    v_coeffs = [(index * 3) % profile.z for index in range(profile.vector_count)]
    v_packed = model.pack_vector(v_coeffs, profile.v_bits)
    assert model.unpack_vector(v_packed, profile.vector_count, profile.v_bits, profile.z) == v_coeffs


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_fixed_weight_sampler_exact_weight(algorithm: str) -> None:
    profile = PROFILES[algorithm]
    digest = bytes((index * 11 + 7) % 256 for index in range(profile.digest_bytes))
    challenge = model.expand_fixed_weight(profile, digest)
    assert len(challenge) == profile.t
    assert set(challenge) <= {0, 1}
    assert sum(challenge) == profile.w


def test_sampler_rejection_refill_path() -> None:
    profile = PROFILES["CROSS-RSDPG-1-FAST"]
    # Force the refill branch by returning a stream whose first 8 bytes keep
    # generating out-of-range candidates for the smallest modulus.
    calls = 0

    def stream(length: int) -> bytes:
        nonlocal calls
        calls += 1
        return b"\xff" * length

    challenge = model.expand_fixed_weight(profile, bytes(profile.digest_bytes), stream=stream)
    assert sum(challenge) == profile.w
    assert calls == 1


def test_tree_publish_and_rebuild_toy() -> None:
    profile = PROFILES["CROSS-RSDP-1-FAST"]
    leaf_count = 8
    challenge = [1, 0, 1, 1, 0, 0, 1, 0]
    root = b"root-seed"
    salt = b"salt"
    tree = model.seed_tree_leaves(profile, root, salt, leaf_count)
    published = model.publish_seed_path(profile, tree, challenge, leaf_count)
    assert model.published_leaf_set(published, leaf_count) == {
        index for index, bit in enumerate(challenge) if bit == 0
    }
    rebuilt = model.rebuild_leaves(profile, tree, challenge, leaf_count, published)
    assert set(rebuilt) == {index for index, bit in enumerate(challenge) if bit == 1}
    level_order_offset = leaf_count - 1
    for index, seed in rebuilt.items():
        assert seed == tree[level_order_offset + index]


def test_tree_detects_disclosed_zero_branch_seed() -> None:
    profile = PROFILES["CROSS-RSDP-1-FAST"]
    leaf_count = 8
    challenge = [1, 0, 1, 1, 0, 0, 1, 0]
    tree = model.seed_tree_leaves(profile, b"root", b"salt", leaf_count)
    faulty = model.detach_seed_disclosure_mutant(tree, list(challenge), leaf_count)
    published = model.publish_seed_path(profile, tree, faulty, leaf_count)
    revealed = model.published_leaf_set(published, leaf_count)
    original_zero = {index for index, bit in enumerate(challenge) if bit == 0}
    assert revealed != original_zero


@pytest.mark.parametrize("algorithm", ["CROSS-RSDP-1-FAST", "CROSS-RSDPG-1-FAST"])
def test_transcript_sign_verify_and_mutations(algorithm: str) -> None:
    profile = PROFILES[algorithm]
    secret = bytes([0x5A] * profile.seed_bytes)
    public = model.model_public_seed(profile, secret)
    message = b"PQCFuzz model message"
    signature = model.model_sign(profile, secret, message, b"\x11" * profile.seed_bytes)
    assert len(signature) == profile.sig_len
    assert model.model_verify(profile, public, message, signature)

    # Each field mutation must break the transcript.
    salt_mutated = bytearray(signature)
    salt_mutated[0] ^= 1
    assert not model.model_verify(profile, public, message, bytes(salt_mutated))
    digest_mutated = bytearray(signature)
    digest_mutated[profile.salt_bytes] ^= 1
    assert not model.model_verify(profile, public, message, bytes(digest_mutated))
    assert not model.model_verify(profile, public, message + b"x", signature)
    assert not model.model_verify(profile, public, message, signature + b"\x00")
    assert not model.model_verify(profile, public, message, signature[:-1])


def test_mutant_catalogue_is_caught() -> None:
    for algorithm in ("CROSS-RSDP-1-FAST", "CROSS-RSDPG-1-FAST"):
        profile = PROFILES[algorithm]
        for mutant in model.MUTANTS:
            assert model.mutant_is_caught(profile, mutant), f"{algorithm}: {mutant}"


def test_mutation_recipe_golden_encoding() -> None:
    encoded = model.mutation_recipe("signature.digest_cmt")
    assert encoded.hex() == "0203000000000000000001"
    decoded = model.decode_mutation_recipe(bytes.fromhex("0203000000000000000001"))
    assert decoded == {"op": 2, "field": 3, "index": 0, "aux": 0, "payload": b"\x01"}
    # 32-bit index beyond 65535 round-trips.
    large = model.mutation_recipe("signature.proof", index=74589, aux=70000)
    decoded_large = model.decode_mutation_recipe(large)
    assert decoded_large["index"] == 74589
    assert decoded_large["aux"] == 70000
    with pytest.raises(model.CrossModelError):
        model.decode_mutation_recipe(b"\x02\x23" + bytes(8))


def _compile_reference_probe(tmp_path: Path, defines: list[str]) -> Path:
    include = REPO_ROOT / "projects" / "CROSS" / "reference" / "include"
    lib = REPO_ROOT / "projects" / "CROSS" / "reference" / "lib"
    obj_dir = tmp_path / "obj"
    obj_dir.mkdir(parents=True, exist_ok=True)
    objects = []
    for name in ("CROSS", "csprng_hash", "fips202", "keccakf1600", "merkle", "pack_unpack", "seedtree", "sign"):
        obj = obj_dir / f"{name}.o"
        subprocess.run(
            ["clang", "-std=c11", "-O1", "-g", "-DSKIP_ASSERT", f"-I{include}", *defines, "-c", str(lib / f"{name}.c"), "-o", str(obj)],
            check=True,
            cwd=REPO_ROOT,
        )
        objects.append(str(obj))
    main = tmp_path / "probe.cc"
    main.write_text(
        textwrap.dedent(
            """
            #include <cstdio>
            #include <cstdlib>
            #include <cstring>
            #include <string>
            #include <vector>
            #include "adapters/cross/cross_test_hooks.h"
            #include "parameters.h"
            extern "C" {
            #include "merkle_tree.h"
            #include "seedtree.h"
            }

            static int hexval(char c) {
              if (c >= '0' && c <= '9') return c - '0';
              if (c >= 'a' && c <= 'f') return c - 'a' + 10;
              if (c >= 'A' && c <= 'F') return c - 'A' + 10;
              return -1;
            }

            static std::vector<uint8_t> from_hex(const std::string &hex) {
              std::vector<uint8_t> out;
              for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                out.push_back(static_cast<uint8_t>((hexval(hex[i]) << 4) | hexval(hex[i + 1])));
              }
              return out;
            }

            static void to_hex(const uint8_t *data, size_t size) {
              static const char *digits = "0123456789abcdef";
              for (size_t i = 0; i < size; ++i) {
                putchar(digits[data[i] >> 4]);
                putchar(digits[data[i] & 0xF]);
              }
              putchar('\\n');
            }

            int main(int argc, char **argv) {
              if (argc < 2) return 2;
              const std::string mode = argv[1];
              if (mode == "expand") {
                if (argc < 3) return 2;
                std::vector<uint8_t> digest = from_hex(argv[2]);
                std::vector<uint8_t> out(pqcfuzz::CrossHookT());
                size_t produced = pqcfuzz::CrossHookExpandFixedWeight(out.data(), out.size(), digest.data(), digest.size());
                if (produced == 0) return 3;
                for (size_t i = 0; i < produced; ++i) putchar(out[i] ? '1' : '0');
                putchar('\\n');
                return 0;
              }
              if (mode == "layout") {
                const int off[LOG2(T)+1] = TREE_OFFSETS;
                const int npl[LOG2(T)+1] = TREE_NODES_PER_LEVEL;
                const int lpl[LOG2(T)+1] = TREE_LEAVES_PER_LEVEL;
                const int starts[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;
                const int cons[TREE_SUBROOTS] = TREE_CONSECUTIVE_LEAVES;
                for (int i = 0; i <= LOG2(T); ++i) printf("%d%s", off[i], i == LOG2(T) ? ";" : ",");
                for (int i = 0; i <= LOG2(T); ++i) printf("%d%s", npl[i], i == LOG2(T) ? ";" : ",");
                for (int i = 0; i <= LOG2(T); ++i) printf("%d%s", lpl[i], i == LOG2(T) ? ";" : ",");
                for (int i = 0; i < TREE_SUBROOTS; ++i) printf("%d%s", starts[i], i + 1 == TREE_SUBROOTS ? ";" : ",");
                for (int i = 0; i < TREE_SUBROOTS; ++i) printf("%d%s", cons[i], i + 1 == TREE_SUBROOTS ? "\\n" : ",");
                return 0;
              }
              if (mode == "seedtree" || mode == "path" || mode == "rebuild") {
                std::vector<uint8_t> root = from_hex(argv[2]);
                std::vector<uint8_t> salt = from_hex(argv[3]);
                static uint8_t seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES];
                gen_seed_tree(seed_tree, root.data(), salt.data());
                if (mode == "seedtree") { to_hex(seed_tree, sizeof(seed_tree)); return 0; }
                uint8_t chall[T] = {0};
                const std::string bits = argv[4];
                for (int i = 0; i < T && i < (int)bits.size(); ++i) chall[i] = bits[i] == '1' ? 1 : 0;
                if (mode == "path") {
                  static uint8_t storage[TREE_NODES_TO_STORE * SEED_LENGTH_BYTES];
                  std::memset(storage, 0, sizeof(storage));
                  int published = seed_path(storage, seed_tree, chall);
                  printf("%d\\n", published);
                  to_hex(storage, sizeof(storage));
                  return 0;
                }
                std::vector<uint8_t> stored = from_hex(argv[5]);
                static uint8_t rebuilt[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES];
                uint8_t ok = rebuild_tree(rebuilt, chall, stored.data(), salt.data());
                printf("%d\\n", ok);
                to_hex(rebuilt, sizeof(rebuilt));
                return 0;
              }
              if (mode == "root" || mode == "proof" || mode == "recompute") {
                std::vector<uint8_t> leaves_bytes = from_hex(argv[2]);
                if (leaves_bytes.size() != (size_t)T * HASH_DIGEST_LENGTH) return 5;
                static uint8_t leaves[T][HASH_DIGEST_LENGTH];
                std::memcpy(leaves, leaves_bytes.data(), leaves_bytes.size());
                static uint8_t merkle_tree[NUM_NODES_MERKLE_TREE * HASH_DIGEST_LENGTH];
                uint8_t root[HASH_DIGEST_LENGTH];
                tree_root(root, merkle_tree, leaves);
                if (mode == "root") { to_hex(root, sizeof(root)); return 0; }
                uint8_t chall[T] = {0};
                const std::string bits = argv[3];
                for (int i = 0; i < T && i < (int)bits.size(); ++i) chall[i] = bits[i] == '1' ? 1 : 0;
                if (mode == "proof") {
                  static uint8_t mtp[TREE_NODES_TO_STORE * HASH_DIGEST_LENGTH];
                  std::memset(mtp, 0, sizeof(mtp));
                  uint16_t published = tree_proof(mtp, merkle_tree, chall);
                  printf("%d\\n", (int)published);
                  to_hex(mtp, sizeof(mtp));
                  return 0;
                }
                std::vector<uint8_t> proof = from_hex(argv[4]);
                uint8_t root2[HASH_DIGEST_LENGTH];
                uint8_t ok = recompute_root(root2, leaves, proof.data(), chall);
                printf("%d\\n", ok);
                to_hex(root2, sizeof(root2));
                return 0;
              }
              const int count = atoi(argv[2]);
              std::vector<uint8_t> packed = from_hex(argv[3]);
              std::vector<uint16_t> coeffs(static_cast<size_t>(count));
              int unpacked = 0;
              if (mode == "y") {
                unpacked = pqcfuzz::CrossHookUnpackY(coeffs.data(), coeffs.size(), packed.data(), packed.size());
              } else if (mode == "v") {
                unpacked = pqcfuzz::CrossHookUnpackV(coeffs.data(), coeffs.size(), packed.data(), packed.size());
              } else if (mode == "s") {
                unpacked = pqcfuzz::CrossHookUnpackSyndrome(coeffs.data(), coeffs.size(), packed.data(), packed.size());
              } else {
                return 4;
              }
              printf("%d\\n", unpacked);
              for (size_t i = 0; i < coeffs.size(); ++i) printf("%u%s", coeffs[i], i + 1 == coeffs.size() ? "\\n" : ",");
              std::vector<uint8_t> repacked(packed.size());
              if (mode == "y") {
                pqcfuzz::CrossHookPackY(repacked.data(), repacked.size(), coeffs.data(), coeffs.size());
              } else if (mode == "v") {
                pqcfuzz::CrossHookPackV(repacked.data(), repacked.size(), coeffs.data(), coeffs.size());
              } else {
                pqcfuzz::CrossHookPackSyndrome(repacked.data(), repacked.size(), coeffs.data(), coeffs.size());
              }
              to_hex(repacked.data(), repacked.size());
              return 0;
            }
            """
        ),
        encoding="utf-8",
    )
    binary = tmp_path / "probe"
    hooks = tmp_path / "cross_test_hooks.o"
    subprocess.run(
        [
            "clang++",
            "-std=c++17",
            "-O1",
            "-g",
            f"-I{REPO_ROOT / 'src'}",
            f"-I{include}",
            *defines,
            "-DPQCFUZZ_HAVE_CROSS",
            "-c",
            str(REPO_ROOT / "src" / "adapters" / "cross" / "cross_test_hooks.cc"),
            "-o",
            str(hooks),
        ],
        check=True,
        cwd=REPO_ROOT,
    )
    link = subprocess.run(
        [
            "clang++",
            "-std=c++17",
            "-O1",
            "-g",
            f"-I{REPO_ROOT / 'src'}",
            f"-I{include}",
            *defines,
            "-DPQCFUZZ_HAVE_CROSS",
            str(main),
            str(hooks),
            *objects,
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    if link.returncode != 0:
        raise RuntimeError(f"probe link failed:\n{link.stderr}")
    return binary


@pytest.mark.parametrize(
    "algorithm,defines",
    [
        ("CROSS-RSDP-1-FAST", ["-DRSDP", "-DCATEGORY_1", "-DSPEED"]),
        ("CROSS-RSDPG-1-FAST", ["-DRSDPG", "-DCATEGORY_1", "-DSPEED"]),
    ],
)
def test_reference_differential_codec_and_challenge(
    tmp_path: Path, algorithm: str, defines: list[str]
) -> None:
    profile = PROFILES[algorithm]
    binary = _compile_reference_probe(tmp_path, defines)

    y_coeffs = [(index * 7 + 3) % profile.p for index in range(profile.n)]
    y_packed = model.pack_vector(y_coeffs, profile.y_bits)
    probe = subprocess.run(
        [str(binary), "y", str(profile.n), y_packed.hex()],
        check=True,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    lines = probe.stdout.strip().splitlines()
    assert lines[0] == "1"
    assert [int(value) for value in lines[1].split(",")] == y_coeffs
    assert lines[2] == y_packed.hex()

    v_coeffs = [(index * 3 + 1) % profile.z for index in range(profile.vector_count)]
    v_packed = model.pack_vector(v_coeffs, profile.v_bits)
    probe = subprocess.run(
        [str(binary), "v", str(profile.vector_count), v_packed.hex()],
        check=True,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    lines = probe.stdout.strip().splitlines()
    assert lines[0] == "1"
    assert [int(value) for value in lines[1].split(",")] == v_coeffs
    assert lines[2] == v_packed.hex()

    # Random coefficients are not all in range; the reference unpack must reject
    # the same out-of-range encoding the model rejects.
    bad = bytearray(y_packed)
    bad[-1] |= 0xFF
    probe_bad = subprocess.run(
        [str(binary), "y", str(profile.n), bytes(bad).hex()],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert probe_bad.stdout.strip().splitlines()[0] == "0"

    digest = bytes(range(profile.digest_bytes))
    challenge = model.expand_fixed_weight(profile, digest)
    probe_challenge = subprocess.run(
        [str(binary), "expand", digest.hex()],
        check=True,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert probe_challenge.stdout.strip() == "".join(str(bit) for bit in challenge)


def _cross_defines(profile: model.Profile) -> list[str]:
    variant = "-DRSDP" if profile.variant == "RSDP" else "-DRSDPG"
    category = f"-DCATEGORY_{profile.category}"
    corner = {"FAST": "-DSPEED", "BALANCED": "-DBALANCED", "SMALL": "-DSIG_SIZE"}[profile.corner]
    return [variant, category, corner]


def _run_probe(binary: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), *args],
        check=check,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


@pytest.mark.parametrize("algorithm", sorted(PROFILES))
def test_reference_differential_seed_and_merkle_trees(tmp_path: Path, algorithm: str) -> None:
    profile = PROFILES[algorithm]
    binary = _compile_reference_probe(tmp_path, _cross_defines(profile))
    layout = model.tree_layout(profile.t)

    layout_out = _run_probe(binary, "layout").stdout.strip()
    offsets, nodes_per_level, leaves_per_level, starts, cons = layout_out.split(";")
    assert [int(value) for value in offsets.split(",") if value] == layout.offsets
    assert [int(value) for value in nodes_per_level.split(",")] == layout.nodes_per_level
    assert [int(value) for value in leaves_per_level.split(",")] == layout.leaves_per_level
    assert [int(value) for value in starts.split(",")] == layout.start_indices
    assert [int(value) for value in cons.split(",")] == layout.consecutive_leaves

    root_seed = bytes((index * 7 + 1) & 0xFF for index in range(profile.seed_bytes))
    salt = bytes((index * 13 + 5) & 0xFF for index in range(profile.salt_bytes))
    tree = model.gen_seed_tree(profile, root_seed, salt, layout)
    assert _run_probe(binary, "seedtree", root_seed.hex(), salt.hex()).stdout.strip() == tree.hex()

    digest = bytes((index * 11 + 3) & 0xFF for index in range(profile.digest_bytes))
    challenge = model.expand_fixed_weight(profile, digest)
    bits = "".join(str(bit) for bit in challenge)
    path, count = model.seed_path(profile, tree, challenge, layout)
    padded_path = path + bytes(profile.tree_nodes_to_store * profile.seed_bytes - len(path))
    path_out = _run_probe(binary, "path", root_seed.hex(), salt.hex(), bits).stdout.splitlines()
    assert int(path_out[0]) == count
    assert path_out[1].strip() == padded_path.hex()

    rebuilt, padding_ok = model.rebuild_tree(profile, challenge, padded_path, salt, layout)
    rebuild_out = _run_probe(binary, "rebuild", root_seed.hex(), salt.hex(), bits, padded_path.hex()).stdout.splitlines()
    assert rebuild_out[0].strip() == ("1" if padding_ok else "0")
    assert rebuild_out[1].strip() == rebuilt.hex()

    leaves = [
        model.shake_stream(profile, [bytes([index & 0xFF]), b"cmt"], profile.digest_bytes)
        for index in range(profile.t)
    ]
    leaves_hex = b"".join(leaves).hex()
    root_digest, tree_nodes = model.merkle_tree_root(profile, leaves, layout)
    assert _run_probe(binary, "root", leaves_hex).stdout.strip() == root_digest.hex()

    proof, published = model.merkle_tree_proof(profile, tree_nodes, challenge, layout)
    padded_proof = proof + bytes(profile.tree_nodes_to_store * profile.digest_bytes - len(proof))
    proof_out = _run_probe(binary, "proof", leaves_hex, bits).stdout.splitlines()
    assert int(proof_out[0]) == published
    assert proof_out[1].strip() == padded_proof.hex()

    recomputed, recompute_ok = model.recompute_merkle_root(profile, leaves, padded_proof, challenge, layout)
    recompute_out = _run_probe(binary, "recompute", leaves_hex, bits, padded_proof.hex()).stdout.splitlines()
    assert recompute_out[0].strip() == ("1" if recompute_ok else "0")
    assert recompute_out[1].strip() == recomputed.hex()

    # A tampered tree path must not rebuild the honest leaves for one-challenge
    # rounds, and the padding check must reject a nonzero tail.
    tampered = bytearray(padded_path)
    tampered[0] ^= 0x01
    tampered_out = _run_probe(binary, "rebuild", root_seed.hex(), salt.hex(), bits, bytes(tampered).hex()).stdout.splitlines()
    assert tampered_out[1].strip() != rebuilt.hex()
    nonzero_tail = bytearray(padded_proof)
    nonzero_tail[-1] = 0x01
    assert _run_probe(binary, "recompute", leaves_hex, bits, bytes(nonzero_tail).hex()).stdout.splitlines()[0].strip() == "0"


@pytest.mark.parametrize("algorithm", sorted(PROFILES))
def test_real_tree_published_leaf_set_property(algorithm: str) -> None:
    profile = PROFILES[algorithm]
    layout = model.tree_layout(profile.t)
    root_seed = bytes((index * 5 + 9) & 0xFF for index in range(profile.seed_bytes))
    salt = bytes((index * 3 + 7) & 0xFF for index in range(profile.salt_bytes))
    tree = model.gen_seed_tree(profile, root_seed, salt, layout)
    honest_leaves = model.seed_leaves(profile, tree, layout)

    digest = bytes((index * 17 + 1) & 0xFF for index in range(profile.digest_bytes))
    challenge = model.expand_fixed_weight(profile, digest)
    path, count = model.seed_path(profile, tree, challenge, layout)
    assert count <= profile.tree_nodes_to_store
    stored = path + bytes(profile.tree_nodes_to_store * profile.seed_bytes - len(path))
    rebuilt, padding_ok = model.rebuild_tree(profile, challenge, stored, salt, layout)
    assert padding_ok
    rebuilt_leaves = model.seed_leaves(profile, rebuilt, layout)

    # One-challenge rounds must be rebuilt exactly; zero-challenge round seeds
    # are hidden and must never be recoverable from the published path.
    for index, bit in enumerate(challenge):
        if bit == 1:
            assert rebuilt_leaves[index] == honest_leaves[index]
        else:
            assert rebuilt_leaves[index] != honest_leaves[index]

    # A path that discloses a zero-challenge leaf seed is detected: replacing a
    # published node with a hidden leaf seed changes the rebuilt one-challenge
    # leaves (the padding/rebuild contract rejects the forged set).
    forged = bytearray(stored)
    hidden_index = next(index for index, bit in enumerate(challenge) if bit == 0)
    forged[0 : profile.seed_bytes] = honest_leaves[hidden_index]
    forged_rebuilt, forged_ok = model.rebuild_tree(profile, challenge, bytes(forged), salt, layout)
    forged_leaves = model.seed_leaves(profile, forged_rebuilt, layout)
    assert not forged_ok or forged_leaves != rebuilt_leaves

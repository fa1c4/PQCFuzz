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
              if (argc < 3) return 2;
              const std::string mode = argv[1];
              if (mode == "expand") {
                std::vector<uint8_t> digest = from_hex(argv[2]);
                std::vector<uint8_t> out(pqcfuzz::CrossHookT());
                size_t produced = pqcfuzz::CrossHookExpandFixedWeight(out.data(), out.size(), digest.data(), digest.size());
                if (produced == 0) return 3;
                for (size_t i = 0; i < produced; ++i) putchar(out[i] ? '1' : '0');
                putchar('\\n');
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

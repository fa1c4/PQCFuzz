"""Independent Falcon model-lane tests.

Pure-Python model tests plus differential probes against the pinned
Falcon-impl-20211101 reference through tests/falcon_hook_cli.cc.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(REPO_ROOT / "tests" / "models"))

import _falcon_util as util  # noqa: E402
import falcon_model as fm  # noqa: E402


PROFILES = fm.load_profiles()


@pytest.fixture(scope="module")
def hook_cli(tmp_path_factory):
    return util.compile_hook_cli(tmp_path_factory.mktemp("falcon-model"))


def run_cli(cli: Path, *args: str) -> str:
    result = subprocess.run([str(cli), *args], cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def parse_int_list(text: str) -> list[int]:
    return [int(item) for item in text.split(",") if item != ""]


def sign_with_reference(cli: Path, profile: fm.FalconProfile, seed: bytes, message: bytes):
    pk, sk = keygen_with_reference(cli, profile.logn, seed)
    signature = bytes.fromhex(run_cli(cli, "sign", seed.hex(), str(profile.logn), profile.format, message.hex(), sk.hex()))
    return pk, sk, signature


def keygen_with_reference(cli: Path, logn: int, seed: bytes):
    output = run_cli(cli, "keygen", seed.hex(), str(logn)).splitlines()
    pk = bytes.fromhex(output[0].split()[1])
    sk = bytes.fromhex(output[1].split()[1])
    return pk, sk


def reference_verify(cli: Path, profile: fm.FalconProfile, pk: bytes, message: bytes, signature: bytes) -> bool:
    # Padded signatures are verified with the pinned padded type; the compressed
    # profile uses the exact compressed type here because the hook exposes the
    # explicit format.
    return run_cli(cli, "verify", profile.format, pk.hex(), message.hex(), signature.hex()) == "ACCEPT"


def make_mutant_signature(case: str, pk: bytes, signature: bytes) -> bytes:
    """Craft a signature/input that separates the model from one faulty mutant."""
    profile = PROFILES["FALCON-512-COMPRESSED"]
    header = signature[0:1]
    salt = signature[1 : 1 + profile.salt_len]
    payload = signature[profile.sig_payload_off :]
    coefficients, _ = fm.decode_compressed(payload, profile.n)
    if case == "ignore_norm":
        for index in range(32):
            coefficients[index] = 2047
        return header + salt + fm.encode_compressed(coefficients)
    if case == "accept_negative_zero":
        metadata = fm.compressed_metadata(payload, profile.n)
        zero_index = next((i for i, value in enumerate(coefficients) if value == 0), None)
        if zero_index is None:
            raise AssertionError("no zero coefficient available")
        byte, bit = metadata["sign_offsets"][zero_index]
        mutated = bytearray(payload)
        mutated[byte] |= 1 << bit
        return header + salt + bytes(mutated)
    if case == "ignore_padding_bits":
        metadata = fm.compressed_metadata(payload, profile.n)
        assert metadata["trailing_bits"] > 0
        mutated = bytearray(payload)
        mutated[metadata["consumed"] - 1] |= 1
        return header + salt + bytes(mutated)
    if case == "little_endian_hash_to_point" or case == "sig_max_len_exact" or case == "always_true":
        return signature
    raise KeyError(case)


def test_profile_matrix():
    assert set(PROFILES) == {
        "FALCON-512-COMPRESSED",
        "FALCON-1024-COMPRESSED",
        "FALCON-512-PADDED",
        "FALCON-1024-PADDED",
        "FALCON-512-CT",
        "FALCON-1024-CT",
    }
    for profile in PROFILES.values():
        assert profile.q == 12289
        assert profile.salt_len == 40
        assert profile.pk_len == 1 + (profile.n * 14 + 7) // 8
        assert profile.sk_len == 1 + 2 * ((profile.n * profile.fg_bits + 7) // 8) + profile.n
        assert profile.sig_payload_off == 41
        if profile.format == "ct":
            assert profile.sig_max_len == 41 + (profile.n * 12 + 7) // 8
            assert profile.ct_header == 0x50 + profile.logn
        else:
            assert profile.sig_header == 0x30 + profile.logn
            assert profile.padded_len == (666 if profile.n == 512 else 1280)


@pytest.mark.parametrize("logn", [9, 10])
def test_compressed_codec_roundtrip(logn):
    n = 1 << logn
    rng = random.Random(1000 + logn)
    for _ in range(25):
        coefficients = [rng.randint(-50, 50) for _ in range(n)]
        payload = fm.encode_compressed(coefficients)
        decoded, consumed = fm.decode_compressed(payload, n)
        assert decoded == coefficients
        assert consumed == len(payload)


def test_compressed_codec_canonicality_rules():
    n = 512
    coefficients = [0] * n
    payload = bytearray(fm.encode_compressed(coefficients))
    metadata = fm.compressed_metadata(bytes(payload), n)
    byte, bit = metadata["sign_offsets"][0]
    payload[byte] |= 1 << bit
    with pytest.raises(fm.FalconModelError, match="negative zero"):
        fm.decode_compressed(bytes(payload), n)

    payload = bytearray(fm.encode_compressed([1] * n))
    metadata = fm.compressed_metadata(bytes(payload), n)
    term_byte, term_bit = metadata["term_offsets"][n - 1]
    payload[term_byte] &= ~(1 << term_bit)
    with pytest.raises(fm.FalconModelError):
        fm.decode_compressed(bytes(payload), n)

    payload = bytearray(fm.encode_compressed([1] * (n - 1) + [128]))
    metadata = fm.compressed_metadata(bytes(payload), n)
    assert metadata["trailing_bits"] > 0
    payload[metadata["consumed"] - 1] |= 1
    with pytest.raises(fm.FalconModelError, match="trailing bits"):
        fm.decode_compressed(bytes(payload), n)

    with pytest.raises(fm.FalconModelError, match="limit"):
        fm.encode_compressed([2048] * n)


def test_codec_differential_with_reference(hook_cli):
    rng = random.Random(7)
    for logn in (9, 10):
        n = 1 << logn
        for _ in range(4):
            # Keep the vector inside the compressed capacity (values below 128
            # encode in 9 bits per coefficient).
            coefficients = [rng.randint(-60, 60) for _ in range(n)]
            reference = run_cli(hook_cli, "compencode", str(logn), ",".join(str(value) for value in coefficients))
            model = fm.encode_compressed(coefficients)
            assert bytes.fromhex(reference) == model
            decoded_text = run_cli(hook_cli, "compdecode", reference, str(logn))
            consumed_field, values = decoded_text.split(" ", 1)
            assert int(consumed_field.split("=")[1]) == len(model)
            reference_coefficients = parse_int_list(values)
            decoded, _ = fm.decode_compressed(model, n)
            assert reference_coefficients == decoded


def test_hash_to_point_boundaries_and_differential(hook_cli):
    # Forced-sample filter: 61444 is kept, 61445 and 65535 are dropped.
    forced = bytearray()
    for t in (61444, 61445, 65535, 0, 12288):
        forced.extend([t >> 8, t & 0xFF])
    stream = lambda _count: bytes(forced) + b"\x00" * 8192
    coefficients = fm.hash_to_point_rejection(stream, 3)
    assert coefficients[:3] == [61444 % fm.Q, 0, 12288 % fm.Q]

    rng = random.Random(11)
    for logn in (9, 10):
        for _ in range(3):
            salt = bytes(rng.randrange(256) for _ in range(40))
            message = bytes(rng.randrange(256) for _ in range(17))
            reference = [
                int(item, 16)
                for item in run_cli(hook_cli, "hash", salt.hex(), message.hex(), str(logn)).split(",")
            ]
            assert reference == fm.hash_to_point(salt, message, 1 << logn)


def test_key_equation_and_public_relation(hook_cli):
    for logn in (9, 10):
        seed = bytes((logn + i) & 0xFF for i in range(48))
        output = run_cli(hook_cli, "keygen", seed.hex(), str(logn)).splitlines()
        pk = bytes.fromhex(output[0].split()[1])
        fields = {line.split(" ", 1)[0]: parse_int_list(line.split(" ", 1)[1]) for line in output[2:]}
        f, g, F, G = fields["F"], fields["G"], fields["FBIG"], fields["GBIG"]
        assert fm.model_key_equation(f, g, F, G)
        h = fm.decode_pk(pk[1:], 1 << logn)
        assert fm.model_public_key_relation(f, g, h)
        # Perturbing F must break the equation.
        broken = list(G)
        broken[0] = (broken[0] + 1) % 128
        assert not fm.model_key_equation(f, g, F, broken)


@pytest.mark.parametrize(
    "algorithm",
    ["FALCON-512-COMPRESSED", "FALCON-512-PADDED", "FALCON-512-CT", "FALCON-1024-COMPRESSED"],
)
def test_model_verify_matches_reference(hook_cli, algorithm):
    profile = PROFILES[algorithm]
    seed = bytes((i * 7 + profile.logn) & 0xFF for i in range(48))
    message = b"PQCFuzz Falcon model lane"
    pk, _, signature = sign_with_reference(hook_cli, profile, seed, message)
    assert reference_verify(hook_cli, profile, pk, message, signature)

    result = fm.model_verify(profile, pk, message, signature)
    assert result.accepted, result.reason
    assert result.codec_ok
    assert result.norm <= profile.norm_bound

    wrong_message = fm.model_verify(profile, pk, message + b"x", signature)
    assert not wrong_message.accepted
    assert not reference_verify(hook_cli, profile, pk, message + b"x", signature)

    mutated = bytearray(signature)
    mutated[-1] ^= 0x01
    mutated_result = fm.model_verify(profile, pk, message, bytes(mutated))
    reference_mutated = reference_verify(hook_cli, profile, pk, message, bytes(mutated))
    if profile.format == "ct":
        # A coefficient change is codec-valid in CT; both must agree.
        assert mutated_result.accepted == reference_mutated
    else:
        assert mutated_result.codec_ok == reference_mutated


def test_multiple_valid_compressed_lengths(hook_cli):
    profile = PROFILES["FALCON-512-COMPRESSED"]
    message = b"length diversity"
    lengths = set()
    for index in range(6):
        seed = bytes((index * 31 + i * 5) & 0xFF for i in range(48))
        pk, _, signature = sign_with_reference(hook_cli, profile, seed, message)
        assert fm.model_verify(profile, pk, message, signature).accepted
        lengths.add(len(signature))
    assert len(lengths) >= 2, "expected at least two distinct legal compressed lengths"


def test_padded_full_conversion_and_padded_codec(hook_cli):
    profile = PROFILES["FALCON-512-COMPRESSED"]
    seed = bytes((i * 13 + 3) & 0xFF for i in range(48))
    message = b"padding"
    pk, _, signature = sign_with_reference(hook_cli, profile, seed, message)
    padded = signature + b"\x00" * (profile.padded_len - len(signature))
    assert fm.model_verify(profile, pk, message, padded).accepted

    partial = padded[:-1]
    assert not fm.model_verify(profile, pk, message, partial).accepted

    non_zero = padded[:-1] + b"\x01"
    assert not fm.model_verify(profile, pk, message, non_zero).accepted

    padded_profile = PROFILES["FALCON-512-PADDED"]
    pk2, _, padded_signature = sign_with_reference(hook_cli, padded_profile, seed, message)
    assert len(padded_signature) == padded_profile.padded_len
    assert fm.model_verify(padded_profile, pk2, message, padded_signature).accepted


def test_ct_codec_roundtrip():
    n = 512
    rng = random.Random(21)
    coefficients = [rng.randint(-2047, 2047) for _ in range(n)]
    payload = fm.encode_ct(coefficients)
    decoded, consumed = fm.decode_ct(payload, n)
    assert decoded == coefficients
    assert consumed == (n * 12 + 7) // 8

    forbidden = list(payload)
    # Write 0x800 into the first 12-bit coefficient (MSB first).
    for i in range(12):
        byte = i // 8
        bit = 7 - (i % 8)
        if (0x800 >> (11 - i)) & 1:
            forbidden[byte] |= 1 << bit
        else:
            forbidden[byte] &= ~(1 << bit)
    with pytest.raises(fm.FalconModelError, match="minimum negative"):
        fm.decode_ct(bytes(forbidden), n)


def test_secret_key_codec_negatives(hook_cli):
    profile = PROFILES["FALCON-512-COMPRESSED"]
    seed = bytes(range(48))
    _, sk = keygen_with_reference(hook_cli, 9, seed)
    fm.decode_sk(sk, profile)

    bad_header = bytearray(sk)
    bad_header[0] ^= 0x01
    with pytest.raises(fm.FalconModelError, match="header"):
        fm.decode_sk(bytes(bad_header), profile)

    short = sk[:-1]
    with pytest.raises(fm.FalconModelError):
        fm.decode_sk(short, profile)


def test_norm_predicate_boundary_unit():
    for algorithm, bound in (("FALCON-512-COMPRESSED", 34034726), ("FALCON-1024-COMPRESSED", 70265242)):
        assert fm.norm_predicate(bound, bound)
        assert not fm.norm_predicate(bound + 1, bound)
        assert fm.norm_predicate(bound - 1, bound)
        # A worst-case 64-bit-scale sum must not wrap in Python.
        worst_case = 512 * (2047 * 2047 + 6144 * 6144)
        assert fm.norm_predicate(worst_case, 2**63) and not fm.norm_predicate(worst_case, bound)


def test_mutant_catalogue(hook_cli):
    profile = PROFILES["FALCON-512-COMPRESSED"]
    seed = bytes((i * 3 + 9) & 0xFF for i in range(48))
    message = b"mutant catalogue"
    pk, _, signature = sign_with_reference(hook_cli, profile, seed, message)
    assert fm.model_verify(profile, pk, message, signature).accepted

    # ignore_norm: codec-valid but norm-breaking coefficients.
    norm_case = make_mutant_signature("ignore_norm", pk, signature)
    model_result = fm.model_verify(profile, pk, message, norm_case).accepted
    mutant_result = fm.MUTANTS["ignore_norm"](profile, pk, message, norm_case)
    assert not model_result and mutant_result

    # accept_negative_zero.
    negative_zero = make_mutant_signature("accept_negative_zero", pk, signature)
    model_result = fm.model_verify(profile, pk, message, negative_zero).accepted
    mutant_result = fm.MUTANTS["accept_negative_zero"](profile, pk, message, negative_zero)
    assert not model_result and mutant_result

    # ignore_padding_bits.
    padding_case = make_mutant_signature("ignore_padding_bits", pk, signature)
    model_result = fm.model_verify(profile, pk, message, padding_case).accepted
    mutant_result = fm.MUTANTS["ignore_padding_bits"](profile, pk, message, padding_case)
    assert not model_result and mutant_result

    # little_endian_hash_to_point diverges from the specification HashToPoint.
    le_matches = fm.hash_to_point(bytes(40), b"x", 512) == fm.hash_to_point_little_endian(bytes(40), b"x", 512)
    assert not le_matches

    # pk_mod_q_reduce: a pk coefficient equal to q must be rejected by the model.
    crafted = bytearray(pk)
    bits = 14
    for i in range(bits):
        byte = 1 + (i >> 3)
        bit = 7 - (i & 7)
        value = (fm.Q >> (bits - 1 - i)) & 1
        if value:
            crafted[byte] |= 1 << bit
        else:
            crafted[byte] &= ~(1 << bit)
    assert not fm.model_verify(profile, bytes(crafted), message, signature).codec_ok
    assert fm.decode_pk(bytes(crafted)[1:], profile.n, reduce_mod_q=True)[0] == 0

    # sig_max_len_exact rejects a legal shorter compressed signature.
    assert len(signature) < profile.sig_max_len
    assert fm.model_verify(profile, pk, message, signature).accepted
    assert not fm.MUTANTS["sig_max_len_exact"](profile, pk, message, signature)

    # always_true accepts a signature on a different message.
    tampered = fm.model_verify(profile, pk, b"other", signature)
    assert not tampered.accepted
    assert fm.MUTANTS["always_true"](profile, pk, b"other", signature)

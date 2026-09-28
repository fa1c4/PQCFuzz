#!/usr/bin/env python3
"""SNOVA model tests: GF16, codecs, expansion, key algebra, public map, Gauss.

Native differential lanes require the pinned round-2 source under
projects/SNOVA/reference and skip with an explicit reason when it is absent.
The pure-Python lanes always run.
"""

from __future__ import annotations

import dataclasses
import hashlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from tests.models import snova_model as model  # noqa: E402
from tests import _snova_util as util  # noqa: E402

PROFILES = model.load_profiles()
PROBE_SOURCE = REPO_ROOT / "tests" / "snova_probe.cc"

_PROBE_CACHE: dict = {}


def _probe(algorithm: str, sk_format: str = "ESK") -> Path:
    key = (algorithm, sk_format)
    if key not in _PROBE_CACHE:
        if not util.have_reference_source():
            pytest.skip(util.reference_skip_reason())
        tmp = REPO_ROOT / "workspace" / "snova" / "tests" / f"model-{algorithm}-{sk_format}".lower()
        _PROBE_CACHE[key] = util.compile_with_snova(tmp, algorithm, sk_format, PROBE_SOURCE)
    return _PROBE_CACHE[key]


# ---------------------------------------------------------------------------
# Pure Python lanes.
# ---------------------------------------------------------------------------
def test_profile_matrix_matches_lock() -> None:
    assert len(PROFILES) == 22
    for profile in PROFILES.values():
        assert profile.n_matrices == profile.v + profile.o
        assert profile.m_matrices == profile.o
        assert profile.sq_rank == profile.l * profile.l
        assert profile.alpha_terms == profile.sq_rank + profile.l
        assert profile.hash_nibbles == profile.m_matrices * profile.sq_rank
        assert profile.hash_bytes == (profile.hash_nibbles + 1) // 2
        assert profile.pk_len == 16 + (profile.m_matrices * profile.o * profile.o * profile.sq_rank + 1) // 2
        assert profile.sig_len == model.expected_signature_length(profile.v, profile.o, profile.l)
        assert profile.signature_data_bytes == profile.sig_len - 16
        assert profile.fixed_abq == (profile.l < 4)
        assert profile.esk_len > profile.ssk_len
        if profile.l <= 3:
            assert profile.fixed_abq


def test_gf16_multiplication_and_inverses() -> None:
    for a in range(16):
        for b in range(16):
            assert model.GF16_MUL_TABLE[a][b] == model.gf16_mul(a, b)
    # Multiplication is polynomial reduction, not integer multiplication.
    assert model.gf16_mul(2, 3) == 6
    assert model.integer_mod16_mul(2, 3) == 6
    assert any(
        model.gf16_mul(a, b) != model.integer_mod16_mul(a, b)
        for a in range(16)
        for b in range(16)
    )
    for a in range(1, 16):
        assert model.gf16_mul(a, model.gf16_inv(a)) == 1
    with pytest.raises(model.SnovaModelError):
        model.gf16_inv(0)


def test_nibble_codecs_roundtrip() -> None:
    for count in range(1, 120):
        values = [(index * 7 + 3) & 0xF for index in range(count)]
        packed = model.pack_nibbles(values)
        assert len(packed) == (count + 1) // 2
        assert model.unpack_nibbles(packed, count) == values
        if count % 2 == 1:
            assert packed[-1] >> 4 == 0, "odd nibble counts pad the high nibble with zero"
        cut = model.pack_nibbles_cut_in_half(values)
        assert model.unpack_nibbles_cut_in_half(cut, count) == values


def test_aes128_known_vector() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert model.aes128_encrypt_block(key, plaintext).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    # Zero-IV CTR keystream starts with the encryption of the all-zero block.
    stream = model.aes128_ctr_stream(key, 32)
    assert stream[:16] == model.aes128_encrypt_block(key, bytes(16))
    assert stream[16:32] == model.aes128_encrypt_block(key, (1).to_bytes(16, "big"))


def test_indexed_shake_matches_block_definition_and_chunking() -> None:
    seed = bytes(range(16))
    one_shot = model.snova_shake_stream(seed, 400)
    block0 = hashlib.shake_128(seed + (0).to_bytes(8, "little")).digest(168)
    block1 = hashlib.shake_128(seed + (1).to_bytes(8, "little")).digest(168)
    block2 = hashlib.shake_128(seed + (2).to_bytes(8, "little")).digest(168)
    assert one_shot == (block0 + block1 + block2)[:400]
    assert one_shot != model.continuous_shake128_stream(seed, 400)
    # Chunked calls and explicit seeks preserve the same bytes.
    assert one_shot[:168] == model.snova_shake_stream(seed, 168)
    assert one_shot[:169] == model.snova_shake_stream(seed, 169)
    assert one_shot[168:336] == block1


def test_fixed_abq_is_seed_independent_for_l_le_3() -> None:
    small = PROFILES["SNOVA-R2-37-17-16-2-AES"]
    fixed_a = model.gen_a_b_q_p(small, bytes([1]) * 16)
    fixed_b = model.gen_a_b_q_p(small, bytes([2]) * 16)
    assert fixed_a["A"] == fixed_b["A"]
    assert fixed_a["B"] == fixed_b["B"]
    assert fixed_a["Q1"] == fixed_b["Q1"]
    assert fixed_a["Q2"] == fixed_b["Q2"]
    for matrix in fixed_a["A"] + fixed_a["B"]:
        assert model.mat_det(matrix, small.l) != 0
    seed_dependent = PROFILES["SNOVA-R2-24-5-16-4-AES"]
    dep_a = model.gen_a_b_q_p(seed_dependent, bytes([1]) * 16)
    dep_b = model.gen_a_b_q_p(seed_dependent, bytes([2]) * 16)
    assert dep_a["A"] != dep_b["A"]


def test_signature_length_arithmetic_and_floor_mutant() -> None:
    for profile in PROFILES.values():
        expected = (profile.n_matrices * profile.sq_rank + 1) // 2 + 16
        assert expected == profile.sig_len
        if profile.n_matrices * profile.sq_rank % 2 == 1:
            assert model.expected_signature_length_floor(profile.v, profile.o, profile.l) == expected - 1


def test_target_hash_binding_mutants() -> None:
    profile = PROFILES["SNOVA-R2-24-5-16-4-AES"]
    seed = bytes(range(16))
    digest = model.message_digest(b"PQCFuzz SNOVA model")
    salt = bytes(range(16))
    baseline = model.target_hash(profile, seed, digest, salt)
    assert model.target_hash(profile, seed, digest, salt[:-1] + bytes([salt[-1] ^ 1])) != baseline
    assert model.target_hash(profile, seed + b"\x00", digest, salt) != baseline
    assert model.target_hash(profile, seed, digest[:-1] + bytes([digest[-1] ^ 1]), salt) != baseline


def test_gauss_fixtures_and_mutants() -> None:
    # Unique solution.
    unique = [[1, 2], [3, 1]]
    assert model.gauss_solve_gf16(unique, [1, 2]) is not None
    # Zero pivot requiring a row swap.
    swap = [[0, 1], [1, 0]]
    solution = model.gauss_solve_gf16(swap, [3, 4])
    assert solution == [4, 3]
    assert model.gauss_solve_without_row_swap(swap, [3, 4]) is None
    # Rank-deficient system (second row is a multiple of the first).
    singular = [[1, 1], [2, 2]]
    assert model.gauss_solve_gf16(singular, [1, 2]) is None
    # Inconsistent system (rhs not on the row image).
    assert model.gauss_solve_gf16(singular, [1, 0]) is None
    # Bounded retry: the first (singular) fixture is skipped and the next one solves.
    solution, attempts = model.gauss_retry_loop([(singular, [1, 0]), (unique, [1, 2])])
    assert solution is not None and attempts == 2
    no_solution, attempts = model.gauss_retry_loop([(singular, [1, 0])] * 3, max_attempts=2)
    assert no_solution is None and attempts == 2


def test_kat_fixture_sanity() -> None:
    fixture_path = REPO_ROOT / "tests" / "fixtures" / "snova" / "kat_reference.json"
    fixture = __import__("json").loads(fixture_path.read_text())
    records = fixture["records"]
    assert len(records) == 44
    by_key = {(entry["algorithm"], entry["sk_format"]): entry for entry in records}
    for entry in records:
        profile = PROFILES[entry["algorithm"]]
        pk = bytes.fromhex(entry["pk_hex"])
        sk = bytes.fromhex(entry["sk_hex"]) if "sk_hex" in entry else None
        sm = bytes.fromhex(entry["sm_hex"])
        assert len(pk) == profile.pk_len
        assert len(sm) == entry["smlen"] == profile.sig_len + entry["mlen"]
        if sk is not None:
            assert len(sk) == profile.ssk_len
        assert len(entry["rsp_sha256"]) == 64
    for algorithm in {entry["algorithm"] for entry in records}:
        ssk = by_key[(algorithm, "SSK")]
        esk = by_key[(algorithm, "ESK")]
        assert ssk["pk_hex"] == esk["pk_hex"]
        assert ssk["sm_hex"] == esk["sm_hex"]
        assert ssk["seed_hex"] == esk["seed_hex"]
        assert ssk["sk_sha256"] != esk["sk_sha256"]


# ---------------------------------------------------------------------------
# Native differential lanes.
# ---------------------------------------------------------------------------
def _settings(algorithm: str) -> tuple:
    return (
        PROFILES[algorithm],
        bytes(range(48)),
        bytes(range(16)),
        bytes(range(29)),
        b"PQCFuzz SNOVA model differential",
    )


@pytest.mark.parametrize("algorithm", ["SNOVA-R2-24-5-16-4-AES", "SNOVA-R2-24-5-16-4-SHAKE", "SNOVA-R2-25-8-16-3-AES"])
def test_native_keygen_matches_model(algorithm: str) -> None:
    profile, seed, _, _, _ = _settings(algorithm)
    binary = _probe(algorithm)
    lines = util.run_probe(binary, [f"KEYGEN {seed.hex()}"])
    parts = lines[0].split()
    assert parts[0] == "KEYGEN" and int(parts[1]) == 0
    pk = bytes.fromhex(parts[2])
    assert len(pk) == profile.pk_len
    assert model.model_public_key(profile, seed[:16], seed[16:]) == pk


@pytest.mark.parametrize("algorithm", ["SNOVA-R2-24-5-16-4-AES", "SNOVA-R2-25-8-16-3-SHAKE"])
def test_native_signature_matches_model_verification(algorithm: str) -> None:
    profile, seed, salt, _, message = _settings(algorithm)
    binary = _probe(algorithm)
    lines = util.run_probe(binary, [f"SIGN {seed.hex()} {message.hex()} {salt.hex()}"])
    parts = lines[0].split()
    assert parts[0] == "SIGN" and int(parts[1]) == 0
    pk = bytes.fromhex(parts[2])
    signature = bytes.fromhex(parts[3])
    assert len(signature) == profile.sig_len
    assert model.model_verify(profile, pk, message, signature)
    mutated_message = message[:-1] + bytes([message[-1] ^ 1])
    assert not model.model_verify(profile, pk, mutated_message, signature)


def test_native_model_map_agrees_on_mutations() -> None:
    algorithm = "SNOVA-R2-24-5-16-4-AES"
    profile, seed, salt, _, message = _settings(algorithm)
    binary = _probe(algorithm)
    parts = util.run_probe(binary, [f"SIGN {seed.hex()} {message.hex()} {salt.hex()}"])[0].split()
    assert parts[0] == "SIGN" and int(parts[1]) == 0
    pk = bytes.fromhex(parts[2])
    signature = bytes.fromhex(parts[3])
    assert model.model_verify(profile, pk, message, signature)

    # Mutate a nibble that changes the independent direct map; the target must reject.
    changed = False
    for index in range(8):
        mutated = bytearray(signature)
        byte_index = index // 2
        mutated[byte_index] ^= 0x0F if index % 2 == 1 else 0x01
        if bytes(mutated) == signature:
            continue
        if not model.model_verify(profile, pk, message, bytes(mutated)):
            lines = util.run_probe(binary, [f"VERIFY {pk.hex()} {message.hex()} {bytes(mutated).hex()}"])
            assert lines[0].split()[0] == "VERIFY" and lines[0].split()[1] == "0"
            changed = True
            break
    assert changed, "no U-nibble mutation changed the model verdict"

    # Mutants that must not reproduce the accepted target hash.
    seed_bytes, p22 = model.decode_public_key(profile, pk)
    u_matrices, decoded_salt = model.decode_signature(profile, signature)
    abq = model.gen_a_b_q_p(profile, seed_bytes)
    digest = model.message_digest(message)
    accepted = model.signature_padding_mask(profile, model.target_hash(profile, seed_bytes, digest, decoded_salt))
    p_blocks = model._assemble_p(profile, abq, p22)

    def drop_alpha_terms(profile_arg, blocks, abq_arg, u_arg):
        l = profile_arg.l
        m = profile_arg.m_matrices
        n = profile_arg.n_matrices
        out = [0] * (m * profile_arg.sq_rank)
        for mi in range(m):
            for alpha in range(profile_arg.sq_rank):  # wrong: drops the l extra terms
                mi_prime = (mi + alpha) % m
                a_block = abq_arg["A"][mi * profile_arg.alpha_terms + alpha]
                b_block = abq_arg["B"][mi * profile_arg.alpha_terms + alpha]
                q1 = abq_arg["Q1"][mi * profile_arg.alpha_terms + alpha]
                q2 = abq_arg["Q2"][mi * profile_arg.alpha_terms + alpha]
                for ni in range(n):
                    left = model.mat_mul(a_block, model.mat_mul(model.mat_transpose(u_arg[ni], l), q1, l), l)
                    total = model.zeros_matrix(l)
                    for nj in range(n):
                        right = model.mat_mul(model.mat_mul(q2, u_arg[nj], l), b_block, l)
                        total = model.mat_add(total, model.mat_mul(blocks[(mi_prime * n + ni) * n + nj], right, l))
                    out[mi * profile_arg.sq_rank : (mi + 1) * profile_arg.sq_rank] = model.mat_add(
                        out[mi * profile_arg.sq_rank : (mi + 1) * profile_arg.sq_rank], model.mat_mul(left, total, l)
                    )
        return model.pack_nibbles(out)

    def fixed_i_prime(profile_arg, blocks, abq_arg, u_arg):
        l = profile_arg.l
        m = profile_arg.m_matrices
        n = profile_arg.n_matrices
        out = [0] * (m * profile_arg.sq_rank)
        for mi in range(m):
            for alpha in range(profile_arg.alpha_terms):
                a_block = abq_arg["A"][mi * profile_arg.alpha_terms + alpha]
                b_block = abq_arg["B"][mi * profile_arg.alpha_terms + alpha]
                q1 = abq_arg["Q1"][mi * profile_arg.alpha_terms + alpha]
                q2 = abq_arg["Q2"][mi * profile_arg.alpha_terms + alpha]
                for ni in range(n):
                    left = model.mat_mul(a_block, model.mat_mul(model.mat_transpose(u_arg[ni], l), q1, l), l)
                    total = model.zeros_matrix(l)
                    for nj in range(n):
                        right = model.mat_mul(model.mat_mul(q2, u_arg[nj], l), b_block, l)
                        total = model.mat_add(total, model.mat_mul(blocks[(mi * n + ni) * n + nj], right, l))
                    out[mi * profile_arg.sq_rank : (mi + 1) * profile_arg.sq_rank] = model.mat_add(
                        out[mi * profile_arg.sq_rank : (mi + 1) * profile_arg.sq_rank], model.mat_mul(left, total, l)
                    )
        return model.pack_nibbles(out)

    def missing_transpose(profile_arg, blocks, abq_arg, u_arg):
        l = profile_arg.l
        m = profile_arg.m_matrices
        n = profile_arg.n_matrices
        out = [0] * (m * profile_arg.sq_rank)
        for mi in range(m):
            for alpha in range(profile_arg.alpha_terms):
                mi_prime = (mi + alpha) % m
                a_block = abq_arg["A"][mi * profile_arg.alpha_terms + alpha]
                b_block = abq_arg["B"][mi * profile_arg.alpha_terms + alpha]
                q1 = abq_arg["Q1"][mi * profile_arg.alpha_terms + alpha]
                q2 = abq_arg["Q2"][mi * profile_arg.alpha_terms + alpha]
                for ni in range(n):
                    left = model.mat_mul(a_block, model.mat_mul(u_arg[ni], q1, l), l)
                    total = model.zeros_matrix(l)
                    for nj in range(n):
                        right = model.mat_mul(model.mat_mul(q2, u_arg[nj], l), b_block, l)
                        total = model.mat_add(total, model.mat_mul(blocks[(mi_prime * n + ni) * n + nj], right, l))
                    out[mi * profile_arg.sq_rank : (mi + 1) * profile_arg.sq_rank] = model.mat_add(
                        out[mi * profile_arg.sq_rank : (mi + 1) * profile_arg.sq_rank], model.mat_mul(left, total, l)
                    )
        return model.pack_nibbles(out)

    baseline_map = model.direct_map(profile, p_blocks, abq, u_matrices)
    assert baseline_map == accepted
    assert drop_alpha_terms(profile, p_blocks, abq, u_matrices) != accepted
    assert fixed_i_prime(profile, p_blocks, abq, u_matrices) != accepted
    assert missing_transpose(profile, p_blocks, abq, u_matrices) != accepted

    # Expansion mutants.
    wrong_expand = model.continuous_shake128_stream(seed_bytes, model.bytes_prng_public(profile))
    assert wrong_expand != model.pk_expand(profile, seed_bytes)
    assert model.aes128_ctr_stream(seed_bytes, model.bytes_prng_public(profile)) == model.pk_expand(profile, seed_bytes)


def test_native_key_alignment_relations() -> None:
    algorithm = "SNOVA-R2-24-5-16-4-AES"
    profile, seed, _, _, message = _settings(algorithm)
    binary = _probe(algorithm)
    parts = util.run_probe(binary, [f"SIGN {seed.hex()} {message.hex()} {(bytes(range(16))).hex()}"])[0].split()
    pk = bytes.fromhex(parts[2])
    signature = bytes.fromhex(parts[3])
    seed_bytes, p22 = model.decode_public_key(profile, pk)
    p, t12, f = model.model_private_algebra(profile, seed_bytes, seed[16:])
    # The model must reproduce P22 through T/P21/F12.
    p22_flat = [value for matrix in p22 for value in matrix]
    assert model.pack_nibbles(model.gen_p22(profile, t12, p["P21"], f["F12"])) == model.pack_nibbles(p22_flat)
    # F22 is identically zero; check the public/private map relation Ptilde(U)=Ftilde(TU).
    abq = model.gen_a_b_q_p(profile, seed_bytes)
    f_blocks = model._assemble_f(profile, f)
    p_blocks = model._assemble_p(profile, abq, p22)
    u_matrices, _ = model.decode_signature(profile, signature)
    x_matrices = model.transform_u_to_x(profile, t12, u_matrices)
    assert model.direct_map(profile, p_blocks, abq, u_matrices) == model.model_private_map(profile, f_blocks, abq, x_matrices)

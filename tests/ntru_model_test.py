"""Independent NTRU model-lane tests.

Pure-Python model tests plus differential probes against the pinned
NTRU-20201016 reference through tests/ntru_hook_cli.cc.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(REPO_ROOT / "tests" / "models"))

import _ntru_util as util  # noqa: E402
import ntru_model as nm  # noqa: E402


PROFILES = nm.load_profiles()
ALGORITHMS = list(util.PARAMS)


@pytest.fixture(scope="module")
def hook_clis(tmp_path_factory):
    out = {}
    for algorithm in ALGORITHMS:
        out[algorithm] = util.compile_hook_cli(algorithm, tmp_path_factory.mktemp(f"ntru-{algorithm}"))
    return out


def run_cli(cli: Path, *args: str) -> dict[str, str]:
    import subprocess

    result = subprocess.run([str(cli), *args], cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    fields: dict[str, str] = {}
    for line in result.stdout.strip().splitlines():
        for token in line.split():
            if "=" in token:
                key, value = token.split("=", 1)
                fields[key] = value
    return fields


def parse_ints(text: str) -> list[int]:
    return [int(item) for item in text.split(",") if item != ""]


def test_profile_matrix_and_layout():
    assert set(PROFILES) == set(ALGORITHMS)
    for profile in PROFILES.values():
        assert profile.b3 == (profile.n - 1 + 4) // 5
        assert profile.bq == ((profile.n - 1) * profile.logq + 7) // 8
        assert profile.pk_len == profile.bq
        assert profile.ct_len == profile.bq
        assert profile.sk_len == 2 * profile.b3 + profile.bq + profile.prf_key_bytes
        if profile.variant == "HPS":
            assert profile.weight == profile.q // 8 - 2
        # S3 tail trit counts from (n-1) mod 5: 509->3, 677->1, 821->0, 701->0
        tail = (profile.n - 1) % 5
        expected_tail = {"NTRU-HPS-2048-509": 3, "NTRU-HPS-2048-677": 1,
                         "NTRU-HPS-4096-821": 5, "NTRU-HRSS-701": 5}[profile.algorithm]
        assert (tail if tail else 5) == expected_tail
        assert profile.tail_unused_bits == (profile.bq * 8) % profile.logq


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_codec_roundtrip_and_canonicality(algorithm):
    profile = PROFILES[algorithm]
    trits = [(i * 7 + 1) % 3 for i in range(profile.n)]
    payload = nm.encode_s3(trits, profile)
    assert len(payload) == profile.pack_trinary_bytes
    decoded = nm.decode_s3(payload, profile)
    assert decoded[: profile.n - 1] == trits[: profile.n - 1]
    assert decoded[-1] == 0

    with pytest.raises(nm.NtruModelError):
        nm.encode_s3([3] + trits[1:], profile)

    coefficients = [(i * 13 + 5) % profile.q for i in range(profile.n)]
    packed = nm.encode_rq0(coefficients, profile)
    unpacked = nm.decode_rq0(packed, profile)
    assert unpacked[: profile.n - 1] == coefficients[: profile.n - 1]
    assert sum(unpacked) % profile.q == 0
    assert unpacked[-1] == (profile.q - sum(coefficients[: profile.n - 1])) % profile.q

    with pytest.raises(nm.NtruModelError):
        nm.encode_rq0([profile.q] + coefficients[1:], profile)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_codec_differential_with_reference(hook_clis, algorithm):
    profile = PROFILES[algorithm]
    cli = hook_clis[algorithm]
    trits = [(i * 5 + 2) % 3 for i in range(profile.n)]
    reference = run_cli(cli, "pack3", ",".join(str(value) for value in trits))
    assert bytes.fromhex(reference["payload"]) == nm.encode_s3(trits, profile)
    unpacked = run_cli(cli, "unpack3", reference["payload"])
    assert parse_ints(unpacked["trits"]) == nm.decode_s3(bytes.fromhex(reference["payload"]), profile)

    coefficients = [(i * 17 + 9) % profile.q for i in range(profile.n)]
    reference_q = run_cli(cli, "packq", ",".join(str(value) for value in coefficients))
    assert bytes.fromhex(reference_q["payload"]) == nm.encode_rq0(coefficients, profile)
    unpacked_q = run_cli(cli, "unpackq", reference_q["payload"])
    hook_coefficients = [value % profile.q for value in parse_ints(unpacked_q["coeffs"])]
    assert hook_coefficients == nm.decode_rq0(bytes.fromhex(reference_q["payload"]), profile)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_lift_differential_with_reference(hook_clis, algorithm):
    profile = PROFILES[algorithm]
    cli = hook_clis[algorithm]
    trits = [(i * 3 + 1) % 3 for i in range(profile.n)]
    reference = run_cli(cli, "lift", ",".join(str(value) for value in trits))
    expected = nm.lift(trits, profile)
    assert parse_ints(reference["coeffs"]) == expected


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_dpke_decrypt_and_membership_differential(hook_clis, algorithm):
    profile = PROFILES[algorithm]
    cli = hook_clis[algorithm]
    keygen_seed = bytes((i * 7 + 3) & 0xFF for i in range(profile.sample_fg_bytes))
    keypair = run_cli(cli, "owcpa_keypair", keygen_seed.hex())
    pk = bytes.fromhex(keypair["pk"])
    sk_owcpa = bytes.fromhex(keypair["sk"])
    # Append a fixed prf key to form the full KEM secret key.
    prf = bytes((i * 11 + 5) & 0xFF for i in range(profile.prf_key_bytes))
    sk = sk_owcpa + prf

    enc_seed = bytes((i * 13 + 7) & 0xFF for i in range(profile.sample_rm_bytes))
    enc = run_cli(cli, "encaps", enc_seed.hex(), pk.hex())
    ct = bytes.fromhex(enc["ct"])
    ss = bytes.fromhex(enc["ss"])

    reference = run_cli(cli, "decrypt", sk.hex(), ct.hex())
    model = nm.dpke_decrypt(profile, sk, ct)
    assert model["fail"] == (reference["fail"] == "1")
    assert model["fail_padding"] == (reference["pad"] == "1")
    assert model["fail_m"] == (reference["m"] == "1")
    assert model["fail_r"] == (reference["r"] == "1")
    assert model["r"] == parse_ints(reference["rtrits"])
    assert model["m"] == parse_ints(reference["mtrits"])

    decaps = run_cli(cli, "decaps", sk.hex(), ct.hex())
    assert decaps["ss"] == ss.hex()
    assert nm.model_decaps(profile, sk, ct) == ss
    assert nm.model_valid_secret(profile, sk, ct) == ss
    assert not model["fail"]


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_padding_and_prf_fallback_exact(hook_clis, algorithm):
    profile = PROFILES[algorithm]
    cli = hook_clis[algorithm]
    if profile.tail_unused_bits == 0:
        pytest.skip("profile has no ciphertext padding field")
    keygen_seed = bytes((i * 5 + 1) & 0xFF for i in range(profile.sample_fg_bytes))
    keypair = run_cli(cli, "owcpa_keypair", keygen_seed.hex())
    pk = bytes.fromhex(keypair["pk"])
    sk_owcpa = bytes.fromhex(keypair["sk"])
    prf = bytes((i * 3 + 9) & 0xFF for i in range(profile.prf_key_bytes))
    sk = sk_owcpa + prf

    enc_seed = bytes((i * 17 + 2) & 0xFF for i in range(profile.sample_rm_bytes))
    enc = run_cli(cli, "encaps", enc_seed.hex(), pk.hex())
    ct = bytearray(bytes.fromhex(enc["ct"]))
    ss_valid = bytes.fromhex(enc["ss"])
    ct[-1] |= 1 << (8 - profile.tail_unused_bits)
    mutated = bytes(ct)

    reference = run_cli(cli, "decrypt", sk.hex(), mutated.hex())
    model = nm.dpke_decrypt(profile, sk, mutated)
    assert reference["pad"] == "1"
    assert model["fail_padding"]
    assert model["fail"]

    decaps = run_cli(cli, "decaps", sk.hex(), mutated.hex())
    # The C API contract of the pinned reference always returns 0.
    assert decaps["rc"] == "0"
    expected = nm.fallback_secret(prf, mutated)
    assert bytes.fromhex(decaps["ss"]) == expected
    assert bytes.fromhex(decaps["ss"]) != ss_valid
    assert nm.model_decaps(profile, sk, mutated) == expected

    # Only the prf key changes the invalid output; the valid output is stable.
    mutated_sk = sk[: profile.sk_prf_off] + bytes([sk[profile.sk_prf_off] ^ 0x01]) + sk[profile.sk_prf_off + 1 :]
    expected2 = nm.fallback_secret(mutated_sk[profile.sk_prf_off : profile.sk_prf_off + profile.prf_key_bytes], mutated)
    decaps2 = run_cli(cli, "decaps", mutated_sk.hex(), mutated.hex())
    assert bytes.fromhex(decaps2["ss"]) == expected2
    assert expected2 != expected
    valid_mutated = run_cli(cli, "decaps", mutated_sk.hex(), bytes.fromhex(enc["ct"]).hex())
    assert bytes.fromhex(valid_mutated["ss"]) == ss_valid


def test_stored_valid_membership_and_padding_fixtures(hook_clis):
    fixture = json.loads((REPO_ROOT / "tests" / "fixtures" / "ntru" / "cases.json").read_text())
    for algorithm, case in fixture["parameters"].items():
        profile = PROFILES[algorithm]
        cli = hook_clis[algorithm]
        pk = bytes.fromhex(case["pk"])
        sk = bytes.fromhex(case["sk"])
        ct_valid = bytes.fromhex(case["ct_valid"])
        assert nm.model_decaps(profile, sk, ct_valid) == bytes.fromhex(case["ss_valid"])
        assert run_cli(cli, "decaps", sk.hex(), case["ct_valid"])["ss"] == case["ss_valid"]
        assert not nm.dpke_decrypt(profile, sk, ct_valid)["fail"]
        assert pk == bytes.fromhex(run_cli(cli, "owcpa_keypair", case["keygen_seed"])["pk"])
        assert sk[: profile.sk_prf_off] == bytes.fromhex(run_cli(cli, "owcpa_keypair", case["keygen_seed"])["sk"])

        padding = bytes.fromhex(case["ct_padding_fail"])
        reference = run_cli(cli, "decrypt", sk.hex(), padding.hex())
        assert reference["pad"] == "1" and reference["fail"] == "1"
        model = nm.dpke_decrypt(profile, sk, padding)
        assert model["fail_padding"] and model["fail"]
        assert nm.model_decaps(profile, sk, padding) == bytes.fromhex(case["ss_padding_fail"])
        assert run_cli(cli, "decaps", sk.hex(), padding.hex())["ss"] == case["ss_padding_fail"]
        assert case["ss_padding_fail"] != case["ss_valid"]

        membership = bytes.fromhex(case["ct_membership_fail"])
        reference = run_cli(cli, "decrypt", sk.hex(), membership.hex())
        assert reference["fail"] == "1" and reference["pad"] == "0"
        model = nm.dpke_decrypt(profile, sk, membership)
        assert model["fail"] and not model["fail_padding"]
        assert nm.model_decaps(profile, sk, membership) == bytes.fromhex(case["ss_membership_fail"])
        assert run_cli(cli, "decaps", sk.hex(), membership.hex())["ss"] == case["ss_membership_fail"]


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_hps_membership_weight(hook_clis, algorithm):
    profile = PROFILES[algorithm]
    if profile.variant != "HPS":
        pytest.skip("weight check is HPS-only")
    cli = hook_clis[algorithm]
    keygen_seed = bytes((i * 7 + 11) & 0xFF for i in range(profile.sample_fg_bytes))
    keypair = run_cli(cli, "owcpa_keypair", keygen_seed.hex())
    pk = bytes.fromhex(keypair["pk"])
    sk = bytes.fromhex(keypair["sk"]) + bytes(profile.prf_key_bytes)

    enc_seed = bytes((i * 19 + 4) & 0xFF for i in range(profile.sample_rm_bytes))
    enc = run_cli(cli, "encaps", enc_seed.hex(), pk.hex())
    ct = bytes.fromhex(enc["ct"])
    reference = run_cli(cli, "decrypt", sk.hex(), ct.hex())
    m = parse_ints(reference["mtrits"])
    assert nm.check_m(m, profile)
    assert nm.wrong_hps_weight_mutant(profile, m)
    # The model rejects a wrong-count message while the mutant accepts it.
    perturbed = list(m)
    ones = [i for i, value in enumerate(perturbed) if value == 1]
    if ones:
        perturbed[ones[0]] = 0
        assert not nm.check_m(perturbed, profile)
        assert nm.wrong_hps_weight_mutant(profile, perturbed)


def test_hrss_hps_lift_mutant(hook_clis):
    profile = PROFILES["NTRU-HRSS-701"]
    cli = hook_clis["NTRU-HRSS-701"]
    keygen_seed = bytes((i * 3 + 21) & 0xFF for i in range(profile.sample_fg_bytes))
    keypair = run_cli(cli, "owcpa_keypair", keygen_seed.hex())
    pk = bytes.fromhex(keypair["pk"])
    sk = bytes.fromhex(keypair["sk"]) + bytes(profile.prf_key_bytes)
    enc_seed = bytes((i * 23 + 6) & 0xFF for i in range(profile.sample_rm_bytes))
    enc = run_cli(cli, "encaps", enc_seed.hex(), pk.hex())
    ct = bytes.fromhex(enc["ct"])
    assert nm.model_decaps(profile, sk, ct) == bytes.fromhex(enc["ss"])
    assert nm.hrss_hps_lift_mutant(profile, sk, ct) != bytes.fromhex(enc["ss"])


def test_mutant_catalogue_against_fallback(hook_clis):
    profile = PROFILES["NTRU-HPS-2048-509"]
    cli = hook_clis["NTRU-HPS-2048-509"]
    keygen_seed = bytes((i * 7 + 31) & 0xFF for i in range(profile.sample_fg_bytes))
    keypair = run_cli(cli, "owcpa_keypair", keygen_seed.hex())
    pk = bytes.fromhex(keypair["pk"])
    sk = bytes.fromhex(keypair["sk"]) + bytes((i * 11 + 5) & 0xFF for i in range(profile.prf_key_bytes))
    enc_seed = bytes((i * 29 + 8) & 0xFF for i in range(profile.sample_rm_bytes))
    enc = run_cli(cli, "encaps", enc_seed.hex(), pk.hex())
    ct = bytearray(bytes.fromhex(enc["ct"]))
    ct[-1] |= 1 << (8 - profile.tail_unused_bits)
    mutated = bytes(ct)
    expected = nm.fallback_secret(sk[profile.sk_prf_off : profile.sk_prf_off + profile.prf_key_bytes], mutated)

    for name, mutant in nm.MUTANTS.items():
        result = mutant(profile, sk, mutated)
        assert result != expected, f"mutant {name} was not caught"

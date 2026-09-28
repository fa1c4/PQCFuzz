"""SIKE/SIDH model tests: parameters, codecs, SHAKE vectors, transcripts."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(TESTS_DIR / "models"))

import sidh_model  # noqa: E402
import sike_model  # noqa: E402

FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "sike_sidh"
SHAKE256_EMPTY_32 = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"


def test_profile_parameter_recomputation():
    for profile in sike_model.load_profiles().values():
        p = sike_model.field_prime(profile.e2, profile.e3)
        assert profile.np == (p.bit_length() + 7) // 8
        assert profile.nsk2 == (profile.e2 + 7) // 8
        sbits = sike_model.bob_scalar_bits(profile.e3)
        assert profile.nsk3 == (sbits + 7) // 8
        assert profile.sk_len == profile.msg_bytes + profile.nsk3 + profile.pk_len
        assert profile.ct_len == profile.c0_len + profile.msg_bytes
        assert profile.c0_len == 6 * profile.np
        assert profile.sk_sk3_off == profile.msg_bytes
        assert profile.sk_pk_off == profile.msg_bytes + profile.nsk3
    for profile in sidh_model.load_profiles().values():
        p = sidh_model.field_prime(profile.e2, profile.e3)
        assert profile.np == (p.bit_length() + 7) // 8
        assert profile.shared_len == 2 * profile.np
        assert profile.pk_len == 6 * profile.np
        assert profile.sk_a_len == (profile.e2 + 7) // 8
        sbits = sidh_model.bob_scalar_bits(profile.e3)
        assert profile.sk_b_len == (sbits + 7) // 8


def test_shake256_known_vector():
    assert sike_model.shake256(b"", 32).hex() == SHAKE256_EMPTY_32
    assert sike_model.shake256(b"The quick brown fox jumps over the lazy dog", 16) == bytes.fromhex(
        "2f671343d9b2e1604dc9dcf0753e5fe1"
    )


def test_fp_codec_boundaries():
    for profile in sike_model.load_profiles().values():
        boundaries = sike_model.limb_boundaries(profile)
        p = sike_model.field_prime(profile.e2, profile.e3)
        assert sike_model.classify_limb(boundaries["p_minus_one"], p) == "canonical"
        assert sike_model.classify_limb(boundaries["p"], p) == "out_of_range"
        assert sike_model.classify_limb(boundaries["p_plus_one"], p) == "out_of_range"
        assert sike_model.classify_limb(boundaries["all_ones"], p) == "out_of_range"
        assert sike_model.fp_encode(p - 1, p, profile.np) == boundaries["p_minus_one"]
        try:
            sike_model.fp_decode(boundaries["p"], p)
            raise AssertionError("p must not decode")
        except ValueError:
            pass


def test_case_fixture_middle_layers():
    cases = sike_model.load_cases()
    for profile in sike_model.load_profiles().values():
        suffix = profile.algorithm.split("-")[1]
        record = cases[suffix]
        checks = sike_model.verify_case(profile, record)
        assert all(checks.values()), (profile.algorithm, checks)


def test_sidh_model_math():
    for profile in sidh_model.load_profiles().values():
        p = sidh_model.field_prime(profile.e2, profile.e3)
        assert sidh_model.j_invariant(6, p) == 287496 % p
        assert sidh_model.fp2_mul((3, 5), sidh_model.fp2_inv((3, 5), 101), 101) == (1, 0)
        assert sidh_model.fp2_mul((1, 2), (3, 4), 101) == ((3 - 8) % 101, (4 + 6) % 101)
    # x-only ladder self-consistency on a small curve.
    p, a, x = 101, 6, 5
    assert sidh_model.montgomery_ladder(x, 12, a, p) == sidh_model.montgomery_ladder(
        sidh_model.montgomery_ladder(x, 3, a, p), 4, a, p
    )


def test_sidh_cfpk_curve_checks():
    records = sidh_model.load_reference()
    for profile in sidh_model.load_profiles().values():
        suffix = profile.algorithm.split("-")[1]
        record = records[suffix]
        honest_pk = bytes.fromhex(record["pk_a"])
        honest = sidh_model.cfpk_curve_checks(honest_pk, profile)
        assert all(honest.values()), (profile.algorithm, honest)

        p = sidh_model.field_prime(profile.e2, profile.e3)
        # xP = 0 degenerates the get_A denominator.
        zero_pk = bytearray(honest_pk)
        zero_pk[: 2 * profile.np] = bytes(2 * profile.np)
        bad = sidh_model.cfpk_curve_checks(bytes(zero_pk), profile)
        assert bad["decodable"] and not bad["denominator_nonzero"]
        # Out-of-range limb must not decode.
        out_of_range = bytearray(honest_pk)
        out_of_range[: profile.np] = p.to_bytes(profile.np, "little")
        assert not sidh_model.cfpk_curve_checks(bytes(out_of_range), profile)["decodable"]
        # Truncated key is rejected by length.
        assert not sidh_model.cfpk_curve_checks(honest_pk[:-1], profile)["pk_length"]
        # A^2 = 4 is a degenerate Montgomery curve.
        try:
            sidh_model.j_invariant(2, p)
            raise AssertionError("degenerate Montgomery curve must not have a j-invariant")
        except ValueError:
            pass


def test_sidh_reference_fixture():
    records = sidh_model.load_reference()
    for profile in sidh_model.load_profiles().values():
        suffix = profile.algorithm.split("-")[1]
        checks = sidh_model.verify_reference(profile, records[suffix])
        assert all(checks.values()), (profile.algorithm, checks)


def test_cpp_model_agreement(tmp_path):
    source = r"""
    #include <cstdio>
    #include <string>
    #include <vector>
    #include "mutators/sha3.h"
    #include "mutators/sike_layout.h"

    int main() {
      const char *algorithms[] = {"SIKE-p434", "SIKE-p503", "SIKE-p610", "SIKE-p751"};
      for (const char *name : algorithms) {
        pqcfuzz::SikeParams params;
        if (!pqcfuzz::GetSikeParams(name, &params)) { printf("params:%s\n", name); return 1; }
        pqcfuzz::SikeBig p;
        if (!pqcfuzz::ComputeSikeFieldPrime(params.e2, params.e3, &p)) { printf("prime:%s\n", name); return 1; }
        std::vector<uint8_t> minus_one(params.np, 0);
        std::vector<uint8_t> prime_bytes(params.np, 0);
        pqcfuzz::SikeBig q = p;
        // p-1 via the public boundary helper through the mutator is covered in
        // the oracle tests; here just print the number of limbs and range of p.
        pqcfuzz::SikeBigToLeBytes(p, prime_bytes.data(), params.np);
        int limbs = 0;
        for (size_t i = 0; i < pqcfuzz::SikeBig::kLimbs; ++i) limbs += p.limb[i] != 0 ? 1 : 0;
        printf("sike %s np=%zu nsk2=%zu nsk3=%zu pk=%zu sk=%zu ct=%zu ss=%zu limbs=%d canonical_p=%d\n",
               name, params.np, params.nsk2, params.nsk3, params.pk_len, params.sk_len, params.ct_len,
               params.ss_len, limbs, pqcfuzz::SikeFpCanonical(prime_bytes.data(), params.np, p) ? 0 : 1);
      }
      const char *sidh[] = {"SIDH-p434", "SIDH-p503", "SIDH-p610", "SIDH-p751"};
      for (const char *name : sidh) {
        pqcfuzz::SidhParams params;
        if (!pqcfuzz::GetSidhParams(name, &params)) { printf("sidh_params:%s\n", name); return 1; }
        printf("sidh %s pk=%zu ska=%zu skb=%zu shared=%zu\n", name, params.pk_len, params.sk_a_len,
               params.sk_b_len, params.shared_len);
      }
      const std::vector<uint8_t> digest = pqcfuzz::Shake256({}, 32);
      std::string hex;
      static const char kHex[] = "0123456789abcdef";
      for (uint8_t byte : digest) { hex.push_back(kHex[byte >> 4]); hex.push_back(kHex[byte & 0xF]); }
      printf("shake=%s\n", hex.c_str());
      return 0;
    }
    """
    from _falcon_util import compile_test_main

    binary = compile_test_main(
        tmp_path,
        source,
        extra_sources=[
            "src/adapters/status.cc",
            "src/mutators/sike_layout.cc",
            "src/mutators/sha3.cc",
        ],
    )
    result = subprocess.run([str(binary)], cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    lines = result.stdout.strip().splitlines()
    fields = {}
    for line in lines:
        parts = line.split()
        if line.startswith("sike "):
            entry = {key: value for key, value in (token.split("=") for token in parts[2:])}
            fields[parts[1]] = entry
            assert entry["canonical_p"] == "1"
        if line.startswith("sidh "):
            entry = {key: value for key, value in (token.split("=") for token in parts[2:])}
            fields[parts[1]] = entry
        if line.startswith("shake="):
            assert line.split("=", 1)[1] == SHAKE256_EMPTY_32
    for profile in sike_model.load_profiles().values():
        entry = fields[profile.algorithm]
        assert int(entry["np"]) == profile.np
        assert int(entry["nsk2"]) == profile.nsk2
        assert int(entry["nsk3"]) == profile.nsk3
        assert int(entry["pk"]) == profile.pk_len
        assert int(entry["sk"]) == profile.sk_len
        assert int(entry["ct"]) == profile.ct_len
        assert int(entry["ss"]) == profile.ss_len
    for profile in sidh_model.load_profiles().values():
        entry = fields[profile.algorithm]
        assert int(entry["pk"]) == profile.pk_len
        assert int(entry["ska"]) == profile.sk_a_len
        assert int(entry["skb"]) == profile.sk_b_len
        assert int(entry["shared"]) == profile.shared_len


def test_fixture_hashes_match_profiles():
    lock = json.loads((REPO_ROOT / "src" / "config" / "source_locks" / "sike.json").read_text())
    import hashlib

    kat_path = REPO_ROOT / lock["kat"]["fixture_path"]
    cases_path = REPO_ROOT / lock["kat"]["cases_fixture_path"]
    assert hashlib.sha256(kat_path.read_bytes()).hexdigest() == lock["kat"]["fixture_sha256"]
    assert hashlib.sha256(cases_path.read_bytes()).hexdigest() == lock["kat"]["cases_fixture_sha256"]

from __future__ import annotations

import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
REFERENCE_ARCHIVE = REPO_ROOT / "workspace" / "build" / "reference" / "libpqcfuzz_pqclean_reference.a"
PQCLEAN_DIR = REPO_ROOT / "third_party" / "PQClean"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import compile_and_run  # noqa: E402


SOURCE = """
#include <cstring>
#include <string>
#include <vector>
#include "adapters/reference/reference_adapter.h"

int main() {
  const pqcfuzz_kem_adapter *kem = pqcfuzz::pqcfuzz_get_pqclean_reference_kem_adapter("pqclean_ref_mlkem768");
  if (kem == nullptr) return 1;
  if (kem->keygen_derand == nullptr || kem->encaps_derand == nullptr) return 2;
  if (kem->reference_version == nullptr || std::strlen(kem->reference_version) == 0) return 3;

  std::vector<uint8_t> coins_a(64, 0x11);
  std::vector<uint8_t> coins_b(64, 0x22);
  std::vector<uint8_t> pk_a(1184), sk_a(2400), pk_b(1184), sk_b(2400);
  if (kem->keygen_derand(pk_a.data(), sk_a.data(), coins_a.data()) != PQCFUZZ_OK) return 4;
  if (kem->keygen_derand(pk_b.data(), sk_b.data(), coins_a.data()) != PQCFUZZ_OK) return 5;
  if (pk_a != pk_b || sk_a != sk_b) return 6;
  if (kem->keygen_derand(pk_b.data(), sk_b.data(), coins_b.data()) != PQCFUZZ_OK) return 7;
  if (pk_a == pk_b) return 8;

  std::vector<uint8_t> enc_coins(32, 0x33);
  std::vector<uint8_t> ct_a(1088), ss_a(32), ct_b(1088), ss_b(32);
  if (kem->encaps_derand(ct_a.data(), ss_a.data(), pk_a.data(), enc_coins.data()) != PQCFUZZ_OK) return 9;
  if (kem->encaps_derand(ct_b.data(), ss_b.data(), pk_a.data(), enc_coins.data()) != PQCFUZZ_OK) return 10;
  if (ct_a != ct_b || ss_a != ss_b) return 11;

  std::vector<uint8_t> dec_ss(32);
  if (kem->decaps(dec_ss.data(), ct_a.data(), sk_a.data()) != PQCFUZZ_OK) return 12;
  if (dec_ss != ss_a) return 13;

  const pqcfuzz_sig_adapter *sig = pqcfuzz::pqcfuzz_get_pqclean_reference_sig_adapter("pqclean_ref_mldsa44");
  if (sig == nullptr) return 14;
  if (sig->reference_version == nullptr) return 15;
  std::vector<uint8_t> sig_pk(1312), sig_sk(2560);
  if (sig->keygen(sig_pk.data(), sig_sk.data()) != PQCFUZZ_OK) return 16;
  std::vector<uint8_t> signature(2420);
  size_t signature_len = 0;
  const std::vector<uint8_t> message = {'m'};
  const std::vector<uint8_t> context = {0x01};
  if (sig->sign(signature.data(), &signature_len, message.data(), message.size(), sig_sk.data(), context.data(), context.size()) != PQCFUZZ_OK) return 17;
  if (signature_len != 2420) return 18;
  if (sig->verify(signature.data(), signature_len, message.data(), message.size(), sig_pk.data(), context.data(), context.size()) != PQCFUZZ_OK) return 19;
  const std::vector<uint8_t> other_context = {0x02};
  if (sig->verify(signature.data(), signature_len, message.data(), message.size(), sig_pk.data(), other_context.data(), other_context.size()) == PQCFUZZ_OK) return 20;

  std::vector<uint8_t> appended = signature;
  appended.push_back(0x00);
  if (sig->verify(appended.data(), appended.size(), message.data(), message.size(), sig_pk.data(), context.data(), context.size()) == PQCFUZZ_OK) return 21;
  return 0;
}
"""


@pytest.mark.skipif(not REFERENCE_ARCHIVE.is_file(), reason="PQClean reference archive is not built")
def test_pqclean_reference_adapters_are_deterministic_and_ctx_bound(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        SOURCE,
        [
            "src/adapters/reference/reference_adapter.cc",
            "src/adapters/reference/pqclean_randombytes_override.cc",
            "src/adapters/rng_control.cc",
            "src/adapters/liboqs/rng_control.cc",
            "src/adapters/status.cc",
            str(REFERENCE_ARCHIVE),
        ],
        defines=["PQCFUZZ_HAVE_PQCLEAN_REFERENCE"],
    )

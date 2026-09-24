from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import CORE_EXECUTOR_SOURCES, compile_and_run  # noqa: E402


FAKE_KEM_SOURCE = """
#include <cstring>
#include <string>
#include <vector>
#include "mutators/ml_kem_layout.h"
#include "oracles/oracle_executor.h"

namespace {
uint8_t g_valid_ct[1568];
size_t g_valid_ct_len = 0;
uint8_t g_valid_ss[32];
bool g_z_bound = true;

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1184);
  std::memset(sk, 0x22, 2400);
  return PQCFUZZ_OK;
}

pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *) {
  std::memset(ct, 0x33, 1088);
  std::memset(ss, 0x44, 32);
  std::memcpy(g_valid_ct, ct, 1088);
  std::memcpy(g_valid_ss, ss, 32);
  g_valid_ct_len = 1088;
  return PQCFUZZ_OK;
}

pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  if (g_valid_ct_len != 0 && std::memcmp(ct, g_valid_ct, g_valid_ct_len) == 0) {
    std::memcpy(ss, g_valid_ss, 32);
    return PQCFUZZ_OK;
  }
  for (size_t i = 0; i < 32; ++i) {
    ss[i] = g_z_bound
        ? static_cast<uint8_t>(0x5A ^ ct[0] ^ sk[2400 - 32 + i])
        : static_cast<uint8_t>(0x77);
  }
  return PQCFUZZ_OK;
}

const pqcfuzz_kem_adapter kAdapter = {
    "fake", "fake_mlkem768", "ML-KEM-768", 1184, 2400, 1088, 32, Keygen, Encaps, Decaps};
}  // namespace

int main(int argc, char **argv) {
  const std::string mode = argc > 1 ? argv[1] : "z-bound";
  const bool z_bound = mode == "z-bound";
  g_z_bound = z_bound;
  pqcfuzz::OracleExecutorConfig cfg;
  cfg.job_id = "ir-test";
  cfg.pair_id = "ir-pair";
  cfg.algorithm = "ML-KEM-768";
  cfg.oracle_id = "mlkem_implicit_rejection_relations";
  cfg.left = &kAdapter;
  pqcfuzz::GetMlKemParams(cfg.algorithm, &cfg.params);
  cfg.seed = {1, 2, 3};
  // xor_byte with a zero value leaves the ciphertext unchanged.
  cfg.mutation = mode == "no-effect" ? std::vector<uint8_t>{1, 0, 0, 0, 0}
                                     : std::vector<uint8_t>{0, 0, 0, 0, 0xA5};
  auto trace = pqcfuzz::ExecuteKemOracle(cfg);
  if (trace.subtests.size() != 3) return 1;
  if (mode == "no-effect") {
    for (const auto &subtest : trace.subtests) {
      if (!subtest.not_applicable) return 14;
      if (subtest.skipped) return 15;
    }
    if (!trace.findings.empty()) return 16;
    if (pqcfuzz::FinalizeDisposition(trace) != pqcfuzz::OracleDisposition::kNotApplicable) return 17;
    return 0;
  }
  if (!trace.relation_evaluable) return 12;
  if (!trace.mutated_target_entered || !trace.baseline_target_entered) return 13;
  for (const auto &subtest : trace.subtests) {
    if (subtest.skipped) return 2;
  }
  if (z_bound) {
    if (!trace.findings.empty()) return 3;
    if (!trace.subtests[0].passed || !trace.subtests[1].passed || !trace.subtests[2].passed) return 4;
    // The z-region mutation must be recorded with a digest change.
    bool saw_z = false;
    for (const auto &mutation : trace.mutations) {
      if (mutation.target == "secret_key.z" && mutation.effective) saw_z = true;
    }
    if (!saw_z) return 5;
    return 0;
  }
  // A fallback that ignores z fails the z-separation relation only.
  if (trace.subtests[1].passed) return 6;
  if (!trace.subtests[0].passed || !trace.subtests[2].passed) return 7;
  if (trace.findings.size() != 1) return 8;
  if (trace.findings[0].finding_subclass != "implicit_rejection_z_separation") return 9;
  if (trace.findings[0].finding_class != "potential_crypto_vuln") return 10;
  if (trace.findings[0].verdict != pqcfuzz::Verdict::kNonconformant) return 11;
  return 0;
}
"""


def test_implicit_rejection_relations_pass_for_z_bound_fallback(tmp_path: Path) -> None:
    compile_and_run(tmp_path, FAKE_KEM_SOURCE, CORE_EXECUTOR_SOURCES, args=["z-bound"])


def test_implicit_rejection_relations_fail_when_z_is_ignored(tmp_path: Path) -> None:
    compile_and_run(tmp_path, FAKE_KEM_SOURCE, CORE_EXECUTOR_SOURCES, args=["z-ignored"])


def test_implicit_rejection_relations_ineffective_mutation_is_not_applicable(tmp_path: Path) -> None:
    compile_and_run(tmp_path, FAKE_KEM_SOURCE, CORE_EXECUTOR_SOURCES, args=["no-effect"])


def test_rejection_secret_regions_are_bound_to_layout() -> None:
    sys.path.insert(0, str(SRC_ROOT))
    import json

    mlkem = json.loads((SRC_ROOT / "oracles" / "specs" / "ml_kem.json").read_text(encoding="utf-8"))
    aigis = json.loads((SRC_ROOT / "oracles" / "specs" / "aigis_enc.json").read_text(encoding="utf-8"))
    mlkem_ids = {entry["oracle_id"] for entry in mlkem["oracles"]}
    aigis_ids = {entry["oracle_id"] for entry in aigis["oracles"]}
    assert "mlkem_implicit_rejection_relations" in mlkem_ids
    assert "aigisenc_implicit_rejection_relations" in aigis_ids


def test_rejection_secret_offsets_match_specs(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "mutators/aigis_enc_layout.h"
        #include "mutators/ml_kem_layout.h"

        int main() {
          pqcfuzz::MlKemParams kem{};
          if (!pqcfuzz::GetMlKemParams("ML-KEM-768", &kem)) return 1;
          // FIPS 203: dk = dkPKE(384k) || ek(384k+32) || H(ek)(32) || z(32).
          if (kem.z_offset != 768 * 3 + 64) return 2;
          if (kem.z_len != 32) return 3;
          if (kem.z_offset + kem.z_len != kem.sk_len) return 4;

          pqcfuzz::AigisEncParams enc{};
          if (!pqcfuzz::GetAigisEncParams("AIGIS-ENC-2", &enc)) return 5;
          // PQMagic: sk = s_vec || pk || H(pk) || z(SEED_BYTES).
          if (enc.z_offset != enc.sk_len - 32) return 6;
          if (enc.z_len != 32) return 7;
          return 0;
        }
        """,
        ["src/mutators/ml_kem_layout.cc", "src/mutators/aigis_enc_layout.cc"],
    )

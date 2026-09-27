"""SIDH oracle routing, spec, executor, reference fixture and detection tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(TESTS_DIR))

import _sike_util as util  # noqa: E402
from jobs.generated_config_writer import (  # noqa: E402
    ORACLE_ENUM_BY_NAME,
    enabled_subtests_for_pair,
    oracle_ids_for_pair,
    oracle_spec_for_pair,
)
from pairing.pair_alg_loader import load_pair_alg  # noqa: E402
from replay.replay_one import ALGORITHM_BY_ENUM, ORACLE_BY_ENUM  # noqa: E402


PAIR_ALG = REPO_ROOT / "src" / "config" / "pair_alg.sike_sidh.json"
SPEC_PATH = REPO_ROOT / "src" / "oracles" / "specs" / "sidh.json"

SIDH_ORACLES = [
    "sidh_agreement",
    "sidh_cross_agreement",
    "sidh_field_curve_checks",
    "sidh_role_scalar_profile",
    "sidh_isogeny_math",
    "sidh_resources_rng",
    "sike_sidh_timing",
]

DEFAULT_SIDH_ORACLES = SIDH_ORACLES[:6]

ALGORITHMS = [name for name in util.PARAMS if name.startswith("SIDH-")]


def test_pair_alg_routing_and_job_generation():
    document = load_pair_alg(PAIR_ALG)
    pairs = [pair for pair in document["pairs"] if pair["status"] == "enabled" and pair["algorithm_family"] == "SIDH"]
    assert len(pairs) == 4
    assert {pair["algorithm"] for pair in pairs} == set(ALGORITHMS)
    for pair in pairs:
        assert pair["primitive_type"] == "kex"
        assert pair["exchange_contract"]["public_key_exchange"] is True
        assert pair["exchange_contract"]["peer_key_exchange"] is True
        assert pair["exchange_contract"]["secret_key_exchange"] is False
        assert oracle_spec_for_pair(pair) == "src/oracles/specs/sidh.json"
        assert oracle_ids_for_pair(pair)[0] == "sidh_agreement"
        subtests = {entry["oracle_id"]: entry for entry in enabled_subtests_for_pair(pair)}
        assert subtests["sidh_cross_agreement"]["enabled"] is True
        assert "sike_sidh_timing" not in subtests

    assert ORACLE_ENUM_BY_NAME["sidh_agreement"] == 91
    assert ORACLE_ENUM_BY_NAME["sidh_resources_rng"] == 98
    assert ALGORITHM_BY_ENUM[48] == "SIDH-p434"
    assert ALGORITHM_BY_ENUM[51] == "SIDH-p751"
    assert ORACLE_BY_ENUM[91] == "sidh_agreement"
    assert ORACLE_BY_ENUM[99] == "sike_sidh_timing"


def test_sidh_oracle_spec_shape():
    payload = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    records = payload["oracles"]
    assert len(records) == 7
    assert {record["oracle_id"] for record in records} == set(SIDH_ORACLES)
    for record in records:
        assert record["algorithm_family"] == "SIDH"
        assert record["primitive_type"] == "kex"
        assert record.get("claim") and record.get("source_reference") and record.get("limitations")
        assert record.get("property_ids")
        controls = record.get("controls")
        assert controls.get("positive_control") and controls.get("negative_control")
        assert record.get("precondition") is not None
    generated = (REPO_ROOT / "src" / "oracles" / "generated_fips_specs.inc").read_text(encoding="utf-8")
    for oracle_id in SIDH_ORACLES:
        assert f'"{oracle_id}"' in generated
    disabled = {record["oracle_id"] for record in records if record.get("enabled_by_default") is False}
    assert disabled == {"sike_sidh_timing"}


REAL_ADAPTER_MAIN = r"""
#include <cstdio>
#include <string>
#include <vector>

#include "oracles/oracle_result.h"
#include "oracles/sidh_executor.h"

extern "C" const pqcfuzz_kex_adapter *pqcfuzz_get_sidh_kex_adapter(const char *implementation_id);

int main(int argc, char **argv) {
  const char *algorithm = argv[1];
  const char *implementation_id = argv[2];
  pqcfuzz::SidhParams params;
  if (!pqcfuzz::GetSidhParams(algorithm, &params)) { printf("params\n"); return 1; }
  const pqcfuzz_kex_adapter *adapter = pqcfuzz_get_sidh_kex_adapter(implementation_id);
  if (adapter == nullptr) { printf("adapter\n"); return 1; }
  const char *oracles[] = {
      "sidh_agreement", "sidh_cross_agreement", "sidh_field_curve_checks",
      "sidh_role_scalar_profile", "sidh_isogeny_math", "sidh_resources_rng"};
  std::vector<uint8_t> seed(32);
  for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(0x5B + i);
  int failures = 0;
  for (const char *oracle_id : oracles) {
    pqcfuzz::SidhOracleConfig config;
    config.job_id = "pytest";
    config.pair_id = "pytest";
    config.algorithm = algorithm;
    config.oracle_id = oracle_id;
    config.params = params;
    config.left = adapter;
    config.right = adapter;
    config.exchange_contract.public_key_exchange = true;
    config.exchange_contract.peer_key_exchange = true;
    config.seed = seed;
    pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteSidhOracle(config);
    if (!trace.findings.empty()) {
      printf("finding:%s:%zu\n", oracle_id, trace.findings.size());
      ++failures;
      continue;
    }
    if (std::string(oracle_id) == "sidh_isogeny_math" || trace.relation_not_applicable) {
      continue;
    }
    if (!trace.baseline_target_entered) {
      printf("baseline_not_entered:%s\n", oracle_id);
      ++failures;
    }
  }
  if (failures != 0) return 1;
  printf("ok\n");
  return 0;
}
"""


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_real_adapter_honest_oracles(tmp_path, algorithm):
    util.require_sike_sources()
    binary = util.compile_adapter_binary(algorithm, tmp_path, REAL_ADAPTER_MAIN)
    implementation_id = util.PARAMS[algorithm]["sidh_kex_impl"]
    result = subprocess.run([str(binary), algorithm, implementation_id], cwd=REPO_ROOT,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


def test_reference_fixture_transcript(tmp_path):
    util.require_sike_sources()
    fixture = json.loads((REPO_ROOT / "tests" / "fixtures" / "sike_sidh" / "sidh_reference.json").read_text())
    for algorithm in ALGORITHMS:
        suffix = util.PARAMS[algorithm]["source_dir"]
        cli = util.compile_hook_cli(algorithm, tmp_path / suffix)
        record = fixture["records"][util.PARAMS[algorithm]["suffix"]]
        output = subprocess.run(
            [str(cli), "sidh", record["scalar_a"], record["scalar_b"]],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip().splitlines()
        got = {}
        for line in output:
            if "=" in line:
                key, value = line.split("=", 1)
                got[key] = value
        assert got["pk_a"] == record["pk_a"]
        assert got["pk_b"] == record["pk_b"]
        assert got["shared_a"] == record["shared_a"]
        assert got["shared_b"] == record["shared_b"]


def test_typed_role_wrapper_rejects_swapped_key(tmp_path):
    source = r"""
    #include <cstdio>
    #include <string>
    #include <vector>
    #include "adapters/kex_adapter_interface.h"

    int main() {
      pqcfuzz_kex_adapter adapter = {};
      adapter.project_id = "sidh";
      adapter.implementation_id = "fake";
      adapter.algorithm = "SIDH-p434";
      adapter.pk_len = 330;
      adapter.sk_a_len = 27;
      adapter.sk_b_len = 28;
      adapter.shared_len = 110;
      std::vector<uint8_t> pk(adapter.pk_len, 0);
      pqcfuzz::KexRoleKey alice_key;
      alice_key.role = pqcfuzz::KexRole::kAlice;
      alice_key.bytes.assign(adapter.sk_a_len, 0x11);
      // A structurally A-role key must not route into derive_b.
      const pqcfuzz_status swapped = pqcfuzz::KexDeriveTyped(&adapter, pqcfuzz::KexRole::kBob,
                                                             pk.data(), pk.data(), alice_key);
      if (swapped != PQCFUZZ_INVALID_INPUT) { printf("swapped_accepted\n"); return 1; }
      pqcfuzz::KexRoleKey too_short;
      too_short.role = pqcfuzz::KexRole::kBob;
      too_short.bytes.assign(adapter.sk_b_len - 1, 0x22);
      if (pqcfuzz::KexDeriveTyped(&adapter, pqcfuzz::KexRole::kBob, pk.data(), pk.data(), too_short) !=
          PQCFUZZ_INVALID_INPUT) {
        printf("short_accepted\n");
        return 1;
      }
      printf("ok\n");
      return 0;
    }
    """
    from _falcon_util import compile_test_main

    binary = compile_test_main(
        tmp_path,
        source,
        extra_sources=["src/adapters/status.cc"],
    )
    result = subprocess.run([str(binary)], cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "ok"


FAKE_MAIN = r"""
#include <cstdio>
#include <string>
#include <vector>

#include "oracles/oracle_result.h"
#include "oracles/sidh_executor.h"

extern "C" const pqcfuzz_kex_adapter *pqcfuzz_fake_sidh_adapter();
extern "C" void pqcfuzz_fake_sidh_configure(const char *algorithm, size_t pk_len, size_t sk_a_len,
                                            size_t sk_b_len, size_t shared_len, size_t e3);
extern "C" void pqcfuzz_fake_sidh_set_broken(int broken);

int main(int argc, char **argv) {
  const char *algorithm = "SIDH-p434";
  pqcfuzz::SidhParams params;
  if (!pqcfuzz::GetSidhParams(algorithm, &params)) { printf("params\n"); return 1; }
  pqcfuzz_fake_sidh_configure(algorithm, params.pk_len, params.sk_a_len, params.sk_b_len, params.shared_len, params.e3);
  const bool broken = argc > 1 && std::string(argv[1]) == "broken";
  if (broken) pqcfuzz_fake_sidh_set_broken(1);
  const pqcfuzz_kex_adapter *adapter = pqcfuzz_fake_sidh_adapter();
  const char *healthy[] = {"sidh_agreement", "sidh_cross_agreement", "sidh_field_curve_checks",
                           "sidh_role_scalar_profile", "sidh_resources_rng"};
  for (const char *oracle_id : healthy) {
    pqcfuzz::SidhOracleConfig config;
    config.job_id = "pytest"; config.pair_id = "pytest"; config.algorithm = algorithm;
    config.oracle_id = oracle_id; config.params = params; config.left = adapter; config.right = adapter;
    config.exchange_contract.public_key_exchange = true;
    config.exchange_contract.peer_key_exchange = true;
    config.seed.assign(32, 0x42);
    pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteSidhOracle(config);
    if (broken) {
      if (oracle_id == std::string("sidh_agreement") && trace.findings.empty()) {
        printf("agreement_not_detected\n");
        return 1;
      }
      continue;
    }
    if (!trace.findings.empty()) {
      printf("finding:%s:%zu\n", oracle_id, trace.findings.size());
      return 1;
    }
  }
  printf("ok\n");
  return 0;
}
"""


def test_fake_adapter_health_and_agreement_detection(tmp_path):
    from _falcon_util import compile_test_main

    sources = [source for source in util.SIKE_CORE_SOURCES
               if "reference_adapter" not in source]
    binary = compile_test_main(
        tmp_path,
        FAKE_MAIN,
        extra_sources=sources + ["tests/fake_adapters/fake_sike_sidh.cc"],
    )
    result = subprocess.run([str(binary)], cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"
    result = subprocess.run([str(binary), "broken"], cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "src/reporting"))

from _test_sources import CORE_EXECUTOR_SOURCES  # noqa: E402
from replay.replay_one import maybe_write_finding, replay_equivalence_error, validate_replay_trace  # noqa: E402
from write_report import write_reports  # noqa: E402


NATIVE_CASE = r"""
#include <cstring>
#include <fstream>
#include <string>

#include "oracles/metamorphic_executor.h"

namespace {
pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x11, 1312);
  std::memset(sk, 0x22, 2560);
  return PQCFUZZ_OK;
}
pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                    const uint8_t *, const uint8_t *, size_t) {
  std::memset(sig, 0x33, 2420);
  *sig_len = 2420;
  return PQCFUZZ_OK;
}
pqcfuzz_status HealthyVerify(const uint8_t *sig, size_t sig_len, const uint8_t *, size_t,
                             const uint8_t *, const uint8_t *, size_t) {
  if (sig_len != 2420) return PQCFUZZ_REJECT;
  for (size_t i = 0; i < sig_len; ++i) {
    if (sig[i] != 0x33) return PQCFUZZ_REJECT;
  }
  return PQCFUZZ_OK;
}
pqcfuzz_status FaultyVerify(const uint8_t *, size_t, const uint8_t *, size_t,
                            const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_OK;
}
const pqcfuzz_sig_adapter kHealthy = {
    "fixture", "healthy_verify", "ML-DSA-44", 1312, 2560, 2420, 1, 0, 0,
    Keygen, Sign, HealthyVerify, nullptr, 1, 0, 0};
const pqcfuzz_sig_adapter kFaulty = {
    "fixture", "faulty_verify", "ML-DSA-44", 1312, 2560, 2420, 1, 0, 0,
    Keygen, Sign, FaultyVerify, nullptr, 1, 0, 0};
}  // namespace

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  const std::string mode = argv[1];
  if (mode != "healthy" && mode != "faulty") return 3;
  pqcfuzz::MetamorphicSigConfig config;
  config.job_id = "design_sig_verify_sig";
  config.pair_id = "design_single_target";
  config.algorithm = "ML-DSA-44";
  config.oracle_id = "sig_verify_sig";
  config.target = mode == "faulty" ? &kFaulty : &kHealthy;
  config.seed = {1, 2, 3};
  config.message = {'m'};
  config.mutation = {0, 0, 0, 0, 0};
  auto trace = pqcfuzz::ExecuteMetamorphicSigOracle(config);
  // The production fuzzer/replayer attaches adapter provenance after execution.
  trace.adapter_algorithm = config.target->algorithm;
  trace.project_id = config.target->project_id;
  trace.implementation_id = config.target->implementation_id;
  std::ofstream output(argv[2], std::ios::binary);
  if (!output) return 4;
  output << pqcfuzz::TraceToJson(trace);
  return output ? 0 : 5;
}
"""


def _compile_case(tmp_path: Path) -> Path:
    main = tmp_path / "design_slice.cc"
    binary = tmp_path / "design_slice"
    main.write_text(textwrap.dedent(NATIVE_CASE), encoding="utf-8")
    subprocess.run(
        [os.environ.get("CXX", "clang++"), "-std=c++17", "-O0", "-g", "-Isrc",
         str(main), *CORE_EXECUTOR_SOURCES, "-o", str(binary)],
        cwd=REPO_ROOT,
        check=True,
    )
    return binary


def _run_case(binary: Path, mode: str, output: Path) -> dict:
    subprocess.run([str(binary), mode, str(output)], cwd=REPO_ROOT, check=True)
    return json.loads(output.read_text(encoding="utf-8"))


@pytest.mark.skipif(shutil.which(os.environ.get("CXX", "clang++")) is None, reason="native C++ compiler unavailable")
def test_design_slice_oracle_trace_replay_and_report(tmp_path: Path) -> None:
    binary = _compile_case(tmp_path)
    healthy = _run_case(binary, "healthy", tmp_path / "healthy.json")
    original = _run_case(binary, "faulty", tmp_path / "faulty-original.json")
    replayed = _run_case(binary, "faulty", tmp_path / "faulty-replayed.json")

    # The healthy target is the negative control; the fault-injected target is
    # the sensitivity control. Both actually execute the signature oracle.
    assert healthy["oracle_id"] == original["oracle_id"] == "sig_verify_sig"
    assert healthy["findings"] == []
    assert healthy["baseline"]["accepted"] is True
    assert healthy["mutated"]["accepted"] is False
    assert original["disposition"] == "raw_candidate"
    assert original["baseline"]["accepted"] is True
    assert original["mutated"]["accepted"] is True
    assert original["baseline_target_entered"] and original["mutated_target_entered"]
    assert original["mutations"][0]["effective"] is True
    assert original["controls"]["positive_control"] and original["controls"]["negative_control"]
    assert original["findings"][0]["evidence_class"] == "NORMATIVE"
    assert original["findings"][0]["source_reference"]

    job = {"job_id": "design_sig_verify_sig", "pair_id": "design_single_target", "algorithm": "ML-DSA-44"}
    assert validate_replay_trace(original, job) == (True, "")
    assert replay_equivalence_error(original, replayed) == ""

    result_root = tmp_path / "campaign" / "workspace" / "results" / "sig"
    valid_artifact = result_root / "validated"
    invalid_artifact = result_root / "replay_mismatch"
    for artifact in (valid_artifact, invalid_artifact):
        artifact.mkdir(parents=True)
        (artifact / "oracle_trace.json").write_text(json.dumps(original) + "\n", encoding="utf-8")

    maybe_write_finding(valid_artifact, job, original, [str(binary), "faulty"])
    valid_finding = json.loads((valid_artifact / "finding.json").read_text(encoding="utf-8"))
    assert valid_finding["validation_state"] == "validated"

    changed = {**replayed, "mutated": {**replayed["mutated"], "accepted": False}}
    mismatch = replay_equivalence_error(original, changed)
    assert mismatch == "replay_mutated_observation_mismatch"
    maybe_write_finding(invalid_artifact, job, original, [str(binary), "faulty"], mismatch)
    invalid_finding = json.loads((invalid_artifact / "finding.json").read_text(encoding="utf-8"))
    assert invalid_finding["validation_state"] == "invalidated"

    report_root = tmp_path / "report"
    write_reports([tmp_path / "campaign"], report_root, {"json"}, trace_mode="all")
    findings = json.loads((report_root / "findings.json").read_text(encoding="utf-8"))
    diagnostics = json.loads((report_root / "diagnostics.json").read_text(encoding="utf-8"))
    assert len(findings) == len(diagnostics) == 1
    assert findings[0]["oracle_id"] == "sig_verify_sig"
    assert findings[0]["verdict"] == "NONCONFORMANT"
    assert diagnostics[0]["validation_failure_reason"] == mismatch



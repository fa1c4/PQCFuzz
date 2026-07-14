from __future__ import annotations

import csv
import json
import os
import subprocess
import textwrap
from pathlib import Path

from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[1]


COMMON_SOURCES = [
    "src/adapters/status.cc",
    "src/mutators/maul.cc",
    "src/mutators/ml_kem_layout.cc",
    "src/mutators/ml_kem_mutator.cc",
    "src/mutators/ml_dsa_layout.cc",
    "src/mutators/ml_dsa_mutator.cc",
    "src/mutators/slh_dsa_layout.cc",
    "src/mutators/slh_dsa_mutator.cc",
    "src/oracles/oracle_result.cc",
    "src/oracles/oracle_executor.cc",
    "src/triage/finding_writer.cc",
]


SOURCE = """
#include "triage/finding_writer.h"

#include <filesystem>
#include <string>
#include <vector>

namespace {

pqcfuzz::FindingArtifactInput MakeInput(const std::string &result_dir, const std::string &oracle_id, int seed) {
  pqcfuzz::FindingArtifactInput input;
  input.job_id = "writer_test";
  input.pair_id = "writer_pair";
  input.algorithm = "ML-KEM-768";
  input.primitive = "kem";
  input.oracle_id = oracle_id;
  input.result_dir = result_dir;
  input.generated_config_json = "{}\\n";
  input.structured_input = {static_cast<uint8_t>(seed), 2, 3};
  input.trace.oracle_suite = "metamorphic";
  input.trace.relation_mode = "single-target";
  input.trace.job_id = input.job_id;
  input.trace.pair_id = input.pair_id;
  input.trace.algorithm = input.algorithm;
  input.trace.oracle_id = oracle_id;
  input.trace.field = "rng";
  input.trace.expected_relation = "EXPECT_DIFFERENT";
  input.trace.observed_relation = "OBSERVED_EQUAL";
  input.trace.finding_class = "malleability";
  input.trace.finding_subclass = oracle_id == "kem_keygen_badrng" ? "keygen_rng_ignored" : "encaps_rng_ignored";
  input.trace.baseline.status = PQCFUZZ_OK;
  input.trace.mutated.status = PQCFUZZ_OK;
  input.trace.findings.push_back({"malleability", input.trace.finding_subclass, "malleability"});
  return input;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    return 2;
  }
  std::filesystem::path result_dir = std::filesystem::path(argv[1]) / "results" / "kem";
  std::string artifact_dir;
  std::string error;
  if (argc == 3 && std::string(argv[2]) == "empty") {
    auto empty = MakeInput(result_dir.string(), "kem_keygen_badrng", 7);
    empty.trace.findings.clear();
    return !pqcfuzz::WriteFindingArtifacts(empty, &artifact_dir, &error) && error == "no_security_evidence" ? 0 : 7;
  }
  if (argc == 3 && std::string(argv[2]) == "json-escape") {
    auto escaped = MakeInput(result_dir.string(), "kem_keygen_badrng", 7);
    escaped.job_id = "writer\\tjob\\rcontrol";
    escaped.pair_id = std::string("writer_pair_") + static_cast<char>(1);
    escaped.trace.job_id = escaped.job_id;
    escaped.trace.pair_id = escaped.pair_id;
    escaped.trace.findings[0].summary = std::string("summary_") + static_cast<char>(2);
    if (!pqcfuzz::WriteFindingArtifacts(escaped, &artifact_dir, &error)) return 6;
    return 0;
  }
  auto first = MakeInput(result_dir.string(), "kem_keygen_badrng", 1);
  auto duplicate = MakeInput(result_dir.string(), "kem_keygen_badrng", 9);
  auto different = MakeInput(result_dir.string(), "kem_encaps_badrng", 5);
  if (!pqcfuzz::WriteFindingArtifacts(first, &artifact_dir, &error)) return 3;
  if (!pqcfuzz::WriteFindingArtifacts(duplicate, &artifact_dir, &error)) return 4;
  if (!pqcfuzz::WriteFindingArtifacts(different, &artifact_dir, &error)) return 5;
  return 0;
}
"""


def compile_case(tmp_path: Path, *, save_mode: str = "grouped") -> Path:
    main = tmp_path / "main.cc"
    binary = tmp_path / f"case-{save_mode}"
    main.write_text(textwrap.dedent(SOURCE), encoding="utf-8")
    cxx = os.environ.get("CXX", "clang++")
    cmd = [
        cxx,
        "-std=c++17",
        "-O0",
        "-g",
        "-Isrc",
        f'-DPQCFUZZ_FINDING_SAVE_MODE="{save_mode}"',
        "-DPQCFUZZ_MAX_FINDING_EXEMPLARS_PER_GROUP=1",
        str(main),
        *COMMON_SOURCES,
        "-o",
        str(binary),
    ]
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    return binary


def read_counts(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def artifact_dirs(root: Path) -> list[Path]:
    return sorted(path for path in (root / "results" / "kem").iterdir() if path.is_dir())


def test_grouped_writer_keeps_one_exemplar_per_group_and_counts_raw_hits(tmp_path: Path) -> None:
    binary = compile_case(tmp_path, save_mode="grouped")
    run_root = tmp_path / "grouped"

    subprocess.run([str(binary), str(run_root)], cwd=REPO_ROOT, check=True)

    dirs = artifact_dirs(run_root)
    assert len(dirs) == 2
    assert all((path / "finding.json").exists() for path in dirs)
    assert all((path / "oracle_trace.json").exists() for path in dirs)
    finding = json.loads((dirs[0] / "finding.json").read_text(encoding="utf-8"))
    trace = json.loads((dirs[0] / "oracle_trace.json").read_text(encoding="utf-8"))
    trace_schema = json.loads((REPO_ROOT / "src/schemas/oracle_trace.schema.json").read_text(encoding="utf-8"))
    finding_schema = json.loads((REPO_ROOT / "src/schemas/finding.schema.json").read_text(encoding="utf-8"))
    assert trace["version"] == trace["oracle_semantics_version"] == 3
    assert trace["disposition"] == "raw_candidate"
    assert "valid_setup" not in trace
    assert finding["version"] == finding["oracle_semantics_version"] == 3
    assert finding["validation_state"] == "raw"
    assert not list(Draft202012Validator(trace_schema).iter_errors(trace))
    assert not list(Draft202012Validator(finding_schema).iter_errors(finding))
    counts = sorted(read_counts(run_root / "results" / "kem" / "finding_counts.tsv"), key=lambda row: row["finding_subclass"])
    assert [row["count"] for row in counts] == ["1", "2"]
    assert [row["finding_subclass"] for row in counts] == ["encaps_rng_ignored", "keygen_rng_ignored"]
    assert counts[0]["algorithm"] == "ML-KEM-768"
    assert counts[0]["primitive"] == "kem"
    assert counts[0]["oracle_suite"] == "metamorphic"
    assert counts[0]["relation_mode"] == "single-target"
    assert counts[0]["expected_relation"] == "EXPECT_DIFFERENT"
    assert counts[0]["observed_relation"] == "OBSERVED_EQUAL"
    assert counts[0]["baseline_status"] == "OK"
    assert counts[0]["mutated_status"] == "OK"

    run_sh = (dirs[0] / "poc" / "run.sh").read_text(encoding="utf-8")
    readme = (dirs[0] / "poc" / "README.md").read_text(encoding="utf-8")
    assert 'ARTIFACT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"' in run_sh
    assert '--input "$ARTIFACT_DIR/structured_input.bin"' in run_sh
    assert "--input structured_input.bin" not in run_sh
    assert "repository root" in readme


def test_all_writer_keeps_per_input_artifacts_without_counter_file(tmp_path: Path) -> None:
    binary = compile_case(tmp_path, save_mode="all")
    run_root = tmp_path / "all"

    subprocess.run([str(binary), str(run_root)], cwd=REPO_ROOT, check=True)

    assert len(artifact_dirs(run_root)) == 3
    assert not (run_root / "results" / "kem" / "finding_counts.tsv").exists()


def test_grouped_writer_propagates_counter_write_failure(tmp_path: Path) -> None:
    binary = compile_case(tmp_path, save_mode="grouped")
    run_root = tmp_path / "counter-failure"
    blocker = run_root / "results" / "kem" / "finding_counts.tsv.tmp"
    blocker.mkdir(parents=True)

    result = subprocess.run([str(binary), str(run_root)], cwd=REPO_ROOT)

    assert result.returncode == 3
    assert not (run_root / "results" / "kem" / "finding_counts.tsv").exists()


def test_writer_escapes_json_control_characters(tmp_path: Path) -> None:
    binary = compile_case(tmp_path, save_mode="grouped")
    run_root = tmp_path / "json-escape"

    subprocess.run([str(binary), str(run_root), "json-escape"], cwd=REPO_ROOT, check=True)

    [artifact] = artifact_dirs(run_root)
    finding = json.loads((artifact / "finding.json").read_text(encoding="utf-8"))
    trace = json.loads((artifact / "oracle_trace.json").read_text(encoding="utf-8"))
    assert finding["job_id"] == "writer\tjob\rcontrol"
    assert finding["pair_id"] == "writer_pair_\x01"
    assert trace["findings"][0]["summary"] == "summary_\x02"


def test_writer_rejects_empty_evidence(tmp_path: Path) -> None:
    binary = compile_case(tmp_path, save_mode="grouped")

    subprocess.run([str(binary), str(tmp_path / "empty"), "empty"], cwd=REPO_ROOT, check=True)

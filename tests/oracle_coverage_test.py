from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_oracle_coverage_records_execution_and_interventions(tmp_path: Path) -> None:
    main = tmp_path / "main.cc"
    binary = tmp_path / "coverage_case"
    result_dir = tmp_path / "results"
    main.write_text(
        textwrap.dedent(
            """
            #include <string>
            #include "triage/oracle_coverage.h"

            int main(int argc, char **argv) {
              if (argc != 2) return 1;
              const std::string result_dir(argv[1]);
              pqcfuzz::RecordEnvelopeParseRejected(result_dir);
              pqcfuzz::RecordEnvelopeParsed(result_dir);
              pqcfuzz::RecordAlgorithmRejected(result_dir);
              pqcfuzz::RecordRoutingRejected(result_dir);
              pqcfuzz::KEMOracleTrace trace;
              trace.oracle_id = "kem_encaps_badrng";
              trace.valid_setup = true;
              trace.relation_evaluable = true;
              trace.intervention_effective = true;
              pqcfuzz::RngInterventionTrace rng;
              rng.tapes_distinct = true;
              rng.baseline_override_active = true;
              rng.mutated_override_active = true;
              rng.baseline_bytes_consumed = 8;
              rng.mutated_bytes_consumed = 8;
              trace.rng_interventions.push_back(rng);
              trace.findings.push_back({"malleability", "rng", "test"});
              pqcfuzz::RecordOracleTrace(result_dir, trace);
              return 0;
            }
            """
        ),
        encoding="utf-8",
    )
    command = [
        os.environ.get("CXX", "clang++"),
        "-std=c++17",
        "-Isrc",
        str(main),
        "src/triage/oracle_coverage.cc",
        "-o",
        str(binary),
    ]
    subprocess.run(command, cwd=REPO_ROOT, check=True)
    subprocess.run([str(binary), str(result_dir)], cwd=REPO_ROOT, check=True)

    coverage = json.loads((result_dir / "oracle_coverage.json").read_text(encoding="utf-8"))
    assert coverage["schema_version"] == 1
    assert coverage["totals"] == {
        "inputs": 2,
        "parse_rejected": 1,
        "parsed": 1,
        "algorithm_rejected": 1,
        "routing_rejected": 1,
        "oracle_invocations": 1,
        "valid_setup": 1,
        "relation_evaluable": 1,
        "intervention_effective": 1,
        "rng_intervention_observed": 1,
        "skipped": 0,
        "unsupported": 0,
        "finding_records": 1,
    }
    assert coverage["oracles"]["kem_encaps_badrng"]["oracle_invocations"] == 1

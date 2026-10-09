"""X05/P1 submitted KAT relation for QILIN-512."""
import json
from pathlib import Path


_CORPUS = json.loads((Path(__file__).resolve().parents[1] / "data/kat_512_subset.json").read_text())
_RECORDS = {item["source_record_index"]: item for item in _CORPUS["records"]}
_BACKENDS = ('reference', 'optimized')
_OUTPUT_BYTES = 64


def _matches(vector_input, expected, index):
    if not isinstance(vector_input, dict) or not isinstance(index, int) or index not in _RECORDS:
        return False
    record = _RECORDS[index]
    return (vector_input.get("message_hex") == record["message_hex"] and
            vector_input.get("message_bits") == record["message_bits"] and
            expected == record["digest_hex"])


def evaluate(case, baseline, mutated):
    baseline_input = case.get("baseline", {})
    mutated_input = case.get("mutated", {})
    provenance = case.get("kat_provenance", {})
    if not isinstance(baseline_input, dict) or not isinstance(mutated_input, dict):
        baseline_input, mutated_input = {}, {}
    if not isinstance(provenance, dict):
        provenance = {}
    applicable = (baseline_input.get("backend") == mutated_input.get("backend") and
                  baseline_input.get("backend") in _BACKENDS and
                  baseline_input.get("digest_bits") == mutated_input.get("digest_bits") == 512 and
                  provenance.get("path") == _CORPUS["source_path"] and
                  provenance.get("sha256") == _CORPUS["source_sha256"] and
                  _matches(baseline_input, case.get("baseline_expected"),
                           provenance.get("baseline_record_index")) and
                  _matches(mutated_input, case.get("mutated_expected"),
                           provenance.get("mutated_record_index")))
    observable = (baseline.get("reached") is True and mutated.get("reached") is True and
                  baseline.get("status") == mutated.get("status") == "ok" and
                  baseline.get("output_length") == mutated.get("output_length") == _OUTPUT_BYTES and
                  isinstance(baseline.get("output"), str) and
                  isinstance(mutated.get("output"), str) and
                  len(baseline["output"]) == len(mutated["output"]) == 2 * _OUTPUT_BYTES)
    holds = (baseline.get("output") == case.get("baseline_expected") and
             mutated.get("output") == case.get("mutated_expected"))
    return {"applicable": bool(applicable), "observable": bool(observable),
            "holds": bool(holds),
            "expected": "each exact submitted KAT row matches its own digest",
            "actual": {"baseline": baseline.get("output"), "mutated": mutated.get("output"),
                       "baseline_kat": case.get("baseline_expected"),
                       "mutated_kat": case.get("mutated_expected")},
            "explanation": "two source-pinned submitted KAT records on one backend"}


def fault_observation(mutated):
    altered = dict(mutated)
    output = altered.get("output")
    if isinstance(output, str) and len(output) == 2 * _OUTPUT_BYTES:
        altered["output"] = f"{int(output[:2], 16) ^ 1:02x}" + output[2:]
    return altered

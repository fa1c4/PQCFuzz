"""X05/P4 prefix relation for submitted Litchi-XOF output construction."""
import json
from pathlib import Path


_CORPUS = json.loads((Path(__file__).resolve().parents[1] / "data/kat_1024_subset.json").read_text())
_ROWS = {row["source_record_index"]: row for row in _CORPUS["records"]}


def evaluate(case, baseline, mutated):
    left, right = case.get("baseline"), case.get("mutated")
    if not isinstance(left, dict) or not isinstance(right, dict):
        left, right = {}, {}
    short, long = left.get("out_bits"), right.get("out_bits")
    provenance = case.get("submitted_kat_provenance")
    digest = case.get("submitted_kat_digest")
    kat_valid = digest is None
    if digest is not None and isinstance(provenance, dict):
        row = _ROWS.get(provenance.get("record_index"))
        kat_valid = (row is not None and provenance.get("path") == _CORPUS["source_path"] and
                     provenance.get("sha256") == _CORPUS["source_sha256"] and
                     row["message_hex"] == left.get("message_hex") and
                     row["message_bits"] == left.get("message_bits") and
                     digest == row["digest_hex"] and long == 1024)
    applicable = (left.get("backend") == right.get("backend") and
                  left.get("backend") in ("core", "wrapper") and
                  left.get("message_hex") == right.get("message_hex") and
                  left.get("message_bits") == right.get("message_bits") and
                  (short, long) in ((512, 768), (512, 1024), (768, 1024)) and kat_valid)
    observable = (baseline.get("reached") is True and mutated.get("reached") is True and
                  baseline.get("status") == mutated.get("status") == "ok" and
                  baseline.get("output_length") == short // 8 and
                  mutated.get("output_length") == long // 8 and
                  isinstance(baseline.get("output"), str) and
                  isinstance(mutated.get("output"), str) and
                  len(baseline["output"]) == short // 4 and
                  len(mutated["output"]) == long // 4)
    holds = (baseline.get("output") == (mutated.get("output") or "")[:short // 4] and
             (digest is None or mutated.get("output") == digest))
    return {"applicable": bool(applicable), "observable": bool(observable),
            "holds": bool(holds),
            "expected": "short requested XOF output equals the long output prefix",
            "actual": {"short": baseline.get("output"),
                       "long_prefix": (mutated.get("output") or "")[:short // 4],
                       "submitted_kat": digest},
            "explanation": "same bitstring and submitted XOF path under two output requests"}


def fault_observation(mutated):
    altered = dict(mutated)
    output = altered.get("output")
    if isinstance(output, str) and len(output) >= 2:
        altered["output"] = f"{int(output[:2], 16) ^ 1:02x}" + output[2:]
    return altered

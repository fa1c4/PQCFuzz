"""Evaluate exact submitted vector validity or shared-secret bytes."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "PolarKEM-256"
PRIMITIVE = "kem"

def evaluate(case, baseline, mutated):
    cfg = DATA[INSTANCE]
    left, right = case.get("baseline", {}), case.get("mutated", {})
    provenance = case.get("kat_provenance", {})
    operation = "verify" if PRIMITIVE == "signature" else "decapsulate"
    applicable = (isinstance(left, dict) and isinstance(right, dict) and
                  left.get("instance") == right.get("instance") == INSTANCE and
                  left.get("operation") == right.get("operation") == operation and
                  provenance.get("path") == cfg["kat"] and
                  provenance.get("sha256") == cfg["kat_sha256"] and
                  all(isinstance(x.get("record_index"), int) and
                      not isinstance(x.get("record_index"), bool) and
                      0 <= x["record_index"] < 10 for x in (left, right)))
    observations = (baseline, mutated)
    expected = ("accepted", "accepted") if PRIMITIVE == "signature" else tuple(
        cfg["records"][x["record_index"]]["expected_ss"] for x in (left, right)) if applicable else (None, None)
    output_length = 1 if PRIMITIVE == "signature" else len(expected[0]) // 2 if applicable else 0
    observable = all(isinstance(o, dict) and o.get("reached") is True and
                     o.get("status") == "ok" and o.get("output_length") == output_length and
                     (PRIMITIVE == "signature" or o.get("guard_modified") is False)
                     for o in observations)
    holds = observable and tuple(o.get("output") for o in observations) == expected
    return {"applicable": bool(applicable), "observable": bool(observable), "holds": bool(holds),
            "expected": expected, "actual": tuple(o.get("output") for o in observations),
            "explanation": "exact indexed submitted-KAT API consistency"}

def fault_observation(mutated):
    altered = dict(mutated)
    if PRIMITIVE == "signature":
        altered["output"] = "rejected"
    elif isinstance(altered.get("output"), str) and len(altered["output"]) >= 2:
        value = altered["output"]
        altered["output"] = f"{int(value[:2], 16) ^ 1:02x}" + value[2:]
    return altered

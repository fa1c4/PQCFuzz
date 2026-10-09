"""Compare both KEX roles and the exact submitted session key."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "ADKEX-128"

def evaluate(case, baseline, mutated):
    cfg = DATA[INSTANCE]
    left, right = case.get("baseline", {}), case.get("mutated", {})
    provenance = case.get("kat_provenance", {})
    applicable = (isinstance(left, dict) and isinstance(right, dict) and
                  left.get("instance") == right.get("instance") == INSTANCE and
                  left.get("operation") == right.get("operation") == "derive_roles" and
                  provenance.get("path") == cfg["kat"] and
                  provenance.get("sha256") == cfg["kat_sha256"] and
                  all(isinstance(x.get("record_index"), int) and
                      not isinstance(x.get("record_index"), bool) and
                      0 <= x["record_index"] < 10 for x in (left, right)))
    expected = tuple(cfg["records"][x["record_index"]]["expected_ss"]
                     for x in (left, right)) if applicable else (None, None)
    observations = (baseline, mutated)
    observable = all(isinstance(o, dict) and o.get("reached") is True and
                     o.get("status") == "ok" and
                     o.get("output_length") == len(want) // 2 and
                     o.get("guard_modified") is False and
                     o.get("passes") == cfg["passes"] for o, want in zip(observations, expected)) if applicable else False
    holds = observable and all(o.get("output") == o.get("peer_output") == want
                               for o, want in zip(observations, expected))
    return {"applicable": bool(applicable), "observable": bool(observable), "holds": bool(holds),
            "expected": expected,
            "actual": tuple({"a": o.get("output"), "b": o.get("peer_output")} for o in observations),
            "explanation": "source-pinned matching-session final-role agreement"}

def fault_observation(mutated):
    altered = dict(mutated)
    value = altered.get("peer_output")
    if isinstance(value, str) and len(value) >= 2:
        altered["peer_output"] = f"{int(value[:2], 16) ^ 1:02x}" + value[2:]
    return altered

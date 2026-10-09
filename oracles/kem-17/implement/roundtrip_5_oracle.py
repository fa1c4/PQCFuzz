"""Check honest keygen, encapsulation and decapsulation agreement."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "hep-qc-5"

def evaluate(case, baseline, mutated):
    cfg = DATA[INSTANCE]
    left, right = case.get("baseline", {}), case.get("mutated", {})
    provenance = case.get("kat_provenance", {})
    applicable = (isinstance(left, dict) and isinstance(right, dict) and
                  all(x.get("instance") == INSTANCE and x.get("operation") == "roundtrip" and
                      isinstance(x.get("record_index"), int) and
                      not isinstance(x.get("record_index"), bool) and
                      0 <= x["record_index"] < 10 for x in (left, right)) and
                  provenance.get("path") == cfg["kat"] and
                  provenance.get("sha256") == cfg["kat_sha256"])
    length = cfg["records"][0]["SS_Len"]
    observations = (baseline, mutated)
    observable = all(isinstance(o, dict) and o.get("reached") is True and
                     o.get("status") == "ok" and o.get("guard_modified") is False and
                     o.get("output_length") == o.get("peer_output_length") == length and
                     o.get("return_codes") == [0, 0, 0] and
                     isinstance(o.get("output"), str) and len(o["output"]) == length * 2 and
                     isinstance(o.get("peer_output"), str) and len(o["peer_output"]) == length * 2
                     for o in observations)
    holds = observable and all(o["output"] == o["peer_output"] for o in observations)
    return {"applicable": bool(applicable), "observable": bool(observable), "holds": bool(holds),
            "expected": "encapsulated secret equals decapsulated secret for both public seeds",
            "actual": [{"enc": o.get("output"), "dec": o.get("peer_output")}
                       for o in observations],
            "explanation": "honest keygen/enc/dec calls with source-pinned public seed"}

def fault_observation(mutated):
    altered = dict(mutated)
    value = altered.get("peer_output")
    if isinstance(value, str) and len(value) >= 2:
        altered["peer_output"] = f"{int(value[:2], 16) ^ 1:02x}" + value[2:]
    return altered

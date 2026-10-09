"""Check fresh signatures under submitted honest keypairs."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "VDOO-512"

def evaluate(case, baseline, mutated):
    cfg = DATA[INSTANCE]
    left, right = case.get("baseline", {}), case.get("mutated", {})
    provenance = case.get("kat_provenance", {})
    applicable = (isinstance(left, dict) and isinstance(right, dict) and
                  all(x.get("instance") == INSTANCE and x.get("operation") == "sign_roundtrip" and
                      isinstance(x.get("record_index"), int) and
                      not isinstance(x.get("record_index"), bool) and
                      0 <= x["record_index"] < 10 for x in (left, right)) and
                  provenance.get("path") == cfg["kat"] and
                  provenance.get("sha256") == cfg["kat_sha256"])
    observations = (baseline, mutated)
    size = cfg["records"][0]["Sn_Len"]
    observable = all(isinstance(o, dict) and o.get("reached") is True and
                     o.get("status") in ("ok", "reject") and
                     o.get("guard_modified") is False and
                     o.get("output_length") == size and o.get("sign_code") == 0 and
                     isinstance(o.get("verify_code"), int) and
                     isinstance(o.get("signature_sha256"), str) and
                     len(o["signature_sha256"]) == 64 for o in observations)
    holds = observable and all(o["verify_code"] == 0 and o.get("output") == "accepted"
                               for o in observations)
    return {"applicable": bool(applicable), "observable": bool(observable), "holds": bool(holds),
            "expected": "both freshly generated signatures verify",
            "actual": [{"verify_code": o.get("verify_code"), "output": o.get("output")}
                       for o in observations],
            "explanation": "honest source-pinned KAT keypairs with newly signed messages"}

def fault_observation(mutated):
    altered = dict(mutated)
    altered["verify_code"] = -1
    altered["output"] = "rejected"
    return altered

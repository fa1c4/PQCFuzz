"""Check that an indexed VDOO signature rejects a changed message."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "VDOO-512"

def evaluate(case, baseline, mutated):
    cfg = DATA[INSTANCE]
    left, right = case.get("baseline", {}), case.get("mutated", {})
    provenance = case.get("kat_provenance", {})
    index = left.get("record_index") if isinstance(left, dict) else None
    applicable = (isinstance(left, dict) and isinstance(right, dict) and
                  left.get("instance") == right.get("instance") == INSTANCE and
                  left.get("operation") == right.get("operation") == "verify" and
                  left.get("message_flip_bit") == 0 and right.get("message_flip_bit") in (0, 1) and
                  index == right.get("record_index") and isinstance(index, int) and
                  not isinstance(index, bool) and 0 <= index < 10 and
                  provenance.get("signed_record_index") == index and
                  provenance.get("path") == cfg["kat"] and
                  provenance.get("sha256") == cfg["kat_sha256"])
    observable = (isinstance(baseline, dict) and isinstance(mutated, dict) and
                  baseline.get("reached") is True and mutated.get("reached") is True and
                  baseline.get("status") == "ok" and mutated.get("status") in ("ok", "reject") and
                  baseline.get("output_length") == mutated.get("output_length") == 1)
    holds = (baseline.get("output") == "accepted" and mutated.get("output") == "rejected")
    return {"applicable": bool(applicable), "observable": bool(observable), "holds": bool(holds),
            "expected": {"signed_message": "accepted", "changed_message": "rejected"},
            "actual": {"signed_message": baseline.get("output"),
                       "changed_message": mutated.get("output")},
            "explanation": "same public key/signature with a new message is a concrete freshness witness"}

def fault_observation(mutated):
    altered = dict(mutated)
    altered["output"] = "accepted"
    return altered

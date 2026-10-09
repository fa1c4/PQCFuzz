"""Pair source-pinned public signing records."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "VDOO-512"

def pair(a, b):
    cfg = DATA[INSTANCE]
    left = {"instance": INSTANCE, "operation": "sign_roundtrip", "record_index": a}
    right = {"instance": INSTANCE, "operation": "sign_roundtrip", "record_index": b}
    return {"baseline": left, "mutated": right,
            "kat_provenance": {"path": cfg["kat"], "sha256": cfg["kat_sha256"]},
            "changed_fields": ["record_index"] if a != b else [],
            "intervention": "select another submitted key/message/seed record" if a != b else "none",
            "effective": a != b,
            "effectiveness_evidence": {"distinct_record_indices": a != b,
                                       "same_instance_and_operation": True}}

def generate(seed, iteration):
    return pair((seed + iteration) % 10, (seed + iteration + 1) % 10)

def smoke_cases():
    return {"positive": pair(0, 1), "negative": pair(0, 0)}

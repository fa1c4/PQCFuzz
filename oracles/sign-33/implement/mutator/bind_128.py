"""Mutate one message bit while retaining the signed KAT pair."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "VDOO-128"

def pair(index, flip):
    cfg = DATA[INSTANCE]
    baseline = {"instance": INSTANCE, "operation": "verify", "record_index": index,
                "message_flip_bit": 0}
    mutated = dict(baseline, message_flip_bit=flip)
    return {"baseline": baseline, "mutated": mutated,
            "kat_provenance": {"path": cfg["kat"], "sha256": cfg["kat_sha256"],
                               "signed_record_index": index},
            "changed_fields": ["message_flip_bit"] if flip else [],
            "intervention": "flip the first message bit with public key and signature fixed" if flip else "none",
            "effective": bool(flip),
            "effectiveness_evidence": {"message_bit_changed": bool(flip),
                                       "same_public_key_signature_record": True}}

def generate(seed, iteration):
    return pair((seed + iteration) % 10, 1)

def smoke_cases():
    return {"positive": pair(0, 1), "negative": pair(0, 0)}

#!/usr/bin/env python3
"""Add source-backed VDOO message-binding P5 oracles to all three instances."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = "sign-33"
PACKAGE = ROOT / "oracles" / TARGET
SPEC = ROOT / "oracles/spec/sign-33-VDOO.md"

MUTATOR = '''"""Mutate one message bit while retaining the signed KAT pair."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "__INSTANCE__"

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
'''

ORACLE = '''"""Check that an indexed VDOO signature rejects a changed message."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "__INSTANCE__"

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
'''


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def main():
    spec = SPEC.read_text()
    manifest_path = PACKAGE / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    adapter_path = PACKAGE / "implement/adapter.py"
    adapter = adapter_path.read_text()
    old = '        message, mlen = buffer(row["M"])\n'
    new = '''        message, mlen = buffer(row["M"])
        flip = structured_input.get("message_flip_bit", 0)
        if flip not in (0, 1) or isinstance(flip, bool):
            return invalid("unsupported message mutation")
        if flip:
            if mlen == 0:
                return invalid("cannot flip empty message")
            changed = bytearray(bytes.fromhex(row["M"]))
            changed[0] ^= 1
            message = ctypes.create_string_buffer(bytes(changed))
'''
    if old not in adapter and new not in adapter:
        raise SystemExit("VDOO adapter insertion point changed")
    if old in adapter:
        adapter = adapter.replace(old, new)
        write(adapter_path, adapter)
    for instance_obj in manifest["instances"]:
        instance = instance_obj["parameter_set"]
        level = instance.split("-")[1]
        tag = f"VDOO{level}"
        claim, oid = f"{tag}-V", f"{tag}-BIND-01"
        if f"## {claim} —" not in spec:
            spec += f'''
## {claim} — {instance} signed-message acceptance boundary

- Source locator: `third_party/sign-33/specification.pdf`, PDF p. 10 Algorithm 5 (verification), p. 19 §5.7 (EUF-CMA claim); submitted `Test_Vectors/KAT_SIG_{instance}.txt` signed-message records.
- Class: proposed verification rule and public submitted-vector observation.
- Scope: Exact `{instance}` public KAT key/signature/message triple, changing only the first bit of a nonempty message.
- Claim: The archived signature verifies on its archived message; the same signature on a different message should reject, absent a concrete collision/forgery witness.
- Preconditions: One indexed KAT record, same public key/signature, nonempty message, exactly one changed message bit, actual `sig_verify` calls.
- Extraction inference/ambiguity: Algorithm 5 compares the signature's public-map value with the hash of message and salt; acceptance after mutation would need cryptographic review, not automatic normative promotion.
- Limitations: A finite rejection run does not prove EUF-CMA security; only one altered bit and public vectors are tested.
'''
        design = PACKAGE / f"design/VDOO/sig_verify/{oid}.md"
        write(design, f'''# {oid}: VDOO exact signed-message binding

- Claim: `{claim}` in `oracles/spec/sign-33-VDOO.md`; PDF p. 10 Algorithm 5 and p. 19 §5.7.
- Property: S01 version 1, EUF-CMA witness boundary. Pattern: P5 version 1, acceptance set/freshness.
- Extraction status: draft (`unverified_spec`), candidate-only.
- Scope/preconditions: `{instance}` `sig_verify`, exact public KAT key/signature/signed-message history, nonempty message and one effective bit flip.
- Baseline: Verify the archived signature on its recorded message.
- Intervention: Change only the first message bit; keep key, signature and instance fixed. Paired mutator records effectiveness and signed-record index.
- Expected relation: Original accepted, changed-message signature rejected.
- Observables: Two actual API calls, return status, normalized acceptance and archived vector identity.
- Positive control: Valid original and changed message reach the verifier and show accept/reject.
- Negative control: No bit flip is ineffective and `inconclusive`.
- Fault control: Replace observed reject with accept after the real call; predicate must detect it.
- Required capabilities: indexed_public_vector, message_mutation, acceptance_status.
- Predicate: Require exact provenance, valid baseline, reached calls and an effective mutation, then compare accepted/rejected status; failure is a candidate witness only.
- Paired mutator: `implement/mutator/bind_{level}.py`.
- Limitations: One public test signature and one-bit change do not establish unforgeability or uniqueness of accepted encodings.
''')
        write(PACKAGE / f"implement/mutator/bind_{level}.py", MUTATOR.replace("__INSTANCE__", instance))
        write(PACKAGE / f"implement/bind_{level}_oracle.py", ORACLE.replace("__INSTANCE__", instance))
        instance_obj["capabilities"].update(message_mutation=True, acceptance_status=True)
        if not any(oracle["id"] == oid for oracle in instance_obj["oracles"]):
            instance_obj["oracles"].append({"id": oid, "version": 1, "claim": claim,
                "property": "S01", "property_version": 1, "pattern": "P5", "pattern_version": 1,
                "design": f"design/VDOO/sig_verify/{oid}.md",
                "oracle": f"implement/bind_{level}_oracle.py",
                "mutator": f"implement/mutator/bind_{level}.py",
                "required_capabilities": ["indexed_public_vector", "message_mutation", "acceptance_status"],
                "applicable_primitives": ["signature"]})
    write(SPEC, spec)
    manifest["spec_sha256"] = hashlib.sha256(SPEC.read_bytes()).hexdigest()
    write(manifest_path, json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"target": TARGET, "instances": len(manifest["instances"]),
                      "added_oracle": "P5 signed-message binding"}))


if __name__ == "__main__":
    main()

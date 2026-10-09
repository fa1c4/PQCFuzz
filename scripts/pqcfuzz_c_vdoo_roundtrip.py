#!/usr/bin/env python3
"""Register VDOO P2 fresh-signature round-trip oracles for all three instances."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "oracles/sign-33"
SPEC = ROOT / "oracles/spec/sign-33-VDOO.md"
DATA = json.loads((PACKAGE / "data/instances.json").read_text())

MUTATOR = '''"""Pair source-pinned public signing records."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "__INSTANCE__"

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
'''

ORACLE = '''"""Check fresh signatures under submitted honest keypairs."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "__INSTANCE__"

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
'''


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main():
    spec = SPEC.read_text(encoding="utf-8")
    spec = spec.replace("This document covers public submitted KAT records only, under the exact\n`sig_verify` API.",
                        "This document covers public submitted KAT verification and fresh signing\nunder the exact `sig_sign` and `sig_verify` APIs.")
    manifest_path = PACKAGE / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for obj in manifest["instances"]:
        instance = obj["parameter_set"]
        level = instance.rsplit("-", 1)[1]
        tag = f"VDOO{level}"
        claim, oid = f"{tag}-R", f"{tag}-ROUNDTRIP-01"
        if f"## {claim} —" not in spec:
            spec += f'''
## {claim} — {instance} fresh signing under submitted honest keypair

- Source locator: `third_party/sign-33/specification.pdf`, PDF p. 10 Algorithms 4–5 and p. 23 §7.5–7.7; archived `{DATA[instance]["kat"]}`, SHA-256 `{DATA[instance]["kat_sha256"]}`.
- Class: signature correctness relation from PDF, with public submitted key/message/seed controls.
- Scope: `{instance}` actual `sig_sign` then `sig_verify` on ten indexed submitted keypairs and their recorded messages; the keypairs were produced by the submitted KAT driver using `sig_keygen`.
- Claim: A newly generated signature on the matching message verifies under its matching honest public key.
- Preconditions: Exact source/PDF/KAT identity, matching parameter/lengths, public KAT keypair, nonempty message, seeded signing RNG and successful `sig_sign`.
- Extraction inference/ambiguity: This oracle does not assert that the newly generated signature matches the archived signature bytes; seed controls the implementation RNG but signing may consume it differently.
- Limitations: Finite valid-message round trips do not prove unforgeability, signing reliability or malformed-signature rejection.
'''
        design = PACKAGE / f"design/VDOO/sig_verify/{oid}.md"
        write(design, f'''# {oid}: VDOO fresh signature round trip

- Claim: `{claim}` in `oracles/spec/sign-33-VDOO.md`; PDF p. 10 Algorithms 4–5 and p. 23 §7.5–7.7.
- Property: S03 version 1, signature correctness. Pattern: P2 version 1, sign/verify inverse relation.
- Extraction status: draft (`unverified_spec`), candidate-only.
- Scope/preconditions: `{instance}` submitted KAT keypair generated by the submitter's `sig_keygen` driver, recorded nonempty message and public seed; exact `sig_sign`/`sig_verify` API lengths.
- Baseline: Seed `init_randombytes`, sign the recorded message and verify under its recorded public key.
- Intervention: Select a different indexed public key/message/seed record and repeat the sign/verify relation.
- Expected relation: Both freshly generated signatures verify, with successful signing, exact output length and untouched signature guard.
- Observables: Actual API return codes, verification status, signature digest, seed digest and source record identity; no secret key emitted in trace.
- Positive control: Distinct records exercise two honest sign/verify calls.
- Negative control: No record-index change is ineffective and `inconclusive`.
- Fault control: Replace the second observed verification status with reject after real calls; predicate detects it.
- Required capabilities: submitted_kat, indexed_public_vector, seeded_signing, acceptance_status, output_canary.
- Predicate: Check exact provenance, signing success, verification success, lengths and guard on both runs.
- Paired mutator: `implement/mutator/roundtrip_{level}.py`.
- Limitations: Archived keypairs and finite signatures do not measure full signing reliability or prove unforgeability; `sig_keygen` itself is not called by this SOP oracle.
''')
        write(PACKAGE / f"implement/mutator/roundtrip_{level}.py",
              MUTATOR.replace("__INSTANCE__", instance))
        write(PACKAGE / f"implement/roundtrip_{level}_oracle.py",
              ORACLE.replace("__INSTANCE__", instance))
        obj["capabilities"].update(seeded_signing=True, output_canary=True)
        if not any(item["id"] == oid for item in obj["oracles"]):
            obj["oracles"].append({
                "id": oid, "version": 1, "claim": claim,
                "property": "S03", "property_version": 1,
                "pattern": "P2", "pattern_version": 1,
                "design": str(design.relative_to(PACKAGE)),
                "oracle": f"implement/roundtrip_{level}_oracle.py",
                "mutator": f"implement/mutator/roundtrip_{level}.py",
                "required_capabilities": ["submitted_kat", "indexed_public_vector",
                                          "seeded_signing", "acceptance_status", "output_canary"],
                "applicable_primitives": ["signature"]})
        for item in obj["oracles"]:
            if item["id"] == oid:
                item["design"] = str(design.relative_to(PACKAGE))
    write(SPEC, spec)
    manifest["spec_sha256"] = hashlib.sha256(SPEC.read_bytes()).hexdigest()
    write(manifest_path, json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print("registered 3 VDOO P2 fresh-signature oracles")


if __name__ == "__main__":
    main()

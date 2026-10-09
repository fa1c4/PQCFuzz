#!/usr/bin/env python3
"""Register HEP-QC P2 honest round-trip oracles for all four submitted instances."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "oracles/kem-17"
SPEC = ROOT / "oracles/spec/kem-17-HEP-QC.md"

MUTATOR = '''"""Pair public seeds for honest KEM round trips."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "__INSTANCE__"

def pair(a, b):
    cfg = DATA[INSTANCE]
    left = {"instance": INSTANCE, "operation": "roundtrip", "record_index": a}
    right = {"instance": INSTANCE, "operation": "roundtrip", "record_index": b}
    return {"baseline": left, "mutated": right,
            "kat_provenance": {"path": cfg["kat"], "sha256": cfg["kat_sha256"]},
            "changed_fields": ["record_index"] if a != b else [],
            "intervention": "select a different public KAT seed" if a != b else "none",
            "effective": a != b,
            "effectiveness_evidence": {"distinct_seed_indices": a != b,
                                       "same_instance_and_operation": True}}

def generate(seed, iteration):
    return pair((seed + iteration) % 10, (seed + iteration + 1) % 10)

def smoke_cases():
    return {"positive": pair(0, 1), "negative": pair(0, 0)}
'''

ORACLE = '''"""Check honest keygen, encapsulation and decapsulation agreement."""
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
'''


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def main():
    spec = SPEC.read_text(encoding="utf-8")
    manifest_path = PACKAGE / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for obj in manifest["instances"]:
        instance = obj["parameter_set"]
        level = instance.rsplit("-", 1)[1]
        tag = f"HEPQC{level}"
        claim, oid = f"{tag}-R", f"{tag}-ROUNDTRIP-01"
        if f"## {claim} —" not in spec:
            spec += f'''
## {claim} — {instance} honest KEM round trip

- Source locator: `third_party/kem-17/specification.pdf`, PDF pp. 16–18 §3.7 Algorithms 4–6; submitted `{json.loads((PACKAGE / "data/instances.json").read_text())[instance]["kat"]}` supplies public seed indices.
- Class: algorithm correctness relation from the PDF; test seeds are public input controls, not independent normative expected outputs.
- Scope: `{instance}` exact submitted `kem_keygen`, `kem_enc`, `kem_dec` API calls in one run-local build.
- Claim: For honestly generated keypairs and ciphertexts, decapsulation returns the encapsulated shared secret.
- Preconditions: Exact source/PDF/KAT identity, one indexed public seed, explicit `prng_init` before keygen, matching API lengths and success statuses.
- Extraction inference/ambiguity: The archived KAT driver initializes a different DRNG context while this implementation's KEM calls use `prng_get_bytes`; these P2 outputs are not asserted to equal archived KAT bytes.
- Limitations: Finite honest executions do not establish zero failure probability, IND-CCA security or malformed-ciphertext behavior.
'''
        design = PACKAGE / f"design/HEP-QC/kem_dec/{oid}.md"
        write(design, f'''# {oid}: HEP-QC honest KEM round trip

- Claim: `{claim}` in `oracles/spec/kem-17-HEP-QC.md`; PDF pp. 16–18 §3.7 Algorithms 4–6.
- Property: K03 version 1, KEM correctness. Pattern: P2 version 1, round-trip relation.
- Extraction status: draft (`unverified_spec`), candidate-only.
- Scope/preconditions: `{instance}` run-local submitted build, two indexed public KAT seeds; `prng_init` controls the actual `prng_get_bytes` used by `kem_keygen` and `kem_enc`.
- Baseline: Honest keygen→enc→dec under the first public seed.
- Intervention: Reset the PRNG with a different indexed public seed, then repeat all three calls.
- Expected relation: For each seed, encapsulated and decapsulated shared-secret bytes agree, with success status, exact lengths and untouched output guards.
- Observables: Actual `kem_keygen`, `kem_enc`, `kem_dec` results and output bytes. No secret keys are emitted into traces.
- Positive control: Distinct public seeds, both honest triples reach all APIs and agree.
- Negative control: No seed-index change is ineffective and `inconclusive`.
- Fault control: Flip one observed decapsulated-secret bit after real calls; predicate must detect mismatch.
- Required capabilities: indexed_public_vector, seeded_prng, honest_roundtrip, output_canary.
- Predicate: Check source provenance, API statuses, lengths, guards and two independent shared-secret equalities.
- Paired mutator: `implement/mutator/roundtrip_{level}.py`.
- Limitations: Public deterministic seeds and finite trials do not prove reliability or confidentiality; archived KAT bytes are not the expected outputs for this oracle.
''')
        write(PACKAGE / f"implement/mutator/roundtrip_{level}.py",
              MUTATOR.replace("__INSTANCE__", instance))
        write(PACKAGE / f"implement/roundtrip_{level}_oracle.py",
              ORACLE.replace("__INSTANCE__", instance))
        obj["capabilities"].update(seeded_prng=True, honest_roundtrip=True)
        if not any(item["id"] == oid for item in obj["oracles"]):
            obj["oracles"].append({
                "id": oid, "version": 1, "claim": claim,
                "property": "K03", "property_version": 1,
                "pattern": "P2", "pattern_version": 1,
                "design": str(design.relative_to(PACKAGE)),
                "oracle": f"implement/roundtrip_{level}_oracle.py",
                "mutator": f"implement/mutator/roundtrip_{level}.py",
                "required_capabilities": ["indexed_public_vector", "seeded_prng",
                                          "honest_roundtrip", "output_canary"],
                "applicable_primitives": ["kem"]})
        for item in obj["oracles"]:
            if item["id"] == oid:
                item["design"] = str(design.relative_to(PACKAGE))
    write(SPEC, spec)
    manifest["spec_sha256"] = hashlib.sha256(SPEC.read_bytes()).hexdigest()
    write(manifest_path, json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print("registered 4 HEP-QC P2 round-trip oracles")


if __name__ == "__main__":
    main()

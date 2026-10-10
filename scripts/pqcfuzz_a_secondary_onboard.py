#!/usr/bin/env python3
"""Register independently qualified submitted-reference A-tier parameter sets."""
import argparse
import copy
import hashlib
import json
import os
import tempfile
from pathlib import Path

import pqcfuzz_a_full_api_onboard as full
import pqcfuzz_c_public_kat_onboard as kat_base

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "workspace/a_targets_sop/probes/asymmetric/secondary/report.json"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def one(row, registry):
    target, instance = row["target"], row["parameter_set"]
    entry = next(x for x in registry["targets"] if x["target"] == target)
    if any(x["parameter_set"] == instance for x in entry["apis"]):
        return False
    package = ROOT / "oracles" / target
    manifest_path = package / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    spec_path = ROOT / entry["specification"]
    spec = spec_path.read_text()
    data_path = package / "data/instances.json"
    data = json.loads(data_path.read_text())
    source = ROOT / entry["source"]
    generated = row.get("kat_origin") == "build"
    kat = (ROOT / "workspace/a_targets_sop/generated/facto512/src/output" /
           Path(row["kat"]).name if generated else source / row["kat"])
    if sha(kat) != row["kat_sha256"]:
        raise ValueError("KAT digest mismatch: " + target + "/" + instance)
    primitive = entry["primitive"]
    old_api = "sig_verify" if primitive == "signature" else "kem_dec"
    original = next(x for x in entry["apis"] if x["name"] == old_api)
    cfg = {key: row[key] for key in ("kat", "kat_sha256", "sources", "includes", "flags")}
    if generated:
        cfg["kat_origin"] = "build"
        cfg["kat_generator_sources"] = row["kat_generator_sources"]
    cfg["records"] = kat_base.metadata(kat, primitive)
    if target == "sign-01":
        cfg["variable_signature_length"] = True
    data[instance] = cfg
    tag = "".join(char for char in instance.upper() if char.isalnum())
    claim, oid = f"{tag}-K", f"{tag}-KAT-01"
    origin = ("locally regenerated with the pinned submitted KAT_SIG.c generator; "
              if generated else "submitted archive; ")
    locator = (f"{full.PDF_ROUNDTRIP[target]} (algorithm context); {origin}"
               f"`{row['kat']}` SHA-256 `{row['kat_sha256']}`")
    vector_label = "locally regenerated KAT-generator" if generated else "submitted"
    relation = (f"Both valid {vector_label} records are accepted by sig_verify."
                if primitive == "signature" else
                f"Both valid {vector_label} records decapsulate to their own recorded shared secrets.")
    spec += f'''
## {claim} — {instance} {vector_label} valid-vector consistency

- Source locator: {locator}.
- Class: PDF correctness context and {vector_label} vector observation; the latter is not independent normative truth.
- Scope: `{instance}` `{old_api}` on ten exact public {vector_label} records, with API lengths and status.
- Claim: {relation}
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: {vector_label} vectors share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.
'''
    design = f"design/{entry['algorithm']}/{old_api}/{oid}.md"
    oracle = f"implement/kat_{tag.lower()}_oracle.py"
    mutator = f"implement/mutator/kat_{tag.lower()}.py"
    full.write(package / design, f'''# {oid}: exact {vector_label} vector relation

- Claim: `{claim}` in `{entry['specification']}`; source locator {locator}.
- Property: {'S03' if primitive == 'signature' else 'K03'} version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `{instance}` `{old_api}`, exact indexed public {vector_label} KAT, source/KAT SHA and declared output/status semantics.
- Baseline: Valid indexed {vector_label} record 0 in smoke.
- Intervention: Select distinct valid record 1 in smoke; preserve instance and API.
- Expected relation: {relation}
- Observables: Actual API reachability, status, output length{', and output guard' if primitive == 'kem' else ', and return code'}.
- Controls: Distinct records pass; identical record is inconclusive; faulted observation is rejected.
- Required capabilities: {'generated_kat' if generated else 'submitted_kat'}, indexed_public_vector{', output_canary' if primitive == 'kem' else ''}.
- Paired mutator: `{mutator}`.
- Limitations: Same-lineage vectors; no negative-input or finite security proof.
''')
    full.write(package / mutator, kat_base.MUTATOR.replace("__INSTANCE__", instance)
               .replace("__OPERATION__", "verify" if primitive == "signature" else "decapsulate"))
    full.write(package / oracle, kat_base.ORACLE.replace("__INSTANCE__", instance)
               .replace("__PRIMITIVE__", primitive))
    caps = {"submitted_kat": not generated, "generated_kat": generated,
            "indexed_public_vector": True,
            "output_canary": primitive == "kem", "rng_control": False,
            "fault_injection": False, "intermediate_state": False,
            "decapsulation_failure": False}
    manifest["instances"].append({"parameter_set": instance, "api": old_api,
        "profiles": ["gcc-reference"], "adapter": "implement/adapter.py",
        "capabilities": caps,
        "oracles": [{"id": oid, "version": 1, "claim": claim,
                     "property": "S03" if primitive == "signature" else "K03",
                     "property_version": 1, "pattern": "P1", "pattern_version": 1,
                     "design": design, "oracle": oracle, "mutator": mutator,
                     "required_capabilities": ["generated_kat" if generated else "submitted_kat",
                                               "indexed_public_vector"] +
                                              (["output_canary"] if primitive == "kem" else []),
                     "applicable_primitives": [primitive]}]})
    profile = copy.deepcopy(original["profiles"][0])
    profile["build"] = [["python3", "{run}/package/implement/build.py", "{source}",
                         "{run}", instance]]
    profile["seed"] = sum(ord(char) for char in instance) + 33000
    profile["options"] = {"parameter_set": instance}
    if generated:
        profile["disk_mb"] += 256
    entry["apis"].append({"name": old_api, "parameter_set": instance,
                          "profiles": [profile]})
    full.dump(data_path, data)
    full.write(spec_path, spec)
    manifest["spec_sha256"] = sha(spec_path)
    full.dump(manifest_path, manifest)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append")
    args = parser.parse_args()
    reports = json.loads(PROBE.read_text())
    generated_report = ROOT / "workspace/a_targets_sop/probes/asymmetric/facto512_generated.json"
    if generated_report.is_file():
        row = json.loads(generated_report.read_text())
        if row["status"] == "first_vector_match":
            row["kat"] = "generator/output/KAT_SIG_Facto-DSA-512.txt"
            row["kat_origin"] = "build"
            reference = "Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-512/"
            row["kat_generator_sources"] = [reference + name for name in
                                            ("KAT_SIG.c", "SIG_AlgorithmInstance.c",
                                             "auxfunc.c", "drng.c")]
            reports.append(row)
    rows = [row for row in reports
            if row["status"] == "first_vector_match" and
            (not args.target or row["target"] in args.target)]
    if not rows:
        raise SystemExit("no qualified parameter sets")
    registry_path = ROOT / "configs/targets.json"
    registry = json.loads(registry_path.read_text())
    added = [{"target": row["target"], "parameter_set": row["parameter_set"]}
             for row in rows if one(row, registry)]
    if added:
        fd, temp = tempfile.mkstemp(prefix="targets-a-secondary-", suffix=".json",
                                    dir=registry_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(registry, indent=2, ensure_ascii=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, registry_path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    print(json.dumps({"registered": added, "count": len(added)}))


if __name__ == "__main__":
    main()

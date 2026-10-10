#!/usr/bin/env python3
"""Add source-backed P1/P2 SOP slices for first-instance A-tier public calls."""
import argparse
import copy
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX = {x["target"]: x for x in json.loads(
    (ROOT / "workspace/a_targets_sop/api_matrix.json").read_text())}
PDF_ROUNDTRIP = {
    "sign-01": "PDF p. 11", "sign-10": "PDF p. 7", "sign-17": "PDF p. 7",
    "sign-23": "PDF p. 10", "sign-31": "PDF p. 24",
    "kem-01": "PDF pp. 8–9", "kem-02": "PDF pp. 7–9", "kem-04": "PDF p. 7",
    "kem-15": "PDF p. 15", "kem-16": "PDF p. 9", "kem-19": "PDF p. 12",
    "kem-26": "PDF pp. 22–24", "kem-27": "PDF p. 18", "kem-28": "PDF p. 6",
    "kem-29": "PDF p. 11", "kem-30": "PDF pp. 14–16", "kem-36": "PDF p. 7",
}
TEMPLATES = ROOT / "scripts/templates"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def dump(path, value):
    write(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def records(path):
    rows = []
    for block in path.read_text(encoding="ascii").replace("\r\n", "\n").split("Count = ")[1:]:
        row = {key: value for key, value in
               (line.split(" = ", 1) for line in block.splitlines() if " = " in line)}
        rows.append(row)
    if len(rows) != 10 or any("Seed" not in row for row in rows):
        raise ValueError("expected ten source-pinned KAT seeds")
    return rows


def thin(instance, api, common, parent_depth, mutator):
    lines = ["\"\"\"Bind one exact parameter set and public API to the shared relation.\"\"\"",
             "import importlib.util", "from pathlib import Path", "",
             f"INSTANCE = {instance!r}", f"API = {api!r}",
             f"_PATH = Path(__file__).resolve().parents[{parent_depth}] / 'implement/{common}'",
             "_SPEC = importlib.util.spec_from_file_location('a_full_api_common', _PATH)",
             "_COMMON = importlib.util.module_from_spec(_SPEC)",
             "_SPEC.loader.exec_module(_COMMON)", ""]
    if mutator:
        lines += ["def generate(seed, iteration):",
                  "    return _COMMON.generate(INSTANCE, API, seed, iteration)", "",
                  "def smoke_cases():",
                  "    return _COMMON.smoke_cases(INSTANCE, API)"]
    else:
        lines += ["def evaluate(case, baseline, mutated):",
                  "    return _COMMON.evaluate(INSTANCE, API, case, baseline, mutated)", "",
                  "def fault_observation(mutated):",
                  "    return _COMMON.fault_observation(API, mutated)"]
    return "\n".join(lines) + "\n"


def one(target, registry, instance):
    entry = next(x for x in registry["targets"] if x["target"] == target)
    manifest_path = ROOT / "oracles" / target / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    original = next((x for x in manifest["instances"] if x["parameter_set"] == instance and
                     x["api"] in ("kem_dec", "sig_verify")), None)
    if original is None:
        raise ValueError("missing submitted-KAT instance: " + target + "/" + instance)
    old_api = original["api"]
    primitive = entry["primitive"]
    if old_api != ("sig_verify" if primitive == "signature" else "kem_dec"):
        raise ValueError("unexpected original API")
    source = ROOT / entry["source"]
    header_segment = ("/Lore-SM3/Lore-" + instance.rsplit("-", 1)[-1] + "/"
                      if instance.startswith("Lore-SM3-") else "/" + instance + "/")
    matching = [h["path"] for h in MATRIX[target]["primary_reference_headers"]
                if header_segment in h["path"]]
    if not matching:
        raise ValueError("no submitted reference header for " + instance)
    header = source / matching[0]
    if not header.is_file():
        raise ValueError("missing header")
    declared = {name.strip() for name in
                re.findall(r"\b(?:kem|sig)_[a-z_]+\s*(?=\()",
                           header.read_text(errors="replace"))}
    expected = ({"sig_get_pk_len_bytes", "sig_get_sk_len_bytes", "sig_get_sn_len_bytes",
                 "sig_keygen", "sig_sign", "sig_verify"} if primitive == "signature" else
                {"kem_get_pk_len_bytes", "kem_get_sk_len_bytes", "kem_get_ss_len_bytes",
                 "kem_get_ct_len_bytes", "kem_keygen", "kem_enc", "kem_dec"})
    if not expected.issubset(declared):
        raise ValueError("submitted header lacks expected public API: " + target)
    data_path = manifest_path.parent / "data/instances.json"
    configs = json.loads(data_path.read_text())
    cfg = configs[instance]
    vector_capability = ("generated_kat" if cfg.get("kat_origin") in ("package", "build")
                         else "submitted_kat")
    vector_label = ("locally regenerated KAT-generator" if cfg.get("kat_origin") in ("package", "build")
                    else "submitted KAT")
    kat_root = (ROOT / "workspace/a_targets_sop/generated/facto512/src/output"
                if cfg.get("kat_origin") == "build" else
                manifest_path.parent if cfg.get("kat_origin") == "package" else source)
    kat = kat_root / (Path(cfg["kat"]).name if cfg.get("kat_origin") == "build" else cfg["kat"])
    if sha(kat) != cfg["kat_sha256"]:
        raise ValueError("submitted KAT changed")
    rows = records(kat)
    seed_hashes = [hashlib.sha256(bytes.fromhex(row["Seed"])).hexdigest() for row in rows]
    if len(set(seed_hashes)) != 10:
        raise ValueError("KAT seeds not distinct")
    cfg["record_seed_sha256"] = seed_hashes
    tag = "".join(char for char in instance.upper() if char.isalnum())
    spec_path = ROOT / entry["specification"]
    spec = spec_path.read_text()
    spec = spec.replace("extract_version: 1\n", "extract_version: 2\n", 1)
    adapter_path = "implement/full_api_adapter.py"
    common_path = "implement/full_api_common.py"
    generated = []
    for position, api in enumerate(sorted(expected - {old_api}), start=1):
        getter = "_get_" in api
        code = api.upper().replace("_", "")
        claim = f"{tag}-{code}-C"
        oid = f"{tag}-{code}-{'P1' if getter else 'P2'}-01"
        if re.search(rf"(?m)^## {re.escape(claim)}\s+[—:-]", spec):
            raise ValueError("claim already exists: " + claim)
        property_id = "X05" if getter else ("S03" if primitive == "signature" else "K03")
        pattern = "P1" if getter else "P2"
        relation = (f"Its reported allocation/serialization length equals the exact {vector_label} "
                    "object length (signature length may be an upper bound where documented)."
                    if getter else
                    f"For a valid {vector_label} key pair or a freshly generated key pair, the "
                    "complementary public operations complete an honest roundtrip.")
        locator = (f"`{matching[0]}` SHA-256 `{sha(header)}`; `{cfg['kat']}` "
                   f"SHA-256 `{cfg['kat_sha256']}`" if getter else
                   f"{PDF_ROUNDTRIP[target]}; `{matching[0]}` SHA-256 `{sha(header)}`; "
                   f"`{cfg['kat']}` SHA-256 `{cfg['kat_sha256']}`")
        spec += f'''
## {claim} — {instance} {api} public API relation

- Source locator: {locator}.
- Class: {vector_label + ' API length observation' if getter else 'correctness construction and API contract; P2 relation is an explicit extraction inference'}.
- Scope: `{instance}` `{api}` in the pinned primary reference implementation and ten public {vector_label} records.
- Claim: {relation}
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; {vector_label + ' length is same-lineage control data' if getter else 'honest inverse relation follows the cited construction and API pairing, while randomness bytes are not expected to match the local vector'}.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
'''
        design = f"design/{entry['algorithm']}/{api}/{oid}.md"
        oracle = f"implement/{oid.lower()}_oracle.py"
        mutator = f"implement/mutator/{oid.lower()}.py"
        capability = "submitted_lengths" if getter else "honest_roundtrip"
        design_text = f'''# {oid}: {api} public API relation

- Claim: `{claim}` in `{entry['specification']}`; locator {locator}.
- Property: {property_id} version 1; pattern: {pattern} version 1; extraction: draft (`unverified_spec`).
- Scope/preconditions: Exact `{instance}` `{api}` public function, pinned primary reference source and ten {vector_label} records; valid key/seed and matching declared capacities.
- Baseline: KAT record 0, with its public seed, key pair and/or length field.
- Intervention: Select a distinct record and distinct seed (record 1 in smoke); unrelated fields and selected API remain fixed.
- Expected relation: {relation}
- Observable: `{api}` reachability, API/status, length or inverse result, return codes and output guards; no secret bytes in ordinary report summaries.
- Positive control: Two distinct valid records through the real submitted API.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Change the observed length/roundtrip outcome after target invocation; the predicate rejects it.
- Adapter capabilities: {vector_capability}, indexed_public_vector, {capability}{', rng_control, output_canary' if not getter else ''}.
- Predicate: Both reachable calls must satisfy exact submitted length or successful honest roundtrip; any discrepancy remains candidate-only after gates.
- Paired mutator: `{mutator}`.
- Limitations: Same-lineage KAT and construction inference; finite testing proves no security game and this oracle does not test other parameter sets or malformed inputs.
'''
        write(manifest_path.parent / design, design_text)
        write(manifest_path.parent / oracle, thin(instance, api, "full_api_common.py", 1, False))
        write(manifest_path.parent / mutator, thin(instance, api, "full_api_common.py", 2, True))
        capabilities = {"submitted_kat": vector_capability == "submitted_kat",
                        "generated_kat": vector_capability == "generated_kat",
                        "indexed_public_vector": True,
                        "submitted_lengths": getter, "honest_roundtrip": not getter,
                        "rng_control": not getter, "output_canary": not getter,
                        "fault_injection": False, "intermediate_state": False,
                        "decapsulation_failure": False}
        manifest["instances"].append({"parameter_set": instance, "api": api,
              "profiles": ["gcc-reference"], "adapter": adapter_path,
              "capabilities": capabilities,
              "oracles": [{"id": oid, "version": 1, "claim": claim,
                           "property": property_id, "property_version": 1,
                           "pattern": pattern, "pattern_version": 1,
                           "design": design, "oracle": oracle, "mutator": mutator,
                           "required_capabilities": [vector_capability, "indexed_public_vector",
                                                     capability] +
                                                    (["rng_control", "output_canary"] if not getter else []),
                           "applicable_primitives": [primitive]}]})
        original_api = next(x for x in entry["apis"] if x["parameter_set"] == instance
                            and x["name"] == old_api)
        profile = copy.deepcopy(original_api["profiles"][0])
        profile["options"] = {**profile["options"], "api": api}
        profile["seed"] += position * 101
        entry["apis"].append({"name": api, "parameter_set": instance,
                              "profiles": [profile]})
        generated.append(api)
    write(manifest_path.parent / adapter_path,
          (TEMPLATES / "a_full_api_adapter.py").read_text())
    write(manifest_path.parent / common_path,
          (TEMPLATES / "a_full_api_common.py").read_text())
    dump(data_path, configs)
    write(spec_path, spec)
    manifest["spec_sha256"] = sha(spec_path)
    dump(manifest_path, manifest)
    return {"target": target, "parameter_set": instance, "registered_new_apis": generated}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", required=True)
    args = parser.parse_args()
    if set(args.target) - set(PDF_ROUNDTRIP):
        parser.error("unknown A-tier asymmetric target")
    registry_path = ROOT / "configs/targets.json"
    registry = json.loads(registry_path.read_text())
    results = []
    for target in dict.fromkeys(args.target):
        entry = next(x for x in registry["targets"] if x["target"] == target)
        old_api = "sig_verify" if entry["primitive"] == "signature" else "kem_dec"
        expected = (6 if entry["primitive"] == "signature" else 7)
        for instance in sorted({x["parameter_set"] for x in entry["apis"] if x["name"] == old_api}):
            if len([x for x in entry["apis"] if x["parameter_set"] == instance]) == expected:
                continue
            results.append(one(target, registry, instance))
    fd, temporary = tempfile.mkstemp(prefix="targets-a-full-api-", suffix=".json",
                                     dir=registry_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(registry, indent=2, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, registry_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(json.dumps(results))


if __name__ == "__main__":
    main()

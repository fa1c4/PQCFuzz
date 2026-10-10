#!/usr/bin/env python3
"""Register source-pinned P1 SOP for qualified A-tier hash parameter sets."""
import copy
import hashlib
import json
import os
import tempfile
from pathlib import Path

import pqcfuzz_a_hash_onboard as base

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "workspace/a_targets_sop/probes/hash_secondary/report.json"
TEMPLATES = ROOT / "scripts/templates"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def dump(path, value):
    write(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def thin(corpus_name, bits, is_mutator):
    parents = 2 if is_mutator else 1
    function = (f'''def generate(seed, iteration):
    return _COMMON.kat_generate(seed, iteration, _CORPUS, {bits}, ("reference",))

def smoke_cases():
    return _COMMON.kat_smoke(_CORPUS, {bits}, ("reference",))
''' if is_mutator else f'''def evaluate(case, baseline, mutated):
    return _COMMON.kat_evaluate(case, baseline, mutated, _CORPUS, {bits}, ("reference",), True)

def fault_observation(mutated):
    return _COMMON.fault_observation(mutated)
''')
    return f'''"""Bind one exact hash instance to its source-pinned P1 KAT corpus."""
import importlib.util
import json
from pathlib import Path
_PACKAGE = Path(__file__).resolve().parents[{parents}]
_SPEC = importlib.util.spec_from_file_location("a_hash_common", _PACKAGE / "implement/common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)
_CORPUS = json.loads((_PACKAGE / "data/{corpus_name}").read_text())

{function}'''


def one(row, registry):
    target, instance, bits = row["target"], row["parameter_set"], row["digest_bits"]
    entry = next(x for x in registry["targets"] if x["target"] == target)
    if any(x["parameter_set"] == instance for x in entry["apis"]):
        return False
    package = ROOT / "oracles" / target
    manifest_path = package / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    spec_path = ROOT / entry["specification"]
    spec = spec_path.read_text()
    source = ROOT / entry["source"]
    kat = source / row["kat"]
    if sha(kat) != row["kat_sha256"] or sha(source / row["header"]) != row["header_sha256"]:
        raise ValueError("source/KAT digest changed: " + target + "/" + instance)
    matches = list(base.KAT_RE.finditer(kat.read_text("ascii").replace("\r\n", "\n")))
    records = []
    for index in base.SELECT:
        msg_bits, message, output_bits, digest = matches[index].groups()
        if int(msg_bits) != index or int(output_bits) != bits or len(digest) != bits // 4:
            raise ValueError("malformed submitted KAT: " + target + "/" + instance)
        raw = bytes.fromhex(message)
        if len(raw) != (index + 7) // 8 or (index % 8 and raw[-1] & ((1 << (8 - index % 8)) - 1)):
            raise ValueError("noncanonical submitted KAT: " + target + "/" + instance)
        records.append({"message_bits": index, "message_hex": message.lower(),
                        "digest_hex": digest.lower(), "source_record_index": index})
    tag = "".join(char for char in instance.upper() if char.isalnum())
    corpus_name = "kat_" + tag.lower() + ".json"
    dump(package / "data" / corpus_name,
         {"source_path": row["kat"], "source_sha256": row["kat_sha256"],
          "records": records})
    config_path = package / "data/secondary_instances.json"
    config = json.loads(config_path.read_text()) if config_path.exists() else {}
    config[instance] = {"digest_bits": bits, "sources": row["sources"],
                        "header": row["header"], "header_sha256": row["header_sha256"],
                        "kat": row["kat"], "kat_sha256": row["kat_sha256"]}
    dump(config_path, config)
    write(package / "implement/secondary_build.py",
          (TEMPLATES / "a_hash_secondary_build.py").read_text().replace("__TARGET__", target))
    write(package / "implement/secondary_adapter.py",
          (TEMPLATES / "a_hash_secondary_adapter.py").read_text().replace("__TARGET__", target))
    claim, oid = f"{tag}-K", f"{tag}-KAT-01"
    locator = f"{base.PDF_LOCATORS[target]}; `{row['header']}` SHA-256 `{row['header_sha256']}`; `{row['kat']}` SHA-256 `{row['kat_sha256']}`"
    spec += f'''
## {claim} — {instance} submitted CryptHash known-answer relation

- Source locator: {locator}.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `{instance}` reference `CryptHash` at exactly {bits} output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.
'''
    design = f"design/{entry['algorithm']}/CryptHash/{oid}.md"
    oracle = f"implement/{tag.lower()}_kat_oracle.py"
    mutator = f"implement/mutator/{tag.lower()}_kat.py"
    write(package / design, f'''# {oid}: source-pinned submitted KAT consistency

- Claim: `{claim}` in `{entry['specification']}`; source locator {locator}.
- Property: X05 version 1; pattern P1 version 1; extraction draft (`unverified_spec`).
- Scope/preconditions: `{instance}` reference `CryptHash`, {bits}-bit digest, exact public KAT records and source identity.
- Baseline: Submitted 512-bit input record in smoke.
- Intervention: Switch to submitted 513-bit record while retaining parameter set and backend.
- Expected relation: Each actual digest equals its corresponding pinned KAT digest.
- Observable: Public call reachability, return status, output bytes/length and output canary.
- Controls: Distinct KAT records pass; identical record is inconclusive; faulted digest is rejected.
- Required capabilities: bit_input, submitted_kat, output_canary.
- Paired mutator: `{mutator}`.
- Limitations: Same-lineage KAT, reference backend only, finite testing proves no security property.
''')
    write(package / oracle, thin(corpus_name, bits, False))
    write(package / mutator, thin(corpus_name, bits, True))
    manifest["instances"].append({"parameter_set": instance, "api": "CryptHash",
        "profiles": ["gcc-reference"], "adapter": "implement/secondary_adapter.py",
        "capabilities": {"dual_backend": False, "bit_input": True, "submitted_kat": True,
                         "output_canary": True, "rng_control": False, "fault_injection": False,
                         "intermediate_state": False, "decapsulation_failure": False},
        "oracles": [{"id": oid, "version": 1, "claim": claim, "property": "X05",
                     "property_version": 1, "pattern": "P1", "pattern_version": 1,
                     "design": design, "oracle": oracle, "mutator": mutator,
                     "required_capabilities": ["bit_input", "submitted_kat", "output_canary"],
                     "applicable_primitives": ["hash"]}]})
    original = entry["apis"][0]["profiles"][0]
    profile = copy.deepcopy(original)
    profile["id"] = "gcc-reference"
    profile["build"] = [["python3", "{run}/package/implement/secondary_build.py",
                         "{source}", "{run}", instance]]
    profile["seed"] = sum(ord(char) for char in instance) + 31000
    profile["options"] = {"parameter_set": instance, "digest_bits": bits}
    entry["apis"].append({"name": "CryptHash", "parameter_set": instance,
                          "profiles": [profile]})
    write(spec_path, spec)
    manifest["spec_sha256"] = sha(spec_path)
    dump(manifest_path, manifest)
    return True


def main():
    rows = json.loads(REPORT.read_text())
    if len(rows) != 36 or any(x["status"] != "one_kat_match" for x in rows):
        raise SystemExit("all 36 remaining public hash profiles must match a submitted KAT")
    registry_path = ROOT / "configs/targets.json"
    registry = json.loads(registry_path.read_text())
    added = [{"target": row["target"], "parameter_set": row["parameter_set"]}
             for row in rows if one(row, registry)]
    if added:
        fd, temp = tempfile.mkstemp(prefix="targets-a-hash-secondary-", suffix=".json",
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

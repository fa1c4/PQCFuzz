#!/usr/bin/env python3
"""Register eleven B-tier fixed-output hash slices qualified by exact KAT probes."""
import importlib.util
import hashlib
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "workspace/b_targets_sop"
SELECTED = {
    "hash-05": ("uHash", "PDF pp. 4–5"),
    "hash-10": ("FEILIAN", "PDF pp. 4–6"),
    "hash-11": ("Garnet", "PDF pp. 10–13"),
    "hash-14": ("Laurus", "PDF pp. 7–8"),
    "hash-18": ("MEGASCON", "PDF pp. 3–4"),
    "hash-19": ("MoFang", "PDF pp. 4–5"),
    "hash-20": ("MOZI", "PDF pp. 3–4"),
    "hash-27": ("Vedak", "PDF pp. 4–5"),
    "hash-30": ("ZC-DM", "PDF pp. 5–6"),
    "hash-31": ("ZC-DMC", "PDF pp. 5–6"),
    "hash-32": ("ZC-EDMC", "PDF pp. 5–6"),
}


def by_key(path):
    return {(x["target"], x.get("backend")): x for x in json.loads(path.read_text())}


def main():
    path = ROOT / "configs/targets.json"
    registry = json.loads(path.read_text())
    present = {item["target"] for item in registry["targets"]}
    pending = sorted(SELECTED.keys() - present)
    if not pending:
        print(json.dumps({"registered": [], "already_registered": sorted(SELECTED)}))
        return
    spec = importlib.util.spec_from_file_location("a_hash_onboard",
                                                  ROOT / "scripts/pqcfuzz_a_hash_onboard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    inventory = {x["target"]: x for x in json.loads((WORK / "inventory.json").read_text())}
    base = by_key(WORK / "probes/hash_report.json")
    special = by_key(WORK / "probes/special_report.json")
    zc = by_key(WORK / "probes/zc_report.json")
    zc_opt = by_key(WORK / "probes/zc_opt_report.json")
    entries = []
    for target in pending:
        if target == "hash-11":
            prefix = "Garnet/Implementations/API_CryptHash/Implementations/Reference_Implementation/Garnet/"
            kat = "Garnet/Implementations/API_CryptHash/Test_Vector/KAT_2_12_Garnet_512_Cap1024.txt"
            reference = {"target": target, "instance": "Garnet_512_Cap1024",
                         "backend": "reference", "status": "one_kat_match",
                         "header": prefix + "CryptHash_Garnet.h",
                         "kat": kat,
                         "kat_sha256": hashlib.sha256((ROOT / "third_party" / target /
                                                      "source" / kat).read_bytes()).hexdigest(),
                         "sources": [prefix + name for name in
                                     ("CryptHash_Garnet.c", "Garnet_512.c",
                                      "Garnet_768.c", "Garnet_1024.c")]}
            optimized = {"target": target, "backend": "optimized",
                         "status": "not_same_api", "sources": []}
        else:
            reference = dict(base[(target, "reference")])
            optimized = dict(base[(target, "optimized")])
        options = {}
        if target in ("hash-10", "hash-18", "hash-20"):
            optimized.update(special[(target, "optimized")])
        if target in ("hash-18", "hash-20"):
            options["compilers"] = {"optimized": "g++"}
        if target in ("hash-30", "hash-31", "hash-32"):
            reference.update(zc[(target, "reference")])
            optimized.update(zc_opt[(target, "optimized")])
            family = SELECTED[target][0]
            options["include_dirs"] = [f"{family}/Implementations/lib/common"]
        reference["digest_bits"] = 512
        algorithm, locator = SELECTED[target]
        reference_only = target in ("hash-05", "hash-11", "hash-14")
        entries.append(module.create(target, inventory[target], reference, optimized,
                                     algorithm_override=algorithm,
                                     locator_override=locator, build_options=options,
                                     reference_only=reference_only))
    registry["targets"].extend(entries)
    fd, temporary = tempfile.mkstemp(prefix="targets-b-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(registry, indent=2, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(json.dumps({"registered": pending,
                      "parameter_sets": [e["apis"][0]["parameter_set"] for e in entries]}))


if __name__ == "__main__":
    main()

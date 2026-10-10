#!/usr/bin/env python3
"""Audit source-declared public A-tier APIs against registered SOP instances.

This is a coverage inventory, not evidence that an unregistered function passed.
Only submitted primary reference API headers and inventoried hash API headers
are treated as the known public surface. Alternate backends are kept distinct.
"""
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "workspace/a_targets_sop"
FUNCTION = re.compile(r"\b(CryptHash|kem_(?:get_[a-z]+_len_bytes|keygen|enc|dec)|"
                      r"sig_(?:get_[a-z]+_len_bytes|keygen|sign|verify))\s*\(")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parameter_from_header(path, primitive):
    parts = Path(path).parts
    if primitive == "hash":
        return Path(path).parent.name.removesuffix("_reference")
    try:
        index = max(i for i, part in enumerate(parts) if part == "Reference_Implementation")
    except ValueError:
        return None
    candidates = parts[index + 1:-1]
    if not candidates:
        return None
    if candidates[0] in ("Lore-SHAKE", "Lore-SM3") and len(candidates) > 1:
        return candidates[0] + "/" + candidates[1]
    if candidates[0] in ("x86", "x86_64", "ARM", "aarch64") and len(candidates) > 1:
        return candidates[1]
    return candidates[0]


def main():
    inventory = {x["target"]: x for x in json.loads((WORK / "inventory.json").read_text())}
    matrix = {x["target"]: x for x in json.loads((WORK / "api_matrix.json").read_text())}
    registry = {x["target"]: x for x in json.loads((ROOT / "configs/targets.json").read_text())["targets"]}
    if len(inventory) != 33 or len(matrix) != 17 or set(inventory) - set(registry):
        raise SystemExit("A-tier inventory, matrix or registry incomplete")
    result = {"schema_version": 1, "source": "submitted primary reference public headers",
              "limits": ["Internal helpers and alternate backend APIs are not enumerated here.",
                         "Header declaration does not establish a working build or normative relation.",
                         "A supporting call inside an adapter is not an independently registered SOP API."],
              "targets": []}
    total = 0
    unique = set()
    matched = set()
    for target in sorted(inventory):
        row = inventory[target]
        primitive = row["primitive"]
        if primitive != "hash":
            candidates = matrix[target]["primary_reference_headers"]
        else:
            paths = [h for h in row["api_headers"] if "Reference_Implementation" in h
                     and "/Others/" not in h]
            if not paths:
                source_root = ROOT / "third_party" / target / "source"
                paths = [str(h.relative_to(source_root)) for h in source_root.rglob("*CryptHash*.h")
                         if "Reference_Implementation" in h.parts and "Others" not in h.parts]
            candidates = [{"path": h} for h in sorted(paths)]
        headers = []
        selected = {(x["parameter_set"], x["name"])
                    for x in registry[target]["apis"]}
        for item in candidates:
            relative = item["path"]
            path = ROOT / "third_party" / target / "source" / relative
            if not path.is_file():
                raise SystemExit("missing inventoried header: " + str(path))
            actual = sorted(set(FUNCTION.findall(path.read_text(errors="replace"))))
            listed = sorted(set(item.get("functions", actual)))
            if actual != listed:
                raise SystemExit(f"header function inventory drift: {target} {relative}")
            parameter = parameter_from_header(relative, primitive)
            if not parameter:
                raise SystemExit("could not locate parameter set: " + relative)
            calls = []
            for function in actual:
                is_registered = (parameter, function) in selected
                # Lore has two named symmetric profiles; its registry currently
                # selects SHAKE and should not count SM3 as registered.
                if parameter.startswith("Lore-"):
                    mode, level = parameter.split("/", 1)
                    registry_parameter = (level if mode == "Lore-SHAKE" else
                                          "Lore-SM3-" + level.rsplit("-", 1)[-1])
                    is_registered = (registry_parameter, function) in selected
                calls.append({"function": function, "registry_has_parameter_api": is_registered})
                total += 1
                unique.add((target, parameter, function))
                if is_registered:
                    matched.add((target, parameter, function))
            headers.append({"path": relative, "sha256": sha(path),
                            "parameter_or_variant": parameter, "functions": calls})
        result["targets"].append({"target": target, "algorithm": registry[target]["algorithm"],
                                  "primitive": primitive, "headers": headers,
                                  "registered": sorted([{"parameter_set": p, "api": a}
                                                        for p, a in selected],
                                                       key=lambda x: (x["parameter_set"], x["api"]))})
    result["declared_header_function_slots"] = total
    result["declared_unique_parameter_function_tuples"] = len(unique)
    result["registry_matched_parameter_function_tuples"] = len(matched)
    out = WORK / "full_public_api_inventory.json"
    temporary = out.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(out)
    print(json.dumps({"targets": len(result["targets"]), "declared_slots": total,
                      "unique_parameter_function_tuples": len(unique),
                      "registry_matched_tuples": len(matched),
                      "inventory": str(out.relative_to(ROOT))}))


if __name__ == "__main__":
    main()

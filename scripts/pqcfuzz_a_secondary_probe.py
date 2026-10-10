#!/usr/bin/env python3
"""Qualify additional A-tier asymmetric parameter sets against submitted KATs."""
import argparse
import json
import re
from pathlib import Path

import pqcfuzz_a_asym_probe as base


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "workspace/a_targets_sop/probes/asymmetric/secondary"
AMOEBA = {"576": "128", "864": "192", "1152": "256", "1728": "384", "2304": "512"}


def choices(target, item):
    seen = set()
    for header in item["primary_reference_headers"]:
        path = header["path"]
        if "/Others/" in path:
            continue
        match = re.search(r"/Reference_Implementation/(?:x86/)?([^/]+)/", path)
        if not match:
            continue
        instance = match.group(1)
        if instance in ("Lore-SHAKE", "Lore-SM3"):
            inner = re.search(r"/Reference_Implementation/(Lore-(?:SHAKE|SM3))/(Lore-L[1-4])/", path)
            if not inner:
                continue
            if inner.group(1) == "Lore-SM3":
                yield {"target": target, "instance": "Lore-SM3-" + inner.group(2).split("-")[-1],
                       "build_instance": inner.group(2), "mode": "SM3",
                       "kat": "Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_" + inner.group(2) + ".txt",
                       "header": path}
                continue
            instance = inner.group(2)
        if instance in seen:
            continue
        seen.add(instance)
        if instance == base.CHOICES[target][0]:
            continue
        if target == "sign-01" or target == "kem-01":
            number = {"I": 1, "II": 2, "III": 3}[instance.rsplit("-", 1)[1]]
            old = base.CHOICES[target][1]
            kat = old.replace("sig1", f"sig{number}").replace("enc1", f"enc{number}")
        elif target == "kem-02":
            old = base.CHOICES[target][1]
            kat = old.replace("Amoeba128", "Amoeba" + AMOEBA[instance.split("-")[-1]])
        elif target == "kem-04":
            old = base.CHOICES[target][1]
            kat = old.replace("bag_piglet_128", "bag_piglet_" + instance.removeprefix("bag_piglet"))
        else:
            old_instance, old = base.CHOICES[target]
            kat = old.replace(old_instance, instance)
        yield {"target": target, "instance": instance, "kat": kat, "header": path}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append")
    args = parser.parse_args()
    matrix = {x["target"]: x for x in json.loads(
        (ROOT / "workspace/a_targets_sop/api_matrix.json").read_text())}
    targets = sorted(matrix)
    if args.target:
        unknown = set(args.target) - set(targets)
        if unknown:
            parser.error("unknown target(s): " + ",".join(sorted(unknown)))
        targets = [t for t in targets if t in set(args.target)]
    results = []
    OUT.mkdir(parents=True, exist_ok=True)
    for target in targets:
        for item in choices(target, matrix[target]):
            if item.get("status"):
                results.append(item)
                continue
            instance, kat = item["instance"], item["kat"]
            if not (ROOT / "third_party" / target / "source" / kat).is_file():
                item["status"] = "submitted_kat_missing"
                results.append(item)
                continue
            if target in ("sign-01", "kem-01"):
                number = {"I": 1, "II": 2, "III": 3}[instance.rsplit("-", 1)[1]]
                base.FLAG_OVERRIDES[target] = ([f"-DPARAMS={number}", "-DUSE_ICCS"]
                                               if target == "sign-01" else
                                               [f"-DPARAMS={number}", "-DUSE_NICCS_API"])
            if target == "kem-02":
                level = AMOEBA[instance.split("-")[-1]]
                base.FLAG_OVERRIDES[target] = ["-Dinline=static inline",
                                               "-DSECURITY_LEVEL=" + level]
            if target == "kem-19":
                base.FLAG_OVERRIDES[target] = ["-DLORE_LEVEL=" + instance[-1]]
            if target == "sign-31":
                base.FLAG_OVERRIDES[target] = ["-DTSUOV_VARIANT=" + instance.split("_")[-1]]
            if target == "sign-23":
                base.FLAG_OVERRIDES[target] = ["-DSHUTTLE_MODE=" + instance.split("-")[-1]]
            try:
                result = base.probe(target, item.get("build_instance", instance), kat,
                                    matrix[target], header_override=item["header"],
                                    parameter_set=instance)
                result["header"] = item["header"]
                results.append(result)
            except Exception as exc:
                results.append({**item, "status": "probe_error", "error": repr(exc)})
            (OUT / "report.json").write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
            print(json.dumps({"target": target, "instance": instance,
                              "status": results[-1]["status"],
                              "error": results[-1].get("error"),
                              "build_stderr_tail": results[-1].get("build_stderr_tail", "")[-250:]}),
                  flush=True)
    (OUT / "report.json").write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"total": len(results), "statuses":
                      {status: sum(x["status"] == status for x in results)
                       for status in sorted({x["status"] for x in results})}}))


if __name__ == "__main__":
    main()
